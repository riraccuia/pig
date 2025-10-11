package stun

import (
	"context"
	"fmt"
	"io"
	"net"
	"runtime"
	"sync"

	"github.com/riraccuia/pig/pkg/common"
	"github.com/riraccuia/pig/pkg/ice/conn"
)

type Server struct {
	logger     common.Logger
	workerPool *serverWorkerPool
	listener   io.Closer
	bufPool    *sync.Pool
}

// stunListenMode listens for STUN requests on the specified protocol, address and port.
func NewServer(logger common.Logger, listenAddr net.Addr) (*Server, error) {
	var (
		workerPool *serverWorkerPool
		listener   io.Closer
		err        error
	)

	if listenAddr == nil {
		logger.Fatalf("STUN listen address is required")
	}

	// Create and start worker pool (defaults to number of CPU cores)
	workerPool = newServerWorkerPool(0, logger)
	workerPool.Start()

	s := &Server{
		logger:     logger,
		workerPool: workerPool,
	}

	switch listenAddr.Network() {
	case "udp":
		listener, err = s.stunListenUDP(listenAddr.(*net.UDPAddr))
		if err != nil {
			logger.Fatalf("Failed to listen on STUN listen address: %v", err)
		}
	case "tcp":
		listener, err = s.stunListenTCP(listenAddr.(*net.TCPAddr))
		if err != nil {
			logger.Fatalf("Failed to listen on STUN listen address: %v", err)
		}
	default:
		logger.Fatalf("Unsupported STUN protocol for listen: %s", listenAddr.Network())
	}

	s.listener = listener

	logger.Infof("STUN server listening on %s %s", listenAddr.Network(), listenAddr.String())

	return s, nil
}

func (s *Server) WithBufPool(bufPool *sync.Pool) *Server {
	s.bufPool = bufPool
	return s
}

func (s *Server) GetBuffer() []byte {
	if s.bufPool != nil {
		return *s.bufPool.Get().(*[]byte)
	}
	return make([]byte, 1024)
}

func (s *Server) PutBuffer(buf []byte) {
	if s.bufPool != nil {
		s.bufPool.Put(&buf)
	}
}

func (s *Server) Close() error {
	s.workerPool.Stop()
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

func (s *Server) stunListenUDP(listenAddr *net.UDPAddr) (*net.UDPConn, error) {
	listener, err := conn.ListenUDP("udp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on STUN listen address: %w", err)
	}

	go func() {
		for {
			readBuffer := s.GetBuffer()
			n, addr, err := listener.ReadFromUDP(readBuffer)
			if err != nil {
				s.logger.Errorf("STUN: Failed to read from %s: %v", listenAddr, err)
				return
			}

			s.logger.Infof("STUN: Received %d bytes from %s", n, addr)

			// Create write function for UDP
			writeFn := func(data []byte) error {
				_, err := listener.WriteToUDP(data, addr)
				s.PutBuffer(data)
				return err
			}

			// Submit work to worker pool
			workItem := serverWorkerPoolItem{
				DataBuf:    readBuffer,
				DataLen:    n,
				RemoteAddr: addr,
				WriteFn:    writeFn,
			}

			s.workerPool.Submit(workItem)
		}
	}()

	return listener, nil
}

func (s *Server) stunListenTCP(listenAddr *net.TCPAddr) (*net.TCPListener, error) {
	listener, err := net.ListenTCP("tcp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on STUN listen address: %w", err)
	}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				s.logger.Errorf("STUN: Failed to accept from %s: %v", listener.Addr(), err)
				return
			}

			readBuffer := s.GetBuffer()
			n, err := conn.Read(readBuffer)
			if err != nil {
				s.logger.Errorf("STUN: Failed to read from %s: %v", conn.RemoteAddr(), err)
				return
			}

			s.logger.Infof("STUN: Received %d bytes from %s", n, conn.RemoteAddr())

			// Create write function for TCP
			writeFn := func(data []byte) error {
				_, err := conn.Write(data)
				conn.Close()
				s.PutBuffer(data)
				return err
			}

			// Submit work to worker pool
			workItem := serverWorkerPoolItem{
				DataBuf:    readBuffer,
				DataLen:    n,
				RemoteAddr: conn.RemoteAddr(),
				WriteFn:    writeFn,
			}

			s.workerPool.Submit(workItem)
		}
	}()

	return listener, nil
}

// serverWorkerPoolItem represents work to be processed by worker goroutines
type serverWorkerPoolItem struct {
	DataBuf    []byte             // Raw bytes received
	DataLen    int                // Length of the data
	RemoteAddr net.Addr           // Address of the sender
	WriteFn    func([]byte) error // Function to write response back
}

// serverWorkerPool manages a pool of workers to process STUN requests
type serverWorkerPool struct {
	workChan   chan serverWorkerPoolItem
	workerWg   sync.WaitGroup
	ctx        context.Context
	cancel     context.CancelFunc
	logger     common.Logger
	numWorkers int
}

// newServerWorkerPool creates a new worker pool with the specified number of workers
func newServerWorkerPool(numWorkers int, logger common.Logger) *serverWorkerPool {
	if numWorkers <= 0 {
		numWorkers = runtime.NumCPU()
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &serverWorkerPool{
		workChan:   make(chan serverWorkerPoolItem, numWorkers*2), // Buffer for better throughput
		ctx:        ctx,
		cancel:     cancel,
		logger:     logger,
		numWorkers: numWorkers,
	}
}

// Start begins processing work items with the configured number of workers
func (wp *serverWorkerPool) Start() {
	wp.logger.Infof("STUN: Starting worker pool with %d workers", wp.numWorkers)

	for i := 0; i < wp.numWorkers; i++ {
		wp.workerWg.Add(1)
		go wp.worker(i)
	}
}

// Stop gracefully shuts down the worker pool
func (wp *serverWorkerPool) Stop() {
	wp.logger.Info("STUN: Stopping worker pool...")
	wp.cancel()
	close(wp.workChan)
	wp.workerWg.Wait()
	wp.logger.Info("STUN: Worker pool stopped")
}

// Submit adds a work item to the queue
func (wp *serverWorkerPool) Submit(item serverWorkerPoolItem) {
	select {
	case wp.workChan <- item:
		// Work submitted successfully
	case <-wp.ctx.Done():
		// Worker pool is shutting down
		wp.logger.Error("STUN: Dropping work item, worker pool shutting down")
	default:
		// Channel is full, log and drop
		wp.logger.Error("STUN: Worker queue full, dropping work item")
	}
}

// worker processes work items from the channel
func (wp *serverWorkerPool) worker(id int) {
	defer wp.workerWg.Done()

	for {
		select {
		case <-wp.ctx.Done():
			wp.logger.Debugf("STUN: Worker %d shutting down", id)
			return
		case item, ok := <-wp.workChan:
			if !ok {
				wp.logger.Debugf("STUN: Worker %d: work channel closed", id)
				return
			}
			wp.processWorkItem(id, item)
		}
	}
}

// processWorkItem handles a single STUN request
func (wp *serverWorkerPool) processWorkItem(workerID int, item serverWorkerPoolItem) {
	wp.logger.Debugf("STUN: Worker %d processing %d bytes from %s", workerID, len(item.DataBuf), item.RemoteAddr)

	// Process the STUN request
	response, err := processStunRequestBytes(item.DataBuf[:item.DataLen], item.RemoteAddr)
	if err != nil {
		wp.logger.Errorf("STUN: Worker %d failed to process request from %s: %v", workerID, item.RemoteAddr, err)
		return
	}

	// Write the response back
	if err := item.WriteFn(response.Raw); err != nil {
		wp.logger.Errorf("STUN: Worker %d failed to write response to %s: %v", workerID, item.RemoteAddr, err)
		return
	}

	wp.logger.Infof("STUN: Worker %d successfully processed request from %s", workerID, item.RemoteAddr)
}
