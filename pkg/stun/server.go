// Copyright 2026 Riccardo Raccuia
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package stun

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"runtime"
	"sync"
)

// Server represents a STUN server.
// It listens on a given address and handles STUN requests.
// It's backed by a worker pool to process requests more efficiently.
// Callers must use the Listen method to start the server and the Close method to stop it.
type Server struct {
	config     *ServerConfig
	workerPool *serverWorkerPool
	listener   io.Closer
}

// ServerConfig is the configuration for a STUN server.
type ServerConfig struct {
	Logger LoggerFunc
	// TLS configuration for the STUN server
	TLSConfig *tls.Config
	// Number of workers that the STUN server will spawn to process requests
	// When 0, the number of workers will be set to the number of CPU cores
	Workers int
	// Function that will be used to get a buffer from the buffer pool
	// When nil, memory will be allocated on the fly
	GetBufferFunc func() []byte
	// Function that will be used to put a buffer back into the buffer pool
	// When nil, the buffer will be discarded
	PutBufferFunc func([]byte)
	// Function that will be used to listen on UDP, this is particularly useful for custom listeners like QUIC or DTLS,
	// or where specific network configuration is required (e.g. reuseaddr, reuseport, etc.).
	// When nil, the default UDP listener will be used (net.ListenUDP).
	UDPListenFunc func(network string, listenAddr *net.UDPAddr) (*net.UDPConn, error)
	// Function that will be used to listen on TCP, this is particularly useful for custom listeners,
	// or where specific network configuration is required (e.g. reuseaddr, reuseport, etc.).
	// When nil, the default TCP listener will be used (net.ListenTCP).
	TCPListenFunc func(network string, listenAddr *net.TCPAddr) (*net.TCPListener, error)
}

// NewServer creates a new STUN server instance with the given configuration.
func NewServer(config *ServerConfig) (*Server, error) {
	if config == nil {
		return nil, fmt.Errorf("STUN server config is required")
	}

	if config.UDPListenFunc == nil {
		config.UDPListenFunc = net.ListenUDP
	}

	if config.TCPListenFunc == nil {
		config.TCPListenFunc = net.ListenTCP
	}

	s := &Server{
		config: config,
	}
	s.workerPool = newServerWorkerPool(s, config.Workers)
	return s, nil
}

func (s *Server) logger() LoggerFunc {
	if s.config.Logger == nil {
		return func(level string, args ...any) {}
	}
	return s.config.Logger
}

func (s *Server) getBuffer() []byte {
	if s.config.GetBufferFunc != nil {
		return s.config.GetBufferFunc()
	}
	return make([]byte, 1024)
}

func (s *Server) putBuffer(buf []byte) {
	if s.config.PutBufferFunc != nil {
		s.config.PutBufferFunc(buf[:cap(buf)])
	}
}

// Close closes the STUN server and frees up resources.
func (s *Server) Close() error {
	var err error
	s.workerPool.Stop()
	listener := s.listener
	if s.listener != nil {
		err = listener.Close()
		if err != nil {
			err = fmt.Errorf("failed to close STUN listener: %w", err)
		}
		s.listener = nil
	}
	return err
}

// WaitClose waits for the worker pool to finish processing all work items after the server is closed.
func (s *Server) WaitClose() {
	s.workerPool.workerWg.Wait()
}

// Listen starts the STUN server and listens on the given address.
func (s *Server) Listen(ctx context.Context, listenAddr net.Addr) error {
	return s.listen(ctx, listenAddr)
}

// listen starts the STUN server and listens on the given address.
func (s *Server) listen(ctx context.Context, listenAddr net.Addr) error {
	if s.listener != nil {
		return nil
	}
	s.workerPool.Start(ctx)

	var (
		listener io.Closer
		err      error
	)
	switch listenAddr.Network() {
	case "udp":
		listener, err = s.stunListenUDP(listenAddr.(*net.UDPAddr))
		if err != nil {
			s.logger()("fatal", fmt.Sprintf("Failed to listen on STUN listen address: %v", err))
		}
	case "tcp":
		listener, err = s.stunListenTCP(listenAddr.(*net.TCPAddr))
		if err != nil {
			s.logger()("fatal", fmt.Sprintf("Failed to listen on STUN listen address: %v", err))
		}
	default:
		s.logger()("fatal", fmt.Sprintf("Unsupported STUN protocol for listen: %s", listenAddr.Network()))
	}

	s.listener = listener

	s.logger()("info", fmt.Sprintf("STUN server listening on %s %s", listenAddr.Network(), listenAddr.String()))

	return nil
}

func (s *Server) stunListenUDP(listenAddr *net.UDPAddr) (*net.UDPConn, error) {
	//listener, err := network.ListenUDP("udp", listenAddr)
	listener, err := s.config.UDPListenFunc("udp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on STUN listen address: %w", err)
	}

	go func() {
		for {
			readBuffer := s.getBuffer()
			n, addr, err := listener.ReadFromUDP(readBuffer)
			if err != nil {
				s.logger()("error", fmt.Sprintf("STUN: Failed to read from %s: %v", listenAddr, err))
				return
			}

			s.logger()("info", fmt.Sprintf("STUN: Received %d bytes from %s", n, addr))

			// Create write function for UDP
			writeFn := func(data []byte) error {
				_, err := listener.WriteToUDP(data, addr)
				s.putBuffer(data)
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

func (s *Server) stunListenTCP(listenAddr *net.TCPAddr) (net.Listener, error) {
	listener, err := s.getTCPListener(listenAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on STUN listen address: %w", err)
	}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				s.logger()("error", fmt.Sprintf("STUN: Failed to accept from %s: %v", listener.Addr(), err))
				return
			}

			readBuffer := s.getBuffer()
			n, err := io.ReadFull(conn, readBuffer[:20])
			if err != nil {
				s.logger()("error", fmt.Sprintf("STUN: Failed to read from %s: %v", conn.RemoteAddr(), err))
				continue
			}

			msgLen := binary.BigEndian.Uint16(readBuffer[2:4])
			if msgLen > uint16(len(readBuffer)-20) {
				s.logger()("error", fmt.Sprintf("STUN: Message too long from %s: %d bytes", conn.RemoteAddr(), msgLen))
				continue
			}

			n, err = io.ReadFull(conn, readBuffer[20:20+msgLen])
			if err != nil {
				s.logger()("error", fmt.Sprintf("STUN: Failed to read from %s: %v", conn.RemoteAddr(), err))
				continue
			}

			n += 20

			s.logger()("info", fmt.Sprintf("STUN: Received %d bytes from %s", n, conn.RemoteAddr()))

			// Create write function for TCP
			writeFn := func(data []byte) error {
				_, err := conn.Write(data)
				conn.Close()
				s.putBuffer(data)
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

// getTCPListener returns a TCP listener for the given address and TLS configuration.
func (s *Server) getTCPListener(listenAddr net.Addr) (net.Listener, error) {
	listener, err := s.config.TCPListenFunc("tcp", listenAddr.(*net.TCPAddr))
	if err != nil {
		return nil, fmt.Errorf("failed to listen on STUN listen address: %w", err)
	}
	if s.config.TLSConfig == nil {
		return listener, nil
	}
	// create the TLS listener using the existing TCP listener
	return tls.NewListener(listener, s.config.TLSConfig.Clone()), nil
}

// serverWorkerPoolItem represents work to be processed by worker goroutines.
type serverWorkerPoolItem struct {
	DataBuf    []byte             // Raw bytes received
	DataLen    int                // Length of the data
	RemoteAddr net.Addr           // Address of the sender
	WriteFn    func([]byte) error // Function to write response back
}

// serverWorkerPool manages a pool of workers to process STUN requests.
type serverWorkerPool struct {
	parent     *Server
	workChan   chan serverWorkerPoolItem
	workerWg   sync.WaitGroup
	cancel     context.CancelFunc
	numWorkers int
}

// newServerWorkerPool creates a new worker pool with the specified number of workers.
func newServerWorkerPool(parent *Server, numWorkers int) *serverWorkerPool {
	if numWorkers <= 0 {
		numWorkers = runtime.NumCPU()
	}

	return &serverWorkerPool{
		parent:     parent,
		workChan:   make(chan serverWorkerPoolItem, numWorkers*2), // Buffer for better throughput
		numWorkers: numWorkers,
	}
}

// Start begins processing work items with the configured number of workers.
func (wp *serverWorkerPool) Start(ctx context.Context) {
	wp.parent.logger()("info", fmt.Sprintf("STUN: Starting worker pool with %d workers", wp.numWorkers))

	_, cancel := context.WithCancel(ctx)
	wp.cancel = cancel

	for i := 0; i < wp.numWorkers; i++ {
		wp.workerWg.Add(1)
		go wp.worker(ctx, i)
	}
}

// Stop gracefully shuts down the worker pool.
func (wp *serverWorkerPool) Stop() {
	wp.parent.logger()("info", "STUN: Stopping worker pool...")
	wp.cancel()
	//close(wp.workChan)
	wp.workerWg.Wait()
	wp.parent.logger()("info", "STUN: Worker pool stopped")
}

// Submit adds a work item to the queue.
func (wp *serverWorkerPool) Submit(item serverWorkerPoolItem) {
	select {
	case wp.workChan <- item:
		// Work submitted successfully
	default:
		// Channel is full, log and drop
		wp.parent.logger()("error", "STUN: Worker queue full, dropping work item")
	}
}

// worker processes work items from the channel.
func (wp *serverWorkerPool) worker(ctx context.Context, id int) {
	defer wp.workerWg.Done()

	for {
		select {
		case <-ctx.Done():
			wp.parent.logger()("debug", fmt.Sprintf("STUN: Worker %d shutting down", id))
			return
		case item, ok := <-wp.workChan:
			if !ok {
				wp.parent.logger()("debug", fmt.Sprintf("STUN: Worker %d: work channel closed", id))
				return
			}
			wp.processWorkItem(id, item)
		}
	}
}

// processWorkItem handles a single STUN request.
func (wp *serverWorkerPool) processWorkItem(workerID int, item serverWorkerPoolItem) {
	wp.parent.logger()("debug", fmt.Sprintf("STUN: Worker %d processing %d bytes from %s", workerID, len(item.DataBuf), item.RemoteAddr))

	// Process the STUN request
	message, err := DecodeMessage(item.DataBuf[:item.DataLen])
	if err != nil {
		wp.parent.logger()("error", fmt.Sprintf("STUN: Worker %d failed to parse request from %s: %v", workerID, item.RemoteAddr, err))
		return
	}

	response, err := ProcessBindingRequest(message, item.RemoteAddr, nil, &BindingOptions{
		RequireFingerprint: true,
	})
	if err != nil {
		wp.parent.logger()("error", fmt.Sprintf("STUN: Worker %d failed to process request from %s: %v", workerID, item.RemoteAddr, err))
		return
	}

	// Write the response back
	raw := NewBuffer(wp.parent.getBuffer())
	raw.Reset()
	if err := response.SerializeTo(raw); err != nil {
		wp.parent.logger()("error", fmt.Sprintf("STUN: Worker %d failed to serialize response: %v", workerID, err))
		return
	}
	if err := item.WriteFn(raw.Bytes()); err != nil {
		wp.parent.logger()("error", fmt.Sprintf("STUN: Worker %d failed to write response to %s: %v", workerID, item.RemoteAddr, err))
		return
	}

	wp.parent.logger()("info", fmt.Sprintf("STUN: Worker %d successfully processed request from %s", workerID, item.RemoteAddr))
}
