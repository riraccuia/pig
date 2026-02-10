package main

import (
	"context"
	"flag"
)

func main() {
	serviceMode := flag.Bool("service", false, "run as Windows service")
	flag.Parse()

	if *serviceMode {
		runService()
		return
	}

	runClient(context.Background(), false)
}
