# Makefile for building pig and signtool
# Variables
GO ?= go
GOFLAGS ?=
BINDIR ?= bin
BUILDFLAGS ?=
LDFLAGS ?=-ldflags="-s -w"
GOOS ?= $(shell $(GO) env GOOS)
GOARCH ?= $(shell $(GO) env GOARCH)
CGO_ENABLED ?= 0

# Binary names
PIG_BINNAME ?= pig
SIGNTOOL_BINNAME ?= signtool
CLIENT_BINNAME ?= client

# Directories
PIG_DIR = cmd/pig
SIGNTOOL_DIR = tools/signtool
CLIENT_DIR = cmd/client

# Targets
.PHONY: all pig signtool clean test help

all: pig signtool

# Create bin directory if it doesn't exist
$(BINDIR):
	mkdir -p $(BINDIR)

# Build pig
pig: $(BINDIR)
	CGO_ENABLED=$(CGO_ENABLED) GOOS=$(GOOS) GOARCH=$(GOARCH) $(GO) build $(GOFLAGS) $(BUILDFLAGS) $(LDFLAGS) -o $(BINDIR)/$(PIG_BINNAME) ./$(PIG_DIR)

# Build signtool
signtool: $(BINDIR)
	CGO_ENABLED=$(CGO_ENABLED) GOOS=$(GOOS) GOARCH=$(GOARCH) $(GO) build $(GOFLAGS) $(BUILDFLAGS) $(LDFLAGS) -o $(BINDIR)/$(SIGNTOOL_BINNAME) ./$(SIGNTOOL_DIR)

# Build client
client: $(BINDIR)
	CGO_ENABLED=$(CGO_ENABLED) GOOS=$(GOOS) GOARCH=$(GOARCH) $(GO) build $(GOFLAGS) $(BUILDFLAGS) $(LDFLAGS) -o $(BINDIR)/$(CLIENT_BINNAME) ./$(CLIENT_DIR)

# Cross compilation
.PHONY: pig-linux pig-linux-arm6 pig-darwin pig-windows
pig-linux:
	GOOS=linux GOARCH=amd64 $(MAKE) pig

pig-linux-arm:
	GOOS=linux GOARCH=arm $(MAKE) pig

pig-linux-arm64:
	GOOS=linux GOARCH=arm64 $(MAKE) pig

pig-linux-arm6:
	GOOS=linux GOARCH=arm GOARM=6 $(MAKE) pig

pig-darwin:
	GOOS=darwin GOARCH=amd64 $(MAKE) pig

pig-windows:
	GOOS=windows GOARCH=amd64 PIG_BINNAME=pig.exe $(MAKE) pig

pig-win: pig-windows

.PHONY: signtool-linux signtool-darwin signtool-windows
signtool-linux:
	GOOS=linux GOARCH=amd64 $(MAKE) signtool

signtool-darwin:
	GOOS=darwin GOARCH=amd64 $(MAKE) signtool

signtool-windows:
	GOOS=windows GOARCH=amd64 SIGNTOOL_BINNAME=signtool.exe $(MAKE) signtool

signtool-win: signtool-windows

client-windows:
	GOOS=windows GOARCH=amd64 CLIENT_BINNAME=client.exe $(MAKE) client

client-win: client-windows

windows: pig-win signtool-win client-win
win: windows

# Clean
clean:
	rm -rf $(BINDIR)

# Testing
test:
	$(GO) test -v ./...

# Help
help:
	@echo "Available targets:"
	@echo "  all        : Build both pig and signtool"
	@echo "  pig        : Build just pig"
	@echo "  signtool   : Build just signtool"
	@echo "  pig-linux  : Build pig for Linux"
	@echo "  pig-linux-arm6 : Build pig for Linux ARM6"
	@echo "  pig-linux-arm : Build pig for Linux ARM"
	@echo "  pig-darwin : Build pig for macOS"
	@echo "  pig-windows: Build pig for Windows"
	@echo "  signtool-linux  : Build signtool for Linux"
	@echo "  signtool-darwin : Build signtool for macOS"
	@echo "  signtool-windows: Build signtool for Windows"
	@echo "  clean      : Remove all built binaries"
	@echo "  test       : Run tests"
	@echo "  help       : Show this help message"
	@echo ""
	@echo "Variables:"
	@echo "  GO         : Go command to use (default: go)"
	@echo "  GOFLAGS    : Additional flags to pass to go build"
	@echo "  BINDIR     : Directory to place built binaries (default: bin)"
	@echo "  BUILDFLAGS : Additional build flags"
	@echo "  LDFLAGS    : Additional ldflags"
	@echo "  GOOS       : Target operating system"
	@echo "  GOARCH     : Target architecture"
	@echo "  CGO_ENABLED: Enable CGO (default: 0)"
