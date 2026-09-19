# Makefile for building pig and signtool
# Variables
GO ?= go
BINDIR ?= bin
BUILDFLAGS ?=
LDFLAGS ?= -s -w
GOOS ?= $(shell $(GO) env GOOS)
GOARCH ?= $(shell $(GO) env GOARCH)
CGO_ENABLED ?= 0

# Binary names
PIG_BINNAME ?= pig
SIGNTOOL_BINNAME ?= signtool

# Directories
PIG_DIR = cmd/pig
SIGNTOOL_DIR = tools/signtool
DOCS_DIR = docs
CLIHELP_DIR = $(DOCS_DIR)/cli-help

# Targets
.PHONY: all pig signtool clean test help help-docs \
	pig-linux pig-linux-arm pig-linux-arm6 pig-linux-arm7 pig-linux-arm64 \
	pig-darwin-amd64 pig-darwin-arm64 pig-windows pig-win \
	signtool-linux signtool-linux-arm64 signtool-darwin-amd64 signtool-darwin-arm64 signtool-windows signtool-win \
	windows

all: pig signtool

help-docs:
	@set -e; export COLUMNS=110; \
	$(GO) run ./$(PIG_DIR) -docs config -md > $(DOCS_DIR)/config.md; \
	{ echo '<pre><code>'; $(GO) run ./$(PIG_DIR) -h; echo '</code></pre>'; } | \
		sed -e 's/ -c / \<a href="connect.md"\>-c\<\/a\>/g' \
		    -e 's/ -l / \<a href="listen.md"\>-l\<\/a\>/g' \
		    -e 's/ -stun / \<a href="stun.md"\>-stun\<\/a\>/g' \
		    -e 's/ -config / \<a href="config.md"\>-config\<\/a\>/g' \
		    -e 's/ -docs / \<a href="docs.md"\>-docs\<\/a\>/g' \
		> $(CLIHELP_DIR)/main.md; \
	{ echo '```'; $(GO) run ./$(PIG_DIR) -c -h; echo '```'; } > $(CLIHELP_DIR)/connect.md; \
	{ echo '```'; $(GO) run ./$(PIG_DIR) -l -h; echo '```'; } > $(CLIHELP_DIR)/listen.md; \
	{ echo '<pre><code>'; $(GO) run ./$(PIG_DIR) -config invalid -h; echo '</code></pre>'; } | \
		sed -e 's/ -config / \<a href="config-ref.md"\>-config\<\/a\>/g' \
		> $(CLIHELP_DIR)/config.md; \
	{ echo '```'; $(GO) run ./$(PIG_DIR) -docs config; echo '```'; } > $(CLIHELP_DIR)/config-ref.md; \
	{ echo '```'; $(GO) run ./$(PIG_DIR) -stun -h; echo '```'; } > $(CLIHELP_DIR)/stun.md; \
	{ echo '<pre><code>'; $(GO) run ./$(PIG_DIR) -docs -h 2>/dev/null; echo '</code></pre>'; } | \
		sed -e 's/ config / \<a href="..\/config.md"\>config\<\/a\>/g' \
		    -e 's/ env / \<a href="env.md"\>env\<\/a\>/g' \
		    -e 's/ protos / \<a href="protos.md"\>protos\<\/a\>/g' \
		> $(CLIHELP_DIR)/docs.md; \
	{ echo '```'; $(GO) run ./$(PIG_DIR) -docs env; echo '```'; } > $(CLIHELP_DIR)/env.md; \
	{ echo '```'; $(GO) run ./$(PIG_DIR) -docs protos; echo '```'; } > $(CLIHELP_DIR)/protos.md

# Create bin directory if it doesn't exist
$(BINDIR):
	mkdir -p $(BINDIR)

# Build pig
pig: | $(BINDIR)
	CGO_ENABLED=$(CGO_ENABLED) GOOS=$(GOOS) GOARCH=$(GOARCH) $(GO) build $(BUILDFLAGS) -ldflags='$(LDFLAGS)' -o $(BINDIR)/$(PIG_BINNAME) ./$(PIG_DIR)

# Build signtool
signtool: | $(BINDIR)
	CGO_ENABLED=$(CGO_ENABLED) GOOS=$(GOOS) GOARCH=$(GOARCH) $(GO) build $(BUILDFLAGS) -ldflags='$(LDFLAGS)' -o $(BINDIR)/$(SIGNTOOL_BINNAME) ./$(SIGNTOOL_DIR)

# Cross compilation
pig-linux:
	GOOS=linux GOARCH=amd64 PIG_BINNAME=$(PIG_BINNAME)-linux-amd64 $(MAKE) pig

pig-linux-arm:
	GOOS=linux GOARCH=arm PIG_BINNAME=$(PIG_BINNAME)-linux-arm $(MAKE) pig

pig-linux-arm64:
	GOOS=linux GOARCH=arm64 PIG_BINNAME=$(PIG_BINNAME)-linux-arm64 $(MAKE) pig

pig-linux-arm6:
	GOOS=linux GOARCH=arm GOARM=6 PIG_BINNAME=$(PIG_BINNAME)-linux-arm6 $(MAKE) pig

pig-linux-arm7:
	GOOS=linux GOARCH=arm GOARM=7 PIG_BINNAME=$(PIG_BINNAME)-linux-arm7 $(MAKE) pig

pig-darwin-amd64:
	GOOS=darwin GOARCH=amd64 PIG_BINNAME=$(PIG_BINNAME)-darwin-amd64 $(MAKE) pig

pig-darwin-arm64:
	GOOS=darwin GOARCH=arm64 PIG_BINNAME=$(PIG_BINNAME)-darwin-arm64 $(MAKE) pig

pig-windows:
	GOOS=windows GOARCH=amd64 PIG_BINNAME=$(PIG_BINNAME)-windows-amd64.exe $(MAKE) pig

pig-win: pig-windows

signtool-linux:
	GOOS=linux GOARCH=amd64 SIGNTOOL_BINNAME=$(SIGNTOOL_BINNAME)-linux-amd64 $(MAKE) signtool

signtool-linux-arm64:
	GOOS=linux GOARCH=arm64 SIGNTOOL_BINNAME=$(SIGNTOOL_BINNAME)-linux-arm64 $(MAKE) signtool

signtool-darwin-amd64:
	GOOS=darwin GOARCH=amd64 SIGNTOOL_BINNAME=$(SIGNTOOL_BINNAME)-darwin-amd64 $(MAKE) signtool

signtool-darwin-arm64:
	GOOS=darwin GOARCH=arm64 SIGNTOOL_BINNAME=$(SIGNTOOL_BINNAME)-darwin-arm64 $(MAKE) signtool

signtool-windows:
	GOOS=windows GOARCH=amd64 SIGNTOOL_BINNAME=$(SIGNTOOL_BINNAME)-windows-amd64.exe $(MAKE) signtool

signtool-win: signtool-windows

windows: pig-win signtool-win

# Clean
clean:
	rm -rf $(BINDIR)

# Testing
test:
	$(GO) test -v ./...

# Help
help:
	@echo "Available targets:"
	@echo "  all                  Build pig and signtool for the host"
	@echo "  pig                  Build pig for GOOS/GOARCH (default: host)"
	@echo "  signtool             Build signtool for GOOS/GOARCH (default: host)"
	@echo "  pig-linux            pig, linux/amd64"
	@echo "  pig-linux-arm        pig, linux/arm"
	@echo "  pig-linux-arm6       pig, linux/arm GOARM=6"
	@echo "  pig-linux-arm7       pig, linux/arm GOARM=7"
	@echo "  pig-linux-arm64      pig, linux/arm64"
	@echo "  pig-darwin-amd64     pig, darwin/amd64"
	@echo "  pig-darwin-arm64     pig, darwin/arm64"
	@echo "  pig-windows          pig, windows/amd64 (.exe)"
	@echo "  pig-win              Alias for pig-windows"
	@echo "  signtool-linux       signtool, linux/amd64"
	@echo "  signtool-linux-arm64 signtool, linux/arm64"
	@echo "  signtool-darwin-amd64  signtool, darwin/amd64"
	@echo "  signtool-darwin-arm64  signtool, darwin/arm64"
	@echo "  signtool-windows     signtool, windows/amd64 (.exe)"
	@echo "  signtool-win         Alias for signtool-windows"
	@echo "  windows              pig-windows and signtool-windows"
	@echo "  help-docs            Regenerate docs/ and docs/cli-help/"
	@echo "  test                 Run go test ./..."
	@echo "  clean                Remove $(BINDIR)"
	@echo "  help                 Show this help"
	@echo ""
	@echo "Variables:"
	@echo "  GO           Go command (default: go)"
	@echo "  BINDIR       Output directory (default: bin)"
	@echo "  BUILDFLAGS   Extra go build flags"
	@echo "  LDFLAGS      Linker flags (default: -s -w)"
	@echo "  GOOS         Target OS"
	@echo "  GOARCH       Target architecture"
	@echo "  CGO_ENABLED  Enable CGO (default: 0)"
	@echo "  PIG_BINNAME  pig output name (default: pig)"
	@echo "  SIGNTOOL_BINNAME  signtool output name (default: signtool)"
