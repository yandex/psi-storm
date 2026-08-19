# PSI-Storm Makefile
# Private Set Intersection using OpenSSL

CXX = g++
CXXFLAGS = -O3 -Wall -Wextra -std=c++17
LDFLAGS = -lssl -lcrypto -pthread

# macOS: use Homebrew OpenSSL
ifeq ($(shell uname),Darwin)
    OPENSSL_PREFIX := $(shell brew --prefix openssl@3 2>/dev/null)
    ifneq ($(OPENSSL_PREFIX),)
        CXXFLAGS += -I$(OPENSSL_PREFIX)/include
        LDFLAGS := -L$(OPENSSL_PREFIX)/lib $(LDFLAGS)
    endif
endif

# Directories
TEST_DIR = tests

# Targets
PSI_BIN = psi
TEST_BIN = $(TEST_DIR)/test_psi

# Source files
PSI_SRC = psi.cpp hash_to_curve_p256.cc
TEST_SRC = $(TEST_DIR)/test_psi.cpp

# Default target
.PHONY: all
all: $(PSI_BIN)

# Check OpenSSL version (requires 3.0+)
.PHONY: check-openssl
check-openssl:
	@OPENSSL_BIN="openssl"; \
	if [ "$$(uname)" = "Darwin" ]; then \
		BREW_SSL=$$(brew --prefix openssl@3 2>/dev/null); \
		if [ -n "$$BREW_SSL" ] && [ -x "$$BREW_SSL/bin/openssl" ]; then \
			OPENSSL_BIN="$$BREW_SSL/bin/openssl"; \
		fi; \
	fi; \
	OPENSSL_VER=$$($$OPENSSL_BIN version 2>/dev/null | awk '{print $$2}'); \
	if [ -z "$$OPENSSL_VER" ]; then \
		echo "Error: OpenSSL not found. Please install OpenSSL 3.0 or higher."; \
		exit 1; \
	fi; \
	MAJOR=$$(echo $$OPENSSL_VER | cut -d. -f1); \
	if [ "$$MAJOR" -lt 3 ] 2>/dev/null; then \
		echo "Error: OpenSSL 3.0+ required. Found: $$OPENSSL_VER"; \
		exit 1; \
	fi; \
	echo "OpenSSL $$OPENSSL_VER detected"

# Build main PSI binary
$(PSI_BIN): check-openssl $(PSI_SRC)
	$(CXX) $(CXXFLAGS) -o $@ $(PSI_SRC) $(LDFLAGS)

# Build test binary (includes hash_to_curve_p256 for verification)
$(TEST_BIN): check-openssl $(TEST_SRC) hash_to_curve_p256.cc $(PSI_BIN)
	$(CXX) $(CXXFLAGS) -o $@ $(TEST_SRC) hash_to_curve_p256.cc $(LDFLAGS)

# Build all (main + tests)
.PHONY: build
build: $(PSI_BIN) $(TEST_BIN)

# Run tests
.PHONY: test
test: $(TEST_BIN)
	cd $(TEST_DIR) && ./test_psi

# Run tests and keep files
.PHONY: test-keep
test-keep: $(TEST_BIN)
	cd $(TEST_DIR) && ./test_psi --keep-files

# Run benchmark (default 1M values)
.PHONY: benchmark
benchmark: $(PSI_BIN)
	cd $(TEST_DIR) && bash benchmark.sh

# Run benchmark with custom size
.PHONY: benchmark-%
benchmark-%: $(PSI_BIN)
	cd $(TEST_DIR) && bash benchmark.sh $*

# Clean build artifacts
.PHONY: clean
clean:
	rm -f $(PSI_BIN) $(TEST_BIN)
	rm -f $(TEST_DIR)/_test_*.txt $(TEST_DIR)/_test_*.ini
	rm -f $(TEST_DIR)/_bench_*.txt $(TEST_DIR)/_bench_*.ini

# Deep clean (includes all generated files)
.PHONY: distclean
distclean: clean
	rm -f *.txt.bak
	rm -f send-this-to-partner-*.txt
	rm -f intersection-result.txt

# Install to /usr/local/bin (requires sudo)
.PHONY: install
install: $(PSI_BIN)
	install -m 755 $(PSI_BIN) /usr/local/bin/

# Uninstall
.PHONY: uninstall
uninstall:
	rm -f /usr/local/bin/$(PSI_BIN)

# Debug build
.PHONY: debug
debug: CXXFLAGS = -g -Wall -Wextra -std=c++17 -DDEBUG
debug: clean $(PSI_BIN)

# Docker
DOCKER_IMAGE = psi-storm

.PHONY: docker-build
docker-build:
	docker build -t $(DOCKER_IMAGE) .

.PHONY: docker-test
docker-test: docker-build
	docker run --rm --workdir /app/tests --entrypoint /app/tests/test_psi $(DOCKER_IMAGE)

.PHONY: docker-run
docker-run: docker-build
	@echo "Usage: docker run -v \$$(pwd):/data $(DOCKER_IMAGE) <command> --config /data/secret-config.ini"
	@echo "Commands: step1, step2, compare"

# Show version info
.PHONY: info
info:
	@echo "PSI-Storm Build Info"
	@echo "  OpenSSL version: $$(openssl version | awk '{print $$2}')"
	@echo "  Compiler: $(CXX)"
	@echo "  Flags: $(CXXFLAGS)"

# Help
.PHONY: help
help:
	@echo "PSI-Storm Build System"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  all          - Build PSI binary (default)"
	@echo "  build        - Build PSI and test binaries"
	@echo "  test         - Build and run tests"
	@echo "  test-keep    - Run tests, keep generated files"
	@echo "  benchmark    - Run benchmark with 1M values"
	@echo "  benchmark-N  - Run benchmark with N values (e.g., make benchmark-5000000)"
	@echo "  clean        - Remove build artifacts"
	@echo "  distclean    - Remove all generated files"
	@echo "  debug        - Build with debug symbols"
	@echo "  install      - Install to /usr/local/bin"
	@echo "  uninstall    - Remove from /usr/local/bin"
	@echo "  info         - Show build environment info"
	@echo ""
	@echo "Docker:"
	@echo "  docker-build - Build Docker image"
	@echo "  docker-test  - Run tests in Docker"
	@echo "  docker-run   - Show Docker run usage"
	@echo ""
	@echo "  help         - Show this help"
