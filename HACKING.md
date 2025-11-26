# Agent Guide: Event-Driven Web Downloader Implementation

**This is a comprehensive guide for agents working on the asynchronous web downloader project.** The implementation is designed from the ground up around non-blocking I/O and event callbacks using libev and c-ares.

## Quick Start for Agents

### 🎯 **First Steps**
1. **Check current status**: Read [TODO.md](TODO.md) for implementation progress and next tasks
2. **Understand architecture**: Review the [Overview](docs/overview.md) for system design

## Table of Contents

### Core Documentation
- [Overview](docs/overview.md) - System architecture and component roles
- [Design Principles](docs/design-principles.md) - Implementation guidelines and best practices

### Component Documentation
- [Event Loop Abstraction](docs/event-loop.md) - Core event loop design
- [DNS Resolver](docs/dns-resolver.md) - Asynchronous DNS resolution
- [Connection Management](docs/connection-management.md) - Network connection handling
- [HTTP Transaction](docs/http-transaction.md) - HTTP request/response state machine
- [Download Scheduler](docs/scheduler.md) - Job scheduling and concurrency control
- [Connection Pool](docs/connection-pool.md) - Persistent connection reuse
- [CLI Integration](docs/cli-integration.md) - Top-level workflow and CLI

### Tools & Status
- [ripgrep Guide](docs/ripgrep.md) - Search tool usage for agents
- [Project Status](TODO.md) - Running record of implementation progress
- [Reusability Tests Guide](docs/reusability_tests.md) - Test architecture and patterns

## Hard Requirements

⚠️ **Non-negotiable constraints**:
- **c-ares is mandatory** - All DNS must be asynchronous
- **libev is mandatory** - Event loop management
- **No blocking paths anywhere** - DNS, sockets, timers, redirects
- **Support thousands of concurrent connections** - Scalability is key

## Implementation Strategy

### 🏗️ **Architecture Pattern**
- **State machines** drive all network operations
- **Callbacks** handle completion/progress
- **Event loop** orchestrates all I/O
- **No blocking calls** - use timers and async patterns

### 🔄 **Development Workflow**
1. **Check TODO.md** for current priorities
2. **Review component docs** for design patterns
3. **Use ripgrep** to understand existing code
4. **Follow design principles** for consistency
5. **Test non-blocking behavior** - no blocking paths!

## Key Design Principles

- **No blocking calls** - Use c-ares for DNS, libev for I/O
- **Callbacks + immediate returns** - Never wait for completion
- **Timer-based timeouts** - No sleep() calls
- **Incremental parsing** - Handle data as it arrives
- **Bounded work per event** - Prevent starvation
- **Single-threaded core** - Use ev_async for cross-thread

## Getting Help

- **Architecture questions**: Review component documentation
- **Implementation details**: Use ripgrep to find existing patterns
- **Status updates**: Check TODO.md for current progress
- **Code patterns**: Follow design principles for consistency

## Build and Test Process

### Building with Meson

The project uses the Meson build system. To build and test:

```bash
# Configure build directory (if not already done)
meson setup build

# Build the project
meson compile -C build

# Run all tests
meson test -C build

# Run specific test suite
meson test -C build wget:http
meson test -C build wget:cli

# Run with verbose output
meson test -C build --verbose
```

### Test Results and Known Issues

**Current Test Status (2025-11-26):**
- **25/26 tests pass** ✅
- **1 test fails** ❌: `wget:cli / cli/continue`

#### Continue Test Failure Analysis

The continue test (`cli/continue`) fails with a segmentation fault (SIGSEGV):

```
23/26 wget:cli / cli/continue           FAIL            0.25s   (exit status 139 or signal 11 SIGSEGV)
```

**Test Command:**
```bash
./build/src/wget --no-config --continue --output-document=continue_test.txt http://127.0.0.1:18080/hello.txt
```

**Error:** Segmentation fault during continue functionality execution.

#### Continue Implementation Status

Despite the test failure, the continue option (`-c`/`--continue`) is implemented in the codebase:

- **CLI Option**: Properly parsed and mapped to `opt.always_rest` boolean
- **File Mode**: Files opened in append mode (`"ab"`) when continue is enabled
- **HTTP Range Headers**: Correctly generates `Range: bytes=start-` headers
- **Restart Position**: Calculates restart position using `stat()` on existing files
- **Server Response**: Handles 206 Partial Content responses appropriately

**Root Cause Investigation Needed:**
The segmentation fault suggests a runtime issue in the continue functionality, possibly related to:
- Memory management during file append operations
- HTTP range request processing
- File descriptor handling
- State machine transitions in the continue flow

### Debugging the Continue Test

To investigate the continue test failure:

```bash
# Run with debug output
MALLOC_PERTURB_=1 meson test -C build wget:cli / cli/continue --verbose

# Run with address sanitizer (if available)
ASAN_OPTIONS=detect_leaks=1 meson test -C build wget:cli / cli/continue

# Manual test reproduction
cd build && ./src/wget --no-config --continue --output-document=continue_test.txt http://127.0.0.1:18080/hello.txt
```

---

**Remember**: This is an event-driven system. If you find blocking code, you've found a bug!
