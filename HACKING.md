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

---

**Remember**: This is an event-driven system. If you find blocking code, you've found a bug!
