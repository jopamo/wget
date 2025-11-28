# Overview

**Status Note**: This document describes the **implemented architecture** for a fully asynchronous web downloader. The async architecture is now live and operational, with all core components implemented and tested. Refer to TODO.md for detailed implementation status.

This plan outlines a fully asynchronous web downloader (akin to Wget) built around an event-driven core and explicit state machines. Unlike a traditional Wget design (which might simply add an event library to a mostly blocking codebase), this approach designs the system from the ground up around non-blocking I/O and event callbacks.

The goal is to maximize concurrency (many simultaneous connections and DNS queries) without any blocking calls, using libraries like **libev** (for event loop) and **c-ares** (for async DNS). All major components – event loop, DNS resolver, network connections, HTTP transactions, scheduler, and connection pooling – are designed as independent, state-driven modules that interact through well-defined callback interfaces.

## Key components and their roles

* **Core Event Loop (`evloop`)**
  A thin abstraction over libev, providing a central event dispatcher. It allows other modules to register interest in file descriptor readiness, timers, and cross-thread events in a uniform way.

* **DNS Resolver (`dns_cares`)**
  Integration of the c-ares library with the event loop to perform DNS lookups asynchronously. It triggers callbacks when hostname resolutions complete.

* **Connection Manager (`net_conn`)**
  Manages individual TCP connections (and optional TLS handshakes) as state machines. It handles connecting (including non-blocking DNS and socket connect), reading, writing, and error detection for each connection.

* **HTTP Transaction (`http_transaction`)**
  Implements the state machine for a single HTTP request/response exchange (from sending the request to reading the entire response). It uses `net_conn` for I/O and parses the HTTP response incrementally.

* **Download Scheduler (`scheduler`)**
  Oversees multiple concurrent HTTP transactions. It queues download jobs, enforces concurrency limits (global and per-host), and decides when to start new transactions or retry failed ones.

* **Persistent Connection Pool (`pconn`)**
  Reuses idle keep-alive connections to avoid reconnecting to the same host repeatedly. Manages a pool of open `net_conn` objects keyed by host (and scheme/port) with limits on reuse.

* **Top-Level CLI Integration (`retr`)**
  The main program logic that ties everything together. It parses user input (URLs and options), initializes all subsystems, and starts the event loop. It enqueues initial download jobs and runs the loop until all downloads are complete, then handles cleanup.

Throughout the implementation, state machines and callbacks drive the flow instead of blocking calls or busy-wait loops. Each module will have a clear API and lifecycle, ensuring that resources (file descriptors, memory, watchers) are allocated and freed in one place. We also establish design guidelines (at the end) to maintain non-blocking behavior and clean organization.