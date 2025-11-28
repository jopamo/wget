# Overview

**Status Note**: This document describes the **current architecture** of the wget downloader. The implementation uses synchronous I/O with optional asynchronous DNS resolution via c-ares.

This architecture provides a robust web downloader that balances performance with simplicity. The system uses synchronous I/O operations with optional asynchronous DNS resolution when c-ares is available. This approach provides good performance for typical use cases while maintaining straightforward code structure.

## Key components and their roles

* **DNS Resolution (`host.c`)**
  Provides hostname resolution using either synchronous system calls (`getaddrinfo`) or optional asynchronous DNS via c-ares when available. Supports both IPv4 and IPv6 address families.

* **Connection Management (`connect.c`)**
  Manages TCP connections using synchronous I/O operations. Handles connection establishment, socket operations, and error handling for HTTP and FTP protocols.

* **HTTP Protocol (`http.c`)**
  Implements HTTP protocol handling including request generation, response parsing, and content retrieval. Uses synchronous I/O for reading and writing HTTP data.

* **HTTP Transaction (`http-transaction.c`)**
  Manages individual HTTP request/response exchanges with state tracking and error handling. Provides a structured approach to HTTP interactions.

* **Main Retrieval Logic (`retr.c`)**
  Coordinates the overall download process, handling URL processing, file operations, and the main download loop. Integrates with other components to perform complete downloads.

* **CLI Entry Point (`main.c`)**
  The main program entry point that parses command-line arguments, initializes subsystems, and orchestrates the download process based on user input.

The implementation uses synchronous I/O operations with careful resource management. Each module has a clear API and lifecycle, ensuring that resources (file descriptors, memory) are properly allocated and freed. The design emphasizes reliability and maintainability while providing good performance for typical download scenarios.