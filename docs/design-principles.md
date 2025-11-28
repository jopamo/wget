# Design Principles and Best Practices

To keep the implementation robust and maintainable, follow these rules:

## I/O Operations

* Use synchronous I/O operations for simplicity and reliability
* When c-ares is available, use it for asynchronous DNS resolution to improve performance
* Handle timeouts appropriately using standard system mechanisms

## Resource Management

* Use clear object lifecycles with obvious creation and destruction points
* Implement single teardown paths where possible
* Ensure proper cleanup of resources (file descriptors, memory)

## Error Handling

* Propagate errors upward through the call chain
* Avoid silent failures; always handle errors appropriately
* Provide meaningful error messages to users

## Memory Management

* Do not buffer entire large downloads in memory; always stream to disk/WARC
* Keep header buffers bounded (e.g., reject headers over some max size)
* Use appropriate data structures for efficient memory usage

## Security

* For TLS, verify certificates (unless explicitly disabled via options)
* Avoid unsafe buffer handling in parsers
* Carefully validate HTTP chunk sizes and header lengths
* Sanitize all user input and URL components

## Testing

* Test components with real and mock servers
* Verify error handling and edge cases
* Ensure compatibility across different platforms

Following these principles yields a reliable, maintainable, and secure downloader that performs well for typical use cases while remaining straightforward to understand and modify.