Here you go — **a complete checklist of everything Wget MUST implement** (i.e., all items from the list rewritten as required features for *wget itself*, no comparison wording, no references to wget2).
This is now a **requirements checklist** for a fully modern wget.

---

# **Wget Feature Requirements Checklist**

### **Performance / Parallelism**

* [ ] Multi-threaded download engine
* [ ] Parallel downloading of multiple files
* [ ] Parallel range-requests for single-file acceleration
* [ ] Connection pooling with persistent keep-alive
* [ ] Internal DNS caching layer

---

### **Modern HTTP/TLS Capabilities**

* [ ] HTTP/2 support
* [ ] Improved HTTP/1.1 pipelining/streaming behavior
* [ ] TLS session resumption
* [ ] TLS False Start support
* [ ] OCSP and OCSP-stapling validation
* [ ] TCP Fast Open support (when available)

---

### **URL & Redirect Handling**

* [ ] Fully RFC-correct URL parser
* [ ] Correct relative URL resolution
* [ ] Hardened redirect logic with safety checks
* [ ] Improved filename/content-type detection

---

### **Crawling / Mirroring Features**

* [ ] Link extraction from HTML and XHTML
* [ ] Link extraction from CSS files
* [ ] Parsing and traversal of RSS and Atom feeds
* [ ] Parsing of XML Sitemap files
* [ ] Metalink support (multi-source + checksums)
* [ ] Extended recursion filters and smarter crawl heuristics

---

### **Robustness / Safety Guarantees**

* [ ] Strict and consistent Content-Length enforcement
* [ ] Resilient retry and reconnection logic
* [ ] Built-in checksum verification framework
* [ ] Improved signal handling and clean shutdown behavior

---

### **Additional Functionality**

* [ ] HTTP compression support (gzip / brotli)
* [ ] Enhanced progress reporting and logging
* [ ] Full IPv6 support with fallback logic
* [ ] Automatic decompression of compressed bodies
* [ ] Full cookie management with a dedicated cookie subsystem

---

### **Code Quality / Portability**

* [ ] Modern build system (e.g., Meson)
* [ ] Broad unit-test coverage and fuzz testing
* [ ] Minimized legacy code and compatibility hacks
* [ ] Clean modular architecture to replace legacy wget internals
