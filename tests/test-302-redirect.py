#!/usr/bin/env python3
"""
Simple HTTP server for testing 302 redirects with wget.
This server provides endpoints that return HTTP 302 redirects to test
wget's redirect handling capabilities.
"""

import http.server
import socketserver
import sys
import os

class RedirectHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        """Handle GET requests with redirects"""

        # Test single 302 redirect
        if self.path == '/redirect-302':
            self.send_response(302)
            self.send_header('Location', '/hello.txt')
            self.send_header('Content-Type', 'text/plain')
            self.send_header('Content-Length', '0')
            self.end_headers()
            return

        # Test multiple 302 redirects (chain)
        elif self.path == '/redirect-chain-1':
            self.send_response(302)
            self.send_header('Location', '/redirect-chain-2')
            self.send_header('Content-Type', 'text/plain')
            self.send_header('Content-Length', '0')
            self.end_headers()
            return

        elif self.path == '/redirect-chain-2':
            self.send_response(302)
            self.send_header('Location', '/redirect-chain-3')
            self.send_header('Content-Type', 'text/plain')
            self.send_header('Content-Length', '0')
            self.end_headers()
            return

        elif self.path == '/redirect-chain-3':
            self.send_response(302)
            self.send_header('Location', '/hello.txt')
            self.send_header('Content-Type', 'text/plain')
            self.send_header('Content-Length', '0')
            self.end_headers()
            return

        # Test 302 with body (should be ignored by wget)
        elif self.path == '/redirect-with-body':
            self.send_response(302)
            self.send_header('Location', '/hello.txt')
            self.send_header('Content-Type', 'text/plain')
            self.send_header('Content-Length', '20')
            self.end_headers()
            # Send a body that should be ignored
            self.wfile.write(b"This should be ignored")
            return

        # Serve regular files
        else:
            super().do_GET()

def main():
    """Start the test HTTP server"""
    PORT = 18081

    # Change to test directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    httpd_root = os.path.join(script_dir, 'httpd-root')
    os.chdir(httpd_root)

    with socketserver.TCPServer(("", PORT), RedirectHTTPRequestHandler) as httpd:
        print(f"Test HTTP server running on port {PORT}")
        print("Available test endpoints:")
        print("  /redirect-302 - Single 302 redirect to /hello.txt")
        print("  /redirect-chain-1 - Chain of 3 redirects ending at /hello.txt")
        print("  /redirect-with-body - 302 with response body (should be ignored)")
        print("  /hello.txt - Regular file for testing")
        print("\nPress Ctrl+C to stop the server")

        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down test server...")

if __name__ == "__main__":
    main()