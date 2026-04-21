from http.server import HTTPServer, BaseHTTPRequestHandler
import ssl

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(
    certfile="/home/sebastian/utils/ssl_mock/cert.pem",
    keyfile="/home/sebastian/utils/ssl_mock/key.pem"
)

httpd = HTTPServer(('0.0.0.0', 8002), BaseHTTPRequestHandler)
httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
httpd.serve_forever()
