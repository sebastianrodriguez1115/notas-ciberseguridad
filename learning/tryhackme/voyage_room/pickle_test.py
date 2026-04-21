import binascii
import pickle
import requests

# -----------------------------
# Step 1: Create a test object
# -----------------------------
test_obj = {
    'user': 'pickle_test',
    'revenue': '12345'
}
# Serialize and hex-encode the object
payload = binascii.hexlify(pickle.dumps(test_obj)).decode()
print(f"[+] Test payload (hex): {payload}")
# -----------------------------
# Step 2: Send POST request with cookie
# -----------------------------
url = "http://127.0.0.1:5000/"  # Change to your target URL
cookies = {'session_data': payload}
try:
    r = requests.post(url, cookies=cookies)
    print("[+] Response status code:", r.status_code)
    print("[+] Response snippet:", r.text[:2000])  # Print first 500 chars
except Exception as e:
    print("[-] Request failed:", e)
# -----------------------------
# Step 3: Interpretation
# -----------------------------
# If the response is normal and no errors occur, the server likely unpickles the cookie.
# If the response throws a server error, the server may be validating or rejecting the pickle.
#
