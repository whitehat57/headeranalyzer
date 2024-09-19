import requests
import time
import json
import base64
from io import BytesIO
from PIL import Image
import sys

# Display the header
def display_header():
    print("=" * 50)
    print(" " * 15 + "HTTP Analyzer")
    print(" " * 12 + "Anonymous Fiftyseven")
    print("=" * 50)

# CAPTCHA Solver using 2Captcha
def solve_captcha(api_key, image_url):
    print("[INFO] Sending CAPTCHA to 2Captcha...")

    # 2Captcha API URL
    api_url = "http://2captcha.com/in.php"

    # Send CAPTCHA to 2Captcha
    data = {
        'key': api_key,
        'method': 'base64',
        'body': image_url,
        'json': 1
    }
    
    response = requests.post(api_url, data=data)
    captcha_id = response.json().get('request')
    
    # Poll for CAPTCHA result
    while True:
        print("[INFO] Waiting for CAPTCHA solution...")
        time.sleep(5)
        result_url = f"http://2captcha.com/res.php?key={api_key}&action=get&id={captcha_id}&json=1"
        result_response = requests.get(result_url)
        result_data = result_response.json()

        if result_data.get('status') == 1:
            return result_data.get('request')
        elif result_data.get('status') == 0 and result_data.get('request') != 'CAPCHA_NOT_READY':
            print(f"[ERROR] CAPTCHA solving failed: {result_data.get('request')}")
            return None

# Analyze HTTP Headers and handle bypass methods
def analyze_http_headers(url, headers=None, cookies=None, proxies=None, verify_ssl=True, retries=1, captcha_api_key=None):
    try:
        attempt = 1
        while attempt <= retries:
            print(f"\n[INFO] Attempt {attempt} of {retries}...")

            # Start timing the request
            start_time = time.time()
            
            # Perform an HTTP GET request with user-provided headers, cookies, and proxies
            response = requests.get(url, headers=headers, cookies=cookies, proxies=proxies, verify=verify_ssl, timeout=10)

            # Check for CAPTCHA
            if 'captcha' in response.text.lower() and captcha_api_key:
                print("[INFO] CAPTCHA detected! Solving CAPTCHA...")
                
                # Extract CAPTCHA image URL or base64 (depending on the site)
                captcha_image = extract_captcha_image(response.text)  # Implement based on site-specific extraction
                
                # Solve CAPTCHA
                captcha_solution = solve_captcha(captcha_api_key, captcha_image)
                if captcha_solution:
                    print(f"[INFO] CAPTCHA Solved: {captcha_solution}")
                    # Re-submit the request with the CAPTCHA solution (logic depends on how the CAPTCHA is handled)
                else:
                    print("[ERROR] CAPTCHA solving failed.")
                    return

            # Calculate the response time
            elapsed_time = time.time() - start_time

            print(f"\n[Analyzing Headers for]: {url}")
            print(f"[Response Time]: {elapsed_time:.2f} seconds")

            # Display request headers
            print("\n[Request Headers]")
            for key, value in response.request.headers.items():
                print(f"{key}: {value}")

            # Display response headers
            print("\n[Response Headers]")
            for key, value in response.headers.items():
                print(f"{key}: {value}")

            # Display the HTTP status code
            print(f"\n[Status Code]: {response.status_code}")

            # Display content type
            print(f"[Content Type]: {response.headers.get('Content-Type', 'Unknown')}")

            # Display cookies received from the server
            print("\n[Cookies]:")
            if response.cookies:
                for cookie in response.cookies:
                    print(f"{cookie.name}: {cookie.value}")
            else:
                print("No cookies received.")

            # Check if the response is compressed using gzip or deflate
            encoding = response.headers.get('Content-Encoding')
            if encoding:
                print(f"\n[Content Encoding]: {encoding}")
            else:
                print("\n[Content Encoding]: Not supported.")
            
            if response.status_code == 403:
                print(f"[INFO] 403 Forbidden - Retrying...")
                attempt += 1
            else:
                break

    except requests.exceptions.Timeout:
        print("[Error]: The request timed out.")
    except requests.exceptions.SSLError:
        print("[Error]: SSL verification failed. You can disable it with 'verify_ssl=False'.")
    except requests.exceptions.RequestException as e:
        print(f"[Error]: An error occurred: {e}")

# Function to handle multiple bypass methods and options
def get_bypass_options():
    print("\nSelect bypass options (separate multiple choices by commas, e.g., 1,2):")
    print("1. Use a custom User-Agent")
    print("2. Use custom Cookies")
    print("3. Use a Proxy")
    print("4. Spoof Referer header")
    print("5. Disable SSL Verification")
    print("6. CAPTCHA Solving")
    print("7. Retry on 403")

    choices = input("Choose options (1-7): ").strip().split(',')
    
    headers = {}
    cookies = None
    proxies = None
    verify_ssl = True
    retries = 1
    captcha_api_key = None

    for choice in choices:
        if choice == '1':
            headers['User-Agent'] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36"
            print("Using a custom User-Agent.")
        elif choice == '2':
            cookie_str = input("Enter your cookies (key=value format, separated by semicolons): ").strip()
            cookies = {k: v for k, v in (cookie.split('=') for cookie in cookie_str.split(';'))}
            print("Using custom cookies.")
        elif choice == '3':
            proxy = input("Enter your proxy (format: http://proxy_ip:port or https://proxy_ip:port): ").strip()
            proxies = {"http": proxy, "https": proxy}
            print("Using a proxy.")
        elif choice == '4':
            headers['Referer'] = input("Enter the Referer URL: ").strip()
            print("Using a custom Referer.")
        elif choice == '5':
            verify_ssl = False
            print("Disabling SSL verification.")
        elif choice == '6':
            captcha_api_key = input("Enter your 2Captcha API key: ").strip()
            print("Using CAPTCHA solving.")
        elif choice == '7':
            retries = int(input("Enter the number of retries on 403 (default is 1): ").strip())
            print(f"Retrying on 403 up to {retries} times.")
        else:
            print(f"[Error]: Invalid option {choice}. Ignoring.")

    return headers, cookies, proxies, verify_ssl, retries, captcha_api_key

# Main execution
if __name__ == "__main__":
    display_header()
    url = input("Enter the URL (include http:// or https://): ").strip()
    if url:
        headers, cookies, proxies, verify_ssl, retries, captcha_api_key = get_bypass_options()
        analyze_http_headers(url, headers=headers, cookies=cookies, proxies=proxies, verify_ssl=verify_ssl, retries=retries, captcha_api_key=captcha_api_key)
