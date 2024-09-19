import requests
import time

def analyze_http_headers(url, headers=None, cookies=None, proxies=None, verify_ssl=True):
    try:
        # Start timing the request
        start_time = time.time()
        
        # Perform an HTTP GET request with user-provided headers, cookies, and proxies
        response = requests.get(url, headers=headers, cookies=cookies, proxies=proxies, verify=verify_ssl, timeout=10)

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

    except requests.exceptions.Timeout:
        print("[Error]: The request timed out.")
    except requests.exceptions.SSLError:
        print("[Error]: SSL verification failed. You can disable it with 'verify_ssl=False'.")
    except requests.exceptions.RequestException as e:
        print(f"[Error]: An error occurred: {e}")

def get_user_input():
    # Prompt user for a URL
    url = input("Enter the URL (include http:// or https://): ").strip()
    
    # Check if the URL starts with http:// or https://
    if not (url.startswith("http://") or url.startswith("https://")):
        print("[Error]: Invalid URL. Make sure it starts with http:// or https://")
        return None
    return url

def get_bypass_options():
    # Prompt for bypass options
    print("\nSelect 403 bypass options:")
    print("1. Use a custom User-Agent")
    print("2. Use custom Cookies")
    print("3. Use a Proxy")
    print("4. Spoof Referer header")
    print("5. Disable SSL Verification")
    print("6. No bypass, just analyze headers")
    
    choice = input("Choose an option (1-6): ").strip()
    
    headers = {}
    cookies = None
    proxies = None
    verify_ssl = True

    if choice == '1':
        # Set a custom User-Agent header
        headers['User-Agent'] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36"
        print("Using a custom User-Agent.")
    elif choice == '2':
        # Add custom cookies
        cookie_str = input("Enter your cookies (key=value format, separated by semicolons): ").strip()
        cookies = {k: v for k, v in (cookie.split('=') for cookie in cookie_str.split(';'))}
        print("Using custom cookies.")
    elif choice == '3':
        # Add a proxy
        proxy = input("Enter your proxy (format: http://proxy_ip:port or https://proxy_ip:port): ").strip()
        proxies = {"http": proxy, "https": proxy}
        print("Using a proxy.")
    elif choice == '4':
        # Spoof the Referer header
        headers['Referer'] = input("Enter the Referer URL: ").strip()
        print("Using a custom Referer.")
    elif choice == '5':
        # Disable SSL Verification
        verify_ssl = False
        print("Disabling SSL verification.")
    elif choice == '6':
        print("No bypass, just analyzing headers.")
    else:
        print("[Error]: Invalid choice.")
        return None, None, None, None

    return headers, cookies, proxies, verify_ssl

# Main execution
if __name__ == "__main__":
    url = get_user_input()
    if url:
        headers, cookies, proxies, verify_ssl = get_bypass_options()
        analyze_http_headers(url, headers=headers, cookies=cookies, proxies=proxies, verify_ssl=verify_ssl)
