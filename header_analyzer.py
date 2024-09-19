import requests
import time

def analyze_http_headers(url):
    try:
        # Start timing the request
        start_time = time.time()
        
        # Perform an HTTP GET request with SSL verification
        response = requests.get(url, timeout=10)

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
        print("[Error]: SSL verification failed. You can disable it with 'verify=False'.")
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

# Main execution
if __name__ == "__main__":
    url = get_user_input()
    if url:
        analyze_http_headers(url)
