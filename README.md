# CrossInjector by @FR13ND0x7f

CrossInjector is a Python tool to scan a list of URLs for Cross-Site Scripting (XSS) vulnerabilities. It uses Selenium WebDriver and ChromeDriver to execute JavaScript code and identify if a given URL is vulnerable to XSS attacks.

## Prerequisites

To use CrossInjector, you need to have the following installed:

- Python 3
- Google Chrome browser
- ChromeDriver
- Selenium Python bindings
- webdriver_manager
- termcolor

You can install the required Python packages by running:

```sh
pip install -r requirements.txt
Usage
```

To use CrossInjector, run the following command:

```sh
python CrossInjector.py -p <path-to-payloads-file> -u <path-to-urls-file>
```

```sh
Replace <path-to-payloads-file> with the path to a file containing XSS payloads, and <path-to-urls-file> with the path to a file containing a list of URLs to scan.
```

## License

CrossInjector is licensed under the MIT License.

**Free Software, Hell Yeah!**
