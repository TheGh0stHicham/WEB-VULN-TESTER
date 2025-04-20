# Web Vulnerability Scanner

A Python-based GUI application for scanning common web vulnerabilities, built with Tkinter. It provides a simple interface to crawl a target website, perform multiple security checks, and display results in real time.

## Features

- **URL Validation & Connection Test**: Verifies the target URL and establishes an initial connection.
- **Crawling**: Discovers links up to a configurable depth to identify potential entry points.
- **SSL/TLS Checks**: Validates certificate expiration, days to expiry, and TLS version.
- **Security Header Analysis**: Detects missing or misconfigured HTTP security headers (HSTS, CSP, X-Frame-Options, etc.).
- **Directory Listing Detection**: Tests common directories for enabled directory listings.
- **Form Extraction & Testing**:
  - **XSS**: Injects payloads into form inputs to detect cross-site scripting vulnerabilities.
  - **SQL Injection**: Sends SQL payloads to identify error-based SQL injection issues.
- **Open Redirect Detection**: Scans URLs for redirect parameters and payloads that could lead to open redirects.
- **Live Progress & Logging**: Shows scan progress with a progress bar and logs timestamped results with color-coded severity.
- **Control Actions**: Start, stop, and clear scan functionality for interactive use.

## Prerequisites

- Python 3.7 or higher
- The following Python packages:
  - `requests`
  - `beautifulsoup4`

> Note: `tkinter` is included in the Python standard library on most systems.

## Installation

1. **Clone the repository**

   ```bash
   git clone https://github.com/yourusername/web-vuln-scanner.git
   cd web-vuln-scanner
   ```

2. **Install dependencies**

   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**

   ```bash
   python web_vuln_scanner.py
   ```

## Usage

1. Launch the application.
2. Enter the target URL (include `http://` or `https://`).
3. Select which checks to perform:
   - XSS
   - SQL Injection
   - Open Redirect
   - Security Headers
   - SSL/TLS Issues
   - Directory Listing
4. Set the crawl depth (default is 2).
5. Click **Start Scan** to begin.
6. View real-time progress and results in the log area.
7. Use **Stop Scan** to cancel, or **Clear Results** to reset.

## Project Structure

```
web-vuln-scanner/
├── web_vuln_scanner.py   # Main application code
├── requirements.txt      # Python dependencies
└── README.md             # This documentation
```

## Configuration

- **Crawl Depth**: Adjust in the GUI to control how many link levels are followed.
- **Timeouts & Delays**: Modify `timeout` and `time.sleep` values in the code for faster or slower scans.

## Troubleshooting

- **Connection Errors**: Ensure the target URL is reachable and network/firewall settings allow HTTP/S requests.
- **SSL Errors**: Sites with self-signed or expired certificates may trigger errors; consider adding exception handling or bypass logic.
- **Platform Issues**: On Linux, ensure `tkinter` is installed (`sudo apt-get install python3-tk`).

## Contributing

Contributions are welcome! Feel free to open issues or submit pull requests for new features, bug fixes, or enhancements.

## License

This project is licensed under TheGh0stHicham.

