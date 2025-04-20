import sys
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import requests
import threading
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import time
import socket
import ssl
from datetime import datetime

class WebVulnScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("Web Vulnerability Scanner")
        self.root.geometry("900x700")
        self.root.resizable(True, True)
        
        self.setup_ui()
        self.is_scanning = False
        self.stop_requested = False
        
    def setup_ui(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # URL input
        url_frame = ttk.Frame(main_frame)
        url_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(url_frame, text="Target URL:").pack(side=tk.LEFT, padx=5)
        self.url_entry = ttk.Entry(url_frame, width=50)
        self.url_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.url_entry.insert(0, "https://")
        
        # Button frame
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=5)
        
        self.scan_button = ttk.Button(button_frame, text="Start Scan", command=self.start_scan)
        self.scan_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = ttk.Button(button_frame, text="Stop Scan", command=self.stop_scan, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        self.clear_button = ttk.Button(button_frame, text="Clear Results", command=self.clear_results)
        self.clear_button.pack(side=tk.LEFT, padx=5)
        
        # Options frame
        options_frame = ttk.LabelFrame(main_frame, text="Scan Options", padding="5")
        options_frame.pack(fill=tk.X, pady=5)
        
        # Checkboxes for vulnerability types
        self.xss_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="XSS Vulnerabilities", variable=self.xss_var).grid(row=0, column=0, sticky=tk.W, padx=5)
        
        self.sqli_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="SQL Injection", variable=self.sqli_var).grid(row=0, column=1, sticky=tk.W, padx=5)
        
        self.open_redirect_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Open Redirect", variable=self.open_redirect_var).grid(row=1, column=0, sticky=tk.W, padx=5)
        
        self.header_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Header Security", variable=self.header_var).grid(row=1, column=1, sticky=tk.W, padx=5)
        
        self.ssl_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="SSL/TLS Issues", variable=self.ssl_var).grid(row=2, column=0, sticky=tk.W, padx=5)
        
        self.dir_list_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Directory Listing", variable=self.dir_list_var).grid(row=2, column=1, sticky=tk.W, padx=5)

        # Crawling options
        crawl_frame = ttk.Frame(options_frame)
        crawl_frame.grid(row=3, column=0, columnspan=2, sticky=tk.W, pady=5)
        
        ttk.Label(crawl_frame, text="Crawl Depth:").pack(side=tk.LEFT, padx=5)
        self.depth_var = tk.IntVar(value=2)
        depth_spin = ttk.Spinbox(crawl_frame, from_=1, to=5, width=5, textvariable=self.depth_var)
        depth_spin.pack(side=tk.LEFT, padx=5)
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        ttk.Label(main_frame, text="Progress:").pack(anchor=tk.W, pady=(10, 0))
        self.progress_bar = ttk.Progressbar(main_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill=tk.X, pady=(0, 10))
        
        # Results area
        ttk.Label(main_frame, text="Scan Results:").pack(anchor=tk.W)
        self.results_text = scrolledtext.ScrolledText(main_frame, wrap=tk.WORD, height=20)
        self.results_text.pack(fill=tk.BOTH, expand=True)
        self.results_text.config(state=tk.DISABLED)
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        self.status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def update_results(self, text, level="info"):
        """Add text to results with specified level (info, warning, error)"""
        self.results_text.config(state=tk.NORMAL)
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # Color coding based on level
        tag = f"tag_{timestamp}"
        if level == "warning":
            self.results_text.tag_configure(tag, foreground="orange")
        elif level == "error":
            self.results_text.tag_configure(tag, foreground="red")
        elif level == "success":
            self.results_text.tag_configure(tag, foreground="green")
        else:  # info
            self.results_text.tag_configure(tag, foreground="black")
            
        prefix = f"[{timestamp}] "
        self.results_text.insert(tk.END, prefix + text + "\n", tag)
        self.results_text.see(tk.END)
        self.results_text.config(state=tk.DISABLED)
    
    def clear_results(self):
        """Clear the results area"""
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)
        self.results_text.config(state=tk.DISABLED)
        self.progress_var.set(0)
        self.status_var.set("Ready")
    
    def start_scan(self):
        """Start the vulnerability scan in a separate thread"""
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showerror("Error", "Please enter a valid URL")
            return
            
        if not (url.startswith('http://') or url.startswith('https://')):
            url = 'http://' + url
            self.url_entry.delete(0, tk.END)
            self.url_entry.insert(0, url)
            
        self.is_scanning = True
        self.stop_requested = False
        self.scan_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.clear_results()
        
        # Start scan in a separate thread
        scan_thread = threading.Thread(target=self.perform_scan, args=(url,))
        scan_thread.daemon = True
        scan_thread.start()
    
    def stop_scan(self):
        """Request to stop the ongoing scan"""
        if self.is_scanning:
            self.stop_requested = True
            self.status_var.set("Stopping scan...")
    
    def perform_scan(self, base_url):
        """Main scanning function running in a separate thread"""
        try:
            self.status_var.set(f"Scanning {base_url}...")
            self.update_results(f"Starting vulnerability scan on {base_url}")
            
            # Validate URL
            try:
                parsed_url = urlparse(base_url)
                domain = parsed_url.netloc
                if not domain:
                    raise ValueError("Invalid URL")
                    
                # Test connection
                response = requests.head(base_url, timeout=10, allow_redirects=True)
                self.update_results(f"Connection established to {base_url}")
                
            except requests.exceptions.RequestException as e:
                self.update_results(f"Failed to connect to {base_url}: {str(e)}", "error")
                self.scan_complete()
                return
            except ValueError as e:
                self.update_results(f"Invalid URL: {str(e)}", "error")
                self.scan_complete()
                return
                
            # Collect links for scanning
            self.update_results("Crawling website for links...")
            links = self.crawl_website(base_url, self.depth_var.get())
            
            if self.stop_requested:
                self.scan_complete()
                return
                
            # Perform selected scans
            total_scans = sum([
                self.xss_var.get(), 
                self.sqli_var.get(),
                self.open_redirect_var.get(),
                self.header_var.get(),
                self.ssl_var.get(),
                self.dir_list_var.get()
            ])
            
            scan_count = 0
            
            # Check SSL/TLS issues
            if self.ssl_var.get() and not self.stop_requested:
                scan_count += 1
                self.progress_var.set((scan_count / total_scans) * 100)
                self.status_var.set("Checking SSL/TLS configuration...")
                self.check_ssl_issues(base_url)
                
            # Check header security
            if self.header_var.get() and not self.stop_requested:
                scan_count += 1
                self.progress_var.set((scan_count / total_scans) * 100)
                self.status_var.set("Checking security headers...")
                self.check_security_headers(base_url)
                
            # Check directory listing
            if self.dir_list_var.get() and not self.stop_requested:
                scan_count += 1
                self.progress_var.set((scan_count / total_scans) * 100)
                self.status_var.set("Checking directory listing...")
                self.check_directory_listing(base_url)
            
            # Process forms for XSS and SQL Injection
            if (self.xss_var.get() or self.sqli_var.get()) and not self.stop_requested:
                self.status_var.set("Gathering forms...")
                forms = self.extract_forms(base_url)
                self.update_results(f"Found {len(forms)} forms to test")
                
                if self.xss_var.get() and not self.stop_requested:
                    scan_count += 1
                    self.progress_var.set((scan_count / total_scans) * 100)
                    self.status_var.set("Testing for XSS vulnerabilities...")
                    self.check_xss_vulnerability(base_url, forms)
                    
                if self.sqli_var.get() and not self.stop_requested:
                    scan_count += 1
                    self.progress_var.set((scan_count / total_scans) * 100)
                    self.status_var.set("Testing for SQL Injection...")
                    self.check_sql_injection(base_url, forms)
            
            # Check for open redirect vulnerabilities
            if self.open_redirect_var.get() and not self.stop_requested:
                scan_count += 1
                self.progress_var.set((scan_count / total_scans) * 100)
                self.status_var.set("Testing for open redirect vulnerabilities...")
                self.check_open_redirect(links)
            
            # Final status update
            self.progress_var.set(100)
            self.update_results("Vulnerability scan completed!", "success")
            
        except Exception as e:
            self.update_results(f"Error during scan: {str(e)}", "error")
        finally:
            self.scan_complete()
    
    def scan_complete(self):
        """Reset UI after scan completes or is stopped"""
        if self.stop_requested:
            self.update_results("Scan stopped by user", "warning")
            
        self.is_scanning = False
        self.stop_requested = False
        self.scan_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.status_var.set("Ready")
        self.root.update()
    
    def crawl_website(self, base_url, max_depth=2):
        """Crawl website to discover links up to max_depth"""
        visited = set()
        to_visit = {(base_url, 0)}  # (url, depth)
        all_links = set()
        
        while to_visit and not self.stop_requested:
            current_url, depth = to_visit.pop()
            
            if current_url in visited or depth > max_depth:
                continue
                
            visited.add(current_url)
            all_links.add(current_url)
            
            try:
                self.status_var.set(f"Crawling: {current_url}")
                response = requests.get(current_url, timeout=10)
                
                if 'text/html' not in response.headers.get('Content-Type', ''):
                    continue
                    
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Extract links
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    absolute_url = urljoin(current_url, href)
                    
                    # Only follow links to the same domain
                    if urlparse(absolute_url).netloc == urlparse(base_url).netloc:
                        if absolute_url not in visited:
                            to_visit.add((absolute_url, depth + 1))
                
                time.sleep(0.1)  # Small delay to avoid overwhelming the server
                
            except requests.exceptions.RequestException:
                pass  # Skip if can't access the URL
            except Exception as e:
                self.update_results(f"Error crawling {current_url}: {str(e)}", "warning")
        
        self.update_results(f"Crawled {len(visited)} URLs, found {len(all_links)} valid links")
        return all_links
    
    def extract_forms(self, url):
        """Extract all forms from the given URL"""
        forms = []
        try:
            response = requests.get(url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            for form in soup.find_all('form'):
                form_details = {}
                action = form.get('action', '')
                form_details['action'] = urljoin(url, action) if action else url
                form_details['method'] = form.get('method', 'get').lower()
                
                # Get all input elements
                inputs = []
                for input_tag in form.find_all('input'):
                    input_type = input_tag.get('type', 'text')
                    input_name = input_tag.get('name')
                    input_value = input_tag.get('value', '')
                    
                    if input_name:  # Only include inputs with a name attribute
                        inputs.append({
                            'type': input_type,
                            'name': input_name,
                            'value': input_value
                        })
                
                # Add textarea elements
                for textarea in form.find_all('textarea'):
                    name = textarea.get('name')
                    if name:
                        inputs.append({
                            'type': 'textarea',
                            'name': name,
                            'value': textarea.string or ''
                        })
                
                # Add select elements
                for select in form.find_all('select'):
                    name = select.get('name')
                    if name:
                        options = select.find_all('option')
                        selected_option = next((option.get('value', '') for option in options if option.get('selected')), 
                                            options[0].get('value', '') if options else '')
                        inputs.append({
                            'type': 'select',
                            'name': name,
                            'value': selected_option
                        })
                
                form_details['inputs'] = inputs
                forms.append(form_details)
                
        except requests.exceptions.RequestException as e:
            self.update_results(f"Error fetching URL for form extraction: {str(e)}", "warning")
        
        return forms
    
    def check_xss_vulnerability(self, url, forms):
        """Test forms for XSS vulnerabilities"""
        xss_payloads = [
            '<script>alert("XSS")</script>',
            '"><script>alert("XSS")</script>',
            '<img src="x" onerror="alert(\'XSS\')">',
            '\'"<>;/onmouseover=alert("XSS")//\\'
        ]
        
        if not forms:
            self.update_results("No forms found to test for XSS")
            return
            
        vulnerable_forms = 0
        
        for form in forms:
            if self.stop_requested:
                break
                
            form_url = form['action']
            data = {}
            
            # Fill in the form data
            for input_tag in form['inputs']:
                if input_tag['type'] in ['text', 'search', 'url', 'email', 'textarea']:
                    # Test each input field that could accept text
                    for payload in xss_payloads:
                        if self.stop_requested:
                            break
                            
                        # Create a copy of the data for each payload
                        test_data = {}
                        for inp in form['inputs']:
                            if inp['name'] == input_tag['name']:
                                test_data[inp['name']] = payload
                            else:
                                # Fill other inputs with their default or a generic value
                                test_data[inp['name']] = inp['value'] or "test"
                        
                        try:
                            # Send the form with the payload
                            if form['method'] == 'post':
                                response = requests.post(form_url, data=test_data, timeout=10)
                            else:
                                response = requests.get(form_url, params=test_data, timeout=10)
                            
                            # Check if the payload appears in the response
                            if payload in response.text and not '>alert("XSS")' in response.text:
                                self.update_results(f"Potential XSS vulnerability found in form at {form_url}", "error")
                                self.update_results(f"Field: {input_tag['name']}, Payload: {payload}", "error")
                                vulnerable_forms += 1
                                break  # Found vulnerability in this field, move to next field
                                
                        except requests.exceptions.RequestException:
                            continue
                else:
                    # For other input types, just use the default value
                    data[input_tag['name']] = input_tag['value'] or "test"
        
        if vulnerable_forms > 0:
            self.update_results(f"Found {vulnerable_forms} forms potentially vulnerable to XSS", "error")
        else:
            self.update_results("No XSS vulnerabilities detected", "success")
    
    def check_sql_injection(self, url, forms):
        """Test forms for SQL Injection vulnerabilities"""
        sql_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR 1=1 --",
            "admin' --",
            "admin' #",
            "' UNION SELECT 1,2,3 --",
            "'; DROP TABLE users; --"
        ]
        
        error_patterns = [
            "SQL syntax",
            "mysql_fetch",
            "mysqli_fetch",
            "ORA-",
            "Oracle error",
            "Microsoft SQL Server error",
            "ODBC SQL Server error",
            "PostgreSQL error",
            "SQLite3::"
        ]
        
        if not forms:
            self.update_results("No forms found to test for SQL Injection")
            return
            
        vulnerable_forms = 0
        
        for form in forms:
            if self.stop_requested:
                break
                
            form_url = form['action']
            
            for input_tag in form['inputs']:
                if input_tag['type'] in ['text', 'search', 'hidden', 'password']:
                    # Test each input field for SQL injection
                    for payload in sql_payloads:
                        if self.stop_requested:
                            break
                            
                        # Create test data for this payload
                        test_data = {}
                        for inp in form['inputs']:
                            if inp['name'] == input_tag['name']:
                                test_data[inp['name']] = payload
                            else:
                                test_data[inp['name']] = inp['value'] or "test"
                        
                        try:
                            # Send the form with the payload
                            if form['method'] == 'post':
                                response = requests.post(form_url, data=test_data, timeout=10)
                            else:
                                response = requests.get(form_url, params=test_data, timeout=10)
                            
                            # Check for SQL error signatures in the response
                            response_text = response.text.lower()
                            for pattern in error_patterns:
                                if pattern.lower() in response_text:
                                    self.update_results(f"Potential SQL Injection vulnerability found in form at {form_url}", "error")
                                    self.update_results(f"Field: {input_tag['name']}, Payload: {payload}", "error")
                                    self.update_results(f"Error pattern detected: {pattern}", "error")
                                    vulnerable_forms += 1
                                    break
                                    
                        except requests.exceptions.RequestException:
                            continue
        
        if vulnerable_forms > 0:
            self.update_results(f"Found {vulnerable_forms} forms potentially vulnerable to SQL Injection", "error")
        else:
            self.update_results("No SQL Injection vulnerabilities detected", "success")
    
    def check_open_redirect(self, urls):
        """Test URLs for open redirect vulnerabilities"""
        payloads = [
            "//evil.com",
            "https://evil.com",
            "//google.com",
            "https://google.com"
        ]
        
        redirect_params = ['redirect', 'url', 'next', 'goto', 'return', 'returnurl', 'return_url', 'redirect_uri']
        vulnerable_urls = 0
        
        for url in urls:
            if self.stop_requested:
                break
                
            parsed = urlparse(url)
            query_params = parsed.query.split('&')
            
            # Check if URL has potential redirect parameters
            for param in query_params:
                if '=' in param:
                    param_name = param.split('=')[0].lower()
                    
                    if any(redirect_param in param_name for redirect_param in redirect_params):
                        # Test this parameter for open redirect
                        for payload in payloads:
                            if self.stop_requested:
                                break
                                
                            # Construct test URL
                            test_params = []
                            for p in query_params:
                                if p.startswith(param_name + '='):
                                    test_params.append(f"{param_name}={payload}")
                                else:
                                    test_params.append(p)
                            
                            query_string = '&'.join(test_params)
                            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query_string}"
                            
                            try:
                                # Use allow_redirects=False to prevent actually following the redirect
                                response = requests.get(test_url, timeout=10, allow_redirects=False)
                                
                                # Check if the response is a redirect and points to our payload
                                if response.status_code in [301, 302, 303, 307, 308]:
                                    location = response.headers.get('Location', '')
                                    if payload in location:
                                        self.update_results(f"Potential Open Redirect vulnerability found at {url}", "error")
                                        self.update_results(f"Parameter: {param_name}, Redirects to: {location}", "error")
                                        vulnerable_urls += 1
                                        break
                                        
                            except requests.exceptions.RequestException:
                                continue
        
        if vulnerable_urls > 0:
            self.update_results(f"Found {vulnerable_urls} URLs potentially vulnerable to Open Redirect", "error")
        else:
            self.update_results("No Open Redirect vulnerabilities detected", "success")
    
    def check_security_headers(self, url):
        """Check for missing or misconfigured security headers"""
        security_headers = {
            'Strict-Transport-Security': 'Missing HSTS header',
            'X-Content-Type-Options': 'Missing X-Content-Type-Options header',
            'X-Frame-Options': 'Missing X-Frame-Options header',
            'Content-Security-Policy': 'Missing Content-Security-Policy header',
            'X-XSS-Protection': 'Missing X-XSS-Protection header',
            'Referrer-Policy': 'Missing Referrer-Policy header'
        }
        
        try:
            response = requests.get(url, timeout=10)
            headers = response.headers
            
            missing_headers = []
            for header, message in security_headers.items():
                if header not in headers:
                    missing_headers.append(message)
            
            if missing_headers:
                self.update_results("Security Header Issues:", "warning")
                for message in missing_headers:
                    self.update_results(f"• {message}", "warning")
            else:
                self.update_results("All major security headers are present", "success")
                
            # Check for cookies without secure flag
            cookies = response.cookies
            insecure_cookies = []
            
            for cookie in cookies:
                if not cookie.secure:
                    insecure_cookies.append(cookie.name)
                    
            if insecure_cookies:
                self.update_results(f"Found {len(insecure_cookies)} cookies without Secure flag:", "warning")
                for cookie_name in insecure_cookies:
                    self.update_results(f"• Cookie '{cookie_name}' missing Secure flag", "warning")
            
        except requests.exceptions.RequestException as e:
            self.update_results(f"Error checking security headers: {str(e)}", "error")
    
    def check_ssl_issues(self, url):
        """Check for SSL/TLS configuration issues"""
        if not url.startswith('https://'):
            self.update_results("Site is not using HTTPS", "warning")
            return
            
        try:
            parsed_url = urlparse(url)
            hostname = parsed_url.netloc
            port = 443
            
            # Check if port is specified in URL
            if ':' in hostname:
                hostname, port_str = hostname.split(':')
                port = int(port_str)
            
            # Connect to the server
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Get certificate
                    cert = ssock.getpeercert()
                    
                    # Check expiration
                    not_after = cert['notAfter']
                    expiry_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    now = datetime.now()
                    days_to_expiry = (expiry_date - now).days
                    
                    if days_to_expiry < 0:
                        self.update_results("SSL Certificate has expired!", "error")
                    elif days_to_expiry < 30:
                        self.update_results(f"SSL Certificate will expire in {days_to_expiry} days", "warning")
                    else:
                        self.update_results(f"SSL Certificate is valid for {days_to_expiry} more days", "success")
                    
                    # Check TLS version
                    version = ssock.version()
                    if version == "TLSv1" or version == "TLSv1.1":
                        self.update_results(f"Using outdated TLS version: {version}", "warning")
                    else:
                        self.update_results(f"Using secure TLS version: {version}", "success")
                        
        except ssl.SSLError as e:
            self.update_results(f"SSL Error: {str(e)}", "error")
        except socket.error as e:
            self.update_results(f"Socket Error during SSL check: {str(e)}", "error")
        except Exception as e:
            self.update_results(f"Error checking SSL configuration: {str(e)}", "error")
    
    def check_directory_listing(self, url):
        """Check for enabled directory listing"""
        common_dirs = [
            '/images/',
            '/uploads/',
            '/assets/',
            '/backup/',
            '/admin/',
            '/config/',
            '/data/',
            '/logs/',
            '/files/',
            '/temp/',
            '/test/'
        ]
        
        for directory in common_dirs:
            if self.stop_requested:
                break
                
            test_url = urljoin(url, directory)
            try:
                response = requests.get(test_url, timeout=10)
                
                # Check if directory listing is enabled
                indicators = [
                    'Index of',
                    'Directory Listing',
                    '<title>Index of',
                    'Parent Directory</a>'
                ]
                
                body = response.text.lower()
                if (response.status_code == 200 and 
                    any(indicator.lower() in body for indicator in indicators)):
                    self.update_results(f"Directory listing enabled at {test_url}", "error")
                    
            except requests.exceptions.RequestException:
                continue

if __name__ == "__main__":
    root = tk.Tk()
    app = WebVulnScanner(root)
    root.mainloop()
