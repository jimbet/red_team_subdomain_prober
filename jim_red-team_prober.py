#!/usr/bin/env python3
"""
Advanced Red Team Subdomain With Common Port Prober - v1.4
Author: Sir Jimbet
Version: 1.4 - Red Team Edition with Live Progress
"""
import colorama
colorama.init(autoreset=True)
import concurrent.futures
from typing import List, Dict, Set, Tuple, Optional
from collections import defaultdict
import json
import sys
import requests
import time
import warnings
import dns.resolver
import dns.exception
import random
import socket
import ssl
import urllib3
from datetime import datetime
import hashlib
import re
import threading

warnings.filterwarnings('ignore', message='Unverified HTTPS request')
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# API KEYS CONFIGURATION
GITHUB_TOKEN = ""
SHODAN_API_KEY = ""
CENSYS_API_ID = ""
CENSYS_API_SECRET = ""


class Colors:
    """Color codes for terminal output"""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    DOMAIN = '\033[96m'
    IP = '\033[93m'
    SUCCESS = '\033[92m'
    ERROR = '\033[91m'
    INFO = '\033[94m'
    HIGHLIGHT = '\033[95m'


class Spinner:
    """Animated spinner for long-running operations"""

    def __init__(self, message: str = "Processing", style: str = "line"):
        self.message = message
        self.running = False
        self.thread = None

        self.styles = {
            'line': ['—', '\\', '|', '/'],
            'dots': ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'],
            'arrow': ['←', '↖', '↑', '↗', '→', '↘', '↓', '↙'],
            'box': ['◰', '◳', '◲', '◱'],
            'bounce': ['⠁', '⠂', '⠄', '⡀', '⢀', '⠠', '⠐', '⠈']
        }
        self.frames = self.styles.get(style, self.styles['line'])
        self.current_frame = 0

    def spin(self):
        while self.running:
            frame = self.frames[self.current_frame % len(self.frames)]
            sys.stdout.write(f'\r{Colors.INFO}{frame}{Colors.ENDC} {self.message}')
            sys.stdout.flush()
            self.current_frame += 1
            time.sleep(0.1)

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self.spin, daemon=True)
        self.thread.start()

    def stop(self, final_message: str = None):
        self.running = False
        if self.thread:
            self.thread.join()
        sys.stdout.write('\r' + ' ' * (len(self.message) + 10) + '\r')
        sys.stdout.flush()
        if final_message:
            print(final_message)

    def update_message(self, new_message: str):
        self.message = new_message


class ProxyManager:
    """Proxy and TOR management"""

    def __init__(self, use_tor: bool = False, proxy_list: Optional[List[str]] = None,
                 rotate_proxy: bool = False):
        self.use_tor = use_tor
        self.proxy_list = proxy_list or []
        self.rotate_proxy = rotate_proxy
        self.current_proxy_index = 0
        self.tor_available = False

        if use_tor:
            self.tor_available = self._check_tor_connection()

    def _check_tor_connection(self) -> bool:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex(('127.0.0.1', 9050))
            sock.close()
            return result == 0
        except:
            return False

    def get_proxy_config(self) -> Optional[Dict[str, str]]:
        if self.use_tor and self.tor_available:
            return {'http': 'socks5h://127.0.0.1:9050', 'https': 'socks5h://127.0.0.1:9050'}
        elif self.proxy_list and len(self.proxy_list) > 0:
            if self.rotate_proxy:
                proxy = self.proxy_list[self.current_proxy_index]
                self.current_proxy_index = (self.current_proxy_index + 1) % len(self.proxy_list)
            else:
                proxy = self.proxy_list[0]
            return {'http': proxy, 'https': proxy}
        return None

    def get_random_user_agent(self) -> str:
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        ]
        return random.choice(user_agents)

    def test_tor_connection(self) -> bool:
        try:
            session = requests.Session()
            session.proxies = self.get_proxy_config()
            response = session.get('https://check.torproject.org/api/ip', timeout=20)
            data = response.json()
            return data.get('IsTor', False)
        except:
            return False


class TakeoverChecker:
    """Check for subdomain takeover vulnerabilities"""

    TAKEOVER_FINGERPRINTS = {
        'github': {'cname': ['github.io', 'github.com'], 'response': ['There isn\'t a GitHub Pages site here', 'For root URLs']},
        'heroku': {'cname': ['herokuapp.com', 'herokussl.com'], 'response': ['no-such-app.html', 'There\'s nothing here']},
        'aws_s3': {'cname': ['s3.amazonaws.com', 's3-website'], 'response': ['NoSuchBucket', 'The specified bucket does not exist']},
        'azure': {'cname': ['azurewebsites.net', 'cloudapp.azure.com'], 'response': ['404 Web Site not found', 'Azure Web App - Error']},
        'shopify': {'cname': ['myshopify.com'], 'response': ['Sorry, this shop is currently unavailable']},
        'fastly': {'cname': ['fastly.net'], 'response': ['Fastly error: unknown domain']},
        'ghost': {'cname': ['ghost.io'], 'response': ['The thing you were looking for is no longer here']},
        'pantheon': {'cname': ['pantheonsite.io'], 'response': ['404 error unknown site']},
        'tumblr': {'cname': ['tumblr.com'], 'response': ['Whatever you were looking for doesn\'t currently exist']},
        'wordpress': {'cname': ['wordpress.com'], 'response': ['Do you want to register']},
        'cloudfront': {'cname': ['cloudfront.net'], 'response': ['Bad request', 'ERROR: The request could not be satisfied']}
    }

    def check_takeover(self, subdomain: str, cname: Optional[str] = None) -> Dict:
        result = {'subdomain': subdomain, 'vulnerable': False, 'service': None, 'confidence': 'low', 'cname': cname, 'evidence': []}
        if not cname:
            return result

        for service, fingerprint in self.TAKEOVER_FINGERPRINTS.items():
            cname_match = any(pattern in cname.lower() for pattern in fingerprint['cname'])
            if cname_match:
                try:
                    for protocol in ['https', 'http']:
                        try:
                            url = f"{protocol}://{subdomain}"
                            response = requests.get(url, timeout=10, verify=False, allow_redirects=True)
                            for pattern in fingerprint['response']:
                                if pattern.lower() in response.text.lower():
                                    result['vulnerable'] = True
                                    result['service'] = service
                                    result['confidence'] = 'high'
                                    result['evidence'].append(f"CNAME: {cname}")
                                    result['evidence'].append(f"Pattern found: {pattern}")
                                    result['evidence'].append(f"Status: {response.status_code}")
                                    return result
                            break
                        except:
                            continue
                except Exception:
                    result['service'] = service
                    result['confidence'] = 'medium'
                    result['evidence'].append(f"CNAME points to {service} but unreachable")
        return result


class PortScanner:
    """Fast port scanner"""

    PUBLIC_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 465, 587, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9200, 9443, 27017]

    COMMON_SERVICES = {
        21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP',
        443: 'HTTPS', 445: 'SMB', 465: 'SMTPS', 587: 'SMTP', 993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL',
        1521: 'Oracle', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis',
        8000: 'HTTP-Alt', 8008: 'HTTP-Alt', 8080: 'HTTP-Proxy', 8081: 'HTTP-Alt', 8443: 'HTTPS-Alt',
        8888: 'HTTP-Alt', 9000: 'HTTP-Alt', 9200: 'Elasticsearch', 9443: 'HTTPS-Alt', 27017: 'MongoDB'
    }

    def scan_ports(self, host: str, ports: List[int] = None, timeout: float = 0.5) -> Dict[int, Dict]:
        if ports is None:
            ports = self.PUBLIC_PORTS
        open_ports = {}
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((host, port))
                if result == 0:
                    service = self.COMMON_SERVICES.get(port, 'Unknown')
                    banner = self._grab_banner(sock, port)
                    open_ports[port] = {'service': service, 'banner': banner}
                sock.close()
            except:
                pass
        return open_ports

    def _grab_banner(self, sock: socket.socket, port: int) -> Optional[str]:
        try:
            sock.settimeout(2)
            try:
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                if banner:
                    return banner[:200]
            except:
                pass
            if port in [80, 8080, 8443, 8000, 8008, 8081, 8888, 9000, 9443]:
                sock.send(b'GET / HTTP/1.0\r\n\r\n')
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                if banner:
                    for line in banner.split('\n'):
                        if line.lower().startswith('server:'):
                            return line.split(':', 1)[1].strip()[:200]
            elif port == 22:
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                return banner[:200]
            elif port == 21:
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                return banner[:200]
            return None
        except:
            return None


class HTTPProber:
    """Probe HTTP/HTTPS services"""

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})

    def probe(self, subdomain: str) -> Dict:
        result = {'subdomain': subdomain, 'http': None, 'https': None, 'redirect': None, 'title': None,
                  'status_code': None, 'server': None, 'technologies': [], 'headers': {}}
        for protocol in ['https', 'http']:
            try:
                url = f"{protocol}://{subdomain}"
                response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                result[protocol] = True
                result['status_code'] = response.status_code
                result['server'] = response.headers.get('Server', 'Unknown')
                result['headers'] = dict(response.headers)
                title_match = re.search(r'<title[^>]*>([^<]+)</title>', response.text, re.IGNORECASE)
                if title_match:
                    result['title'] = title_match.group(1).strip()
                result['technologies'] = self._detect_technologies(response)
                if response.history:
                    result['redirect'] = response.url
                break
            except:
                continue
        return result

    def _detect_technologies(self, response: requests.Response) -> List[str]:
        technologies = []
        headers = response.headers
        content = response.text.lower()
        server = headers.get('Server', '').lower()
        if 'apache' in server:
            technologies.append('Apache')
        if 'nginx' in server:
            technologies.append('Nginx')
        if 'cloudflare' in server:
            technologies.append('Cloudflare')
        if 'microsoft' in server or 'iis' in server:
            technologies.append('IIS')
        if 'x-powered-by' in headers:
            technologies.append(headers['x-powered-by'])
        if 'wp-content' in content or 'wordpress' in content:
            technologies.append('WordPress')
        if 'drupal' in content:
            technologies.append('Drupal')
        if 'joomla' in content:
            technologies.append('Joomla')
        if 'react' in content:
            technologies.append('React')
        if 'angular' in content:
            technologies.append('Angular')
        if 'vue' in content:
            technologies.append('Vue.js')
        return list(set(technologies))


class WAFDetector:
    """Detect WAF/CDN"""

    WAF_SIGNATURES = {
        'Cloudflare': ['__cfduid', 'cf-ray', 'cloudflare'],
        'Akamai': ['akamai', 'akamaighost'],
        'Imperva': ['incap_ses', 'visid_incap', 'imperva'],
        'AWS WAF': ['x-amzn-', 'awselb'],
        'Sucuri': ['sucuri', 'x-sucuri'],
        'Wordfence': ['wordfence'],
        'ModSecurity': ['mod_security', 'NOYB'],
        'F5 BIG-IP': ['bigip', 'f5'],
        'Barracuda': ['barracuda'],
        'Fortinet': ['fortinet', 'fortigate']
    }

    def detect(self, subdomain: str) -> Dict:
        result = {'subdomain': subdomain, 'waf_detected': False, 'waf_name': None, 'cdn_detected': False, 'cdn_name': None, 'evidence': []}
        try:
            for protocol in ['https', 'http']:
                try:
                    url = f"{protocol}://{subdomain}"
                    response = requests.get(url, timeout=10, verify=False)
                    all_headers = str(response.headers).lower() + str(response.cookies).lower()
                    for waf_name, signatures in self.WAF_SIGNATURES.items():
                        for sig in signatures:
                            if sig.lower() in all_headers:
                                result['waf_detected'] = True
                                result['waf_name'] = waf_name
                                result['evidence'].append(f"Signature: {sig}")
                                if waf_name in ['Cloudflare', 'Akamai']:
                                    result['cdn_detected'] = True
                                    result['cdn_name'] = waf_name
                    break
                except:
                    continue
        except:
            pass
        return result


class SSLAnalyzer:
    """Analyze SSL/TLS certificates"""

    def analyze_certificate(self, hostname: str) -> Dict:
        result = {'hostname': hostname, 'has_ssl': False, 'issuer': None, 'subject': None, 'san_domains': [], 'expiry': None, 'expired': False, 'self_signed': False}
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    result['has_ssl'] = True
                    issuer = dict(x[0] for x in cert.get('issuer', []))
                    result['issuer'] = issuer.get('organizationName', 'Unknown')
                    subject = dict(x[0] for x in cert.get('subject', []))
                    result['subject'] = subject.get('commonName', 'Unknown')
                    san = cert.get('subjectAltName', [])
                    for type_name, value in san:
                        if type_name == 'DNS':
                            clean_domain = value.replace('*.', '')
                            result['san_domains'].append(clean_domain)
                    not_after = cert.get('notAfter')
                    if not_after:
                        expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                        result['expiry'] = expiry_date.isoformat()
                        result['expired'] = expiry_date < datetime.now()
                    if result['issuer'] == result['subject']:
                        result['self_signed'] = True
        except:
            pass
        return result


class CloudAssetFinder:
    """Find cloud storage buckets"""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})

    def find_s3_buckets(self, domain: str) -> List[Dict]:
        buckets_found = []
        patterns = [domain, domain.replace('.', '-'), domain.replace('.', ''), f"{domain}-assets", f"{domain}-backup",
                    f"{domain}-uploads", f"{domain}-files", f"{domain}-data", f"{domain}-storage", f"{domain}-media", f"{domain}-static"]
        for bucket_name in patterns:
            urls = [f"https://{bucket_name}.s3.amazonaws.com", f"https://s3.amazonaws.com/{bucket_name}"]
            for url in urls:
                try:
                    response = self.session.get(url, timeout=5, allow_redirects=False)
                    if response.status_code in [200, 403, 301]:
                        bucket_info = {'bucket_name': bucket_name, 'url': url, 'status': response.status_code,
                                       'public': response.status_code == 200, 'listable': False}
                        if response.status_code == 200 and 'ListBucketResult' in response.text:
                            bucket_info['listable'] = True
                        buckets_found.append(bucket_info)
                        break
                except:
                    continue
        return buckets_found

    def find_azure_blobs(self, domain: str) -> List[Dict]:
        blobs_found = []
        patterns = [domain.replace('.', ''), domain.replace('.', '-')]
        for blob_name in patterns:
            url = f"https://{blob_name}.blob.core.windows.net"
            try:
                response = self.session.get(url, timeout=5)
                if response.status_code in [200, 400]:
                    blobs_found.append({'blob_name': blob_name, 'url': url, 'status': response.status_code})
            except:
                continue
        return blobs_found


class WHOISLookup:
    """WHOIS information gathering"""

    def lookup(self, domain: str) -> Dict:
        result = {'registrar': None, 'creation_date': None, 'expiration_date': None, 'name_servers': [], 'status': []}
        try:
            import whois
            w = whois.whois(domain)
            result['registrar'] = w.registrar
            result['creation_date'] = str(w.creation_date) if w.creation_date else None
            result['expiration_date'] = str(w.expiration_date) if w.expiration_date else None
            result['name_servers'] = w.name_servers if w.name_servers else []
            result['status'] = w.status if w.status else []
        except ImportError:
            result['error'] = 'python-whois not installed (pip install python-whois)'
        except Exception as e:
            result['error'] = str(e)
        return result


class IPGeolocation:
    """IP geolocation and ASN lookup"""

    def __init__(self):
        self.session = requests.Session()

    def geolocate(self, ip: str) -> Dict:
        result = {'ip': ip, 'country': None, 'city': None, 'org': None, 'asn': None}
        try:
            response = self.session.get(f"http://ip-api.com/json/{ip}", timeout=5)
            if response.status_code == 200:
                data = response.json()
                result['country'] = data.get('country')
                result['city'] = data.get('city')
                result['org'] = data.get('org')
                result['asn'] = data.get('as')
        except:
            pass
        return result


class APIEndpointDiscovery:
    """Discover API endpoints"""

    COMMON_API_PATHS = ['/api', '/api/v1', '/api/v2', '/api/v3', '/rest', '/rest/api', '/rest/v1',
                        '/graphql', '/gql', '/swagger', '/swagger.json', '/swagger/v1/swagger.json',
                        '/api-docs', '/api/docs', '/docs', '/openapi.json', '/openapi.yaml', '/v1', '/v2', '/v3']

    def discover(self, subdomain: str) -> List[Dict]:
        found_endpoints = []
        for protocol in ['https', 'http']:
            base_url = f"{protocol}://{subdomain}"
            for path in self.COMMON_API_PATHS:
                try:
                    url = base_url + path
                    response = requests.get(url, timeout=5, verify=False, allow_redirects=False)
                    if response.status_code in [200, 301, 302]:
                        found_endpoints.append({'url': url, 'status': response.status_code,
                                               'content_type': response.headers.get('Content-Type', '')})
                except:
                    continue
            if found_endpoints:
                break
        return found_endpoints


class GitHubDorkSearcher:
    """Search GitHub for sensitive information"""

    def __init__(self, github_token: Optional[str] = None):
        self.token = github_token
        self.session = requests.Session()
        if github_token:
            self.session.headers.update({'Authorization': f'token {github_token}'})

    def search(self, domain: str, max_results: int = 10) -> List[Dict]:
        if not self.token:
            return []
        results = []
        queries = [f'"{domain}" password', f'"{domain}" api_key', f'"{domain}" secret',
                   f'"{domain}" token', f'"{domain}" credentials']
        for query in queries:
            try:
                url = f"https://api.github.com/search/code?q={query}&per_page={max_results}"
                response = self.session.get(url, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    for item in data.get('items', []):
                        results.append({'repository': item.get('repository', {}).get('full_name'),
                                       'file': item.get('name'), 'url': item.get('html_url'), 'query': query})
                elif response.status_code == 403:
                    break
            except:
                continue
        return results


class ShodanSearcher:
    """Search Shodan for exposed services"""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key

    def search(self, domain: str) -> List[Dict]:
        if not self.api_key:
            return []
        results = []
        try:
            import shodan
            api = shodan.Shodan(self.api_key)
            search_results = api.search(f'hostname:{domain}')
            for result in search_results['matches']:
                results.append({'ip': result['ip_str'], 'port': result.get('port'), 'org': result.get('org'),
                               'os': result.get('os'), 'data': result.get('data', '')[:200]})
        except:
            pass
        return results


class CensysSearcher:
    """Search Censys for certificates"""

    def __init__(self, api_id: Optional[str] = None, api_secret: Optional[str] = None):
        self.api_id = api_id
        self.api_secret = api_secret

    def search(self, domain: str) -> List[Dict]:
        if not self.api_id or not self.api_secret:
            return []
        results = []
        try:
            import censys.certificates
            c = censys.certificates.CensysCertificates(self.api_id, self.api_secret)
            for cert in c.search(f'parsed.names: {domain}'):
                results.append({'fingerprint': cert.get('fingerprint_sha256'),
                               'names': cert.get('parsed', {}).get('names', []),
                               'issuer': cert.get('parsed', {}).get('issuer', {})})
        except:
            pass
        return results


class ChangeTracker:
    """Track changes between scans"""

    def __init__(self, history_file: str = 'scan_history.json'):
        self.history_file = history_file

    def load_previous_scan(self, domain: str) -> Optional[Dict]:
        try:
            with open(self.history_file, 'r') as f:
                history = json.load(f)
                return history.get(domain)
        except:
            return None

    def save_scan(self, domain: str, results: Dict):
        try:
            history = {}
            try:
                with open(self.history_file, 'r') as f:
                    history = json.load(f)
            except:
                pass
            history[domain] = {'timestamp': datetime.now().isoformat(), 'results': results}
            with open(self.history_file, 'w') as f:
                json.dump(history, f, indent=2)
        except Exception as e:
            print(f"{Colors.ERROR}Failed to save scan history: {e}{Colors.ENDC}")

    def compare(self, old_results: Dict, new_results: Dict) -> Dict:
        comparison = {'new_subdomains': [], 'removed_subdomains': [], 'ip_changes': []}
        old_subs = set(old_results.get('subdomains', {}).keys())
        new_subs = set(new_results.get('subdomains', {}).keys())
        comparison['new_subdomains'] = list(new_subs - old_subs)
        comparison['removed_subdomains'] = list(old_subs - new_subs)
        for subdomain in old_subs & new_subs:
            old_ips = set(old_results['subdomains'].get(subdomain, []))
            new_ips = set(new_results['subdomains'].get(subdomain, []))
            if old_ips != new_ips:
                comparison['ip_changes'].append({'subdomain': subdomain, 'old_ips': list(old_ips), 'new_ips': list(new_ips)})
        return comparison


class DNSResolver:
    """DNS resolver using dnspython"""

    def __init__(self, timeout: int = 5, dns_server: Optional[str] = None):
        self.timeout = timeout
        self.dns_server = dns_server
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
        if dns_server:
            self.resolver.nameservers = [dns_server]

    def get_nameservers(self, domain: str) -> List[str]:
        try:
            answers = self.resolver.resolve(domain, 'NS')
            nameservers = []
            for rdata in answers:
                ns = str(rdata.target).rstrip('.')
                if ns:
                    nameservers.append(ns.lower())
            return nameservers
        except:
            return []

    def get_mx_records(self, domain: str) -> List[Dict[str, any]]:
        try:
            answers = self.resolver.resolve(domain, 'MX')
            mx_records = []
            for rdata in answers:
                mx_records.append({'priority': rdata.preference, 'host': str(rdata.exchange).rstrip('.')})
            return sorted(mx_records, key=lambda x: x['priority'])
        except:
            return []

    def get_txt_records(self, domain: str) -> List[str]:
        try:
            answers = self.resolver.resolve(domain, 'TXT')
            txt_records = []
            for rdata in answers:
                txt_data = ' '.join([s.decode() if isinstance(s, bytes) else s for s in rdata.strings])
                txt_records.append(txt_data)
            return txt_records
        except:
            return []

    def get_soa_record(self, domain: str) -> Optional[Dict[str, any]]:
        try:
            answers = self.resolver.resolve(domain, 'SOA')
            for rdata in answers:
                return {'mname': str(rdata.mname).rstrip('.'), 'rname': str(rdata.rname).rstrip('.'),
                        'serial': rdata.serial, 'refresh': rdata.refresh, 'retry': rdata.retry,
                        'expire': rdata.expire, 'minimum': rdata.minimum}
        except:
            return None

    def get_spf_record(self, domain: str) -> Optional[str]:
        txt_records = self.get_txt_records(domain)
        for record in txt_records:
            if record.startswith('v=spf1'):
                return record
        return None

    def get_dmarc_record(self, domain: str) -> Optional[str]:
        try:
            dmarc_domain = f"_dmarc.{domain}"
            txt_records = self.get_txt_records(dmarc_domain)
            for record in txt_records:
                if record.startswith('v=DMARC1'):
                    return record
        except:
            pass
        return None

    def get_caa_records(self, domain: str) -> List[Dict[str, any]]:
        try:
            answers = self.resolver.resolve(domain, 'CAA')
            caa_records = []
            for rdata in answers:
                caa_records.append({'flags': rdata.flags,
                                   'tag': rdata.tag.decode() if isinstance(rdata.tag, bytes) else rdata.tag,
                                   'value': rdata.value.decode() if isinstance(rdata.value, bytes) else rdata.value})
            return caa_records
        except:
            return []

    def resolve(self, domain: str, record_type: str = 'A') -> List[str]:
        try:
            answers = self.resolver.resolve(domain, record_type)
            addresses = []
            for rdata in answers:
                if record_type == 'A':
                    addresses.append(str(rdata))
                elif record_type == 'AAAA':
                    addresses.append(str(rdata))
                elif record_type == 'CNAME':
                    addresses.append(str(rdata.target).rstrip('.'))
                else:
                    addresses.append(str(rdata))
            return addresses
        except:
            return []

    def get_comprehensive_dns_info(self, domain: str) -> Dict[str, any]:
        print(f"\n{Colors.HEADER}{'='*60}{Colors.ENDC}")
        print(f"{Colors.HEADER}Comprehensive DNS Information for {Colors.DOMAIN}{domain}{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*60}{Colors.ENDC}\n")

        dns_info = {'domain': domain, 'nameservers': [], 'a_records': [], 'aaaa_records': [],
                    'mx_records': [], 'txt_records': [], 'soa_record': None, 'spf_record': None,
                    'dmarc_record': None, 'caa_records': []}

        print(f"  {Colors.INFO}[*]{Colors.ENDC} Querying A records...")
        a_records = self.resolve(domain, 'A')
        if a_records:
            dns_info['a_records'] = a_records
            for ip in a_records:
                print(f"      {Colors.SUCCESS}✓{Colors.ENDC} A: {Colors.IP}{ip}{Colors.ENDC}")
        else:
            print(f"      {Colors.WARNING}⚠ {Colors.ENDC} No A records found")

        print(f"\n  {Colors.INFO}[*]{Colors.ENDC} Querying AAAA records (IPv6)...")
        aaaa_records = self.resolve(domain, 'AAAA')
        if aaaa_records:
            dns_info['aaaa_records'] = aaaa_records
            for ip in aaaa_records:
                print(f"      {Colors.SUCCESS}✓{Colors.ENDC} AAAA: {Colors.IP}{ip}{Colors.ENDC}")
        else:
            print(f"      {Colors.WARNING}⚠ {Colors.ENDC} No AAAA records found")

        print(f"\n  {Colors.INFO}[*]{Colors.ENDC} Querying NS records...")
        nameservers = self.get_nameservers(domain)
        if nameservers:
            dns_info['nameservers'] = nameservers
            for ns in nameservers:
                print(f"      {Colors.SUCCESS}✓{Colors.ENDC} NS: {Colors.INFO}{ns}{Colors.ENDC}")
        else:
            print(f"      {Colors.WARNING}⚠ {Colors.ENDC} No NS records found")

        print(f"\n  {Colors.INFO}[*]{Colors.ENDC} Querying MX records...")
        mx_records = self.get_mx_records(domain)
        if mx_records:
            dns_info['mx_records'] = mx_records
            for mx in mx_records:
                print(f"      {Colors.SUCCESS}✓{Colors.ENDC} MX: {Colors.HIGHLIGHT}{mx['priority']}{Colors.ENDC} {Colors.DOMAIN}{mx['host']}{Colors.ENDC}")
        else:
            print(f"      {Colors.WARNING}⚠ {Colors.ENDC} No MX records found")

        print(f"\n  {Colors.INFO}[*]{Colors.ENDC} Querying TXT records...")
        txt_records = self.get_txt_records(domain)
        if txt_records:
            dns_info['txt_records'] = txt_records
            for i, txt in enumerate(txt_records, 1):
                display_txt = txt if len(txt) <= 80 else txt[:77] + "..."
                print(f"      {Colors.SUCCESS}✓{Colors.ENDC} TXT[{i}]: {Colors.INFO}{display_txt}{Colors.ENDC}")
        else:
            print(f"      {Colors.WARNING}⚠ {Colors.ENDC} No TXT records found")

        print(f"\n  {Colors.INFO}[*]{Colors.ENDC} Querying SOA record...")
        soa_record = self.get_soa_record(domain)
        if soa_record:
            dns_info['soa_record'] = soa_record
            print(f"      {Colors.SUCCESS}✓{Colors.ENDC} SOA:")
            print(f"        Primary NS: {Colors.INFO}{soa_record['mname']}{Colors.ENDC}")
            print(f"        Admin Email: {Colors.INFO}{soa_record['rname']}{Colors.ENDC}")
            print(f"        Serial: {Colors.HIGHLIGHT}{soa_record['serial']}{Colors.ENDC}")
        else:
            print(f"      {Colors.WARNING}⚠ {Colors.ENDC} No SOA record found")

        print(f"\n  {Colors.INFO}[*]{Colors.ENDC} Checking SPF record...")
        spf_record = self.get_spf_record(domain)
        if spf_record:
            dns_info['spf_record'] = spf_record
            display_spf = spf_record if len(spf_record) <= 80 else spf_record[:77] + "..."
            print(f"      {Colors.SUCCESS}✓{Colors.ENDC} SPF: {Colors.INFO}{display_spf}{Colors.ENDC}")
        else:
            print(f"      {Colors.WARNING}⚠ {Colors.ENDC} No SPF record found")

        print(f"\n  {Colors.INFO}[*]{Colors.ENDC} Checking DMARC record...")
        dmarc_record = self.get_dmarc_record(domain)
        if dmarc_record:
            dns_info['dmarc_record'] = dmarc_record
            display_dmarc = dmarc_record if len(dmarc_record) <= 80 else dmarc_record[:77] + "..."
            print(f"      {Colors.SUCCESS}✓{Colors.ENDC} DMARC: {Colors.INFO}{display_dmarc}{Colors.ENDC}")
        else:
            print(f"      {Colors.WARNING}⚠ {Colors.ENDC} No DMARC record found")

        print(f"\n  {Colors.INFO}[*]{Colors.ENDC} Querying CAA records...")
        caa_records = self.get_caa_records(domain)
        if caa_records:
            dns_info['caa_records'] = caa_records
            for caa in caa_records:
                print(f"      {Colors.SUCCESS}✓{Colors.ENDC} CAA: {Colors.HIGHLIGHT}{caa['tag']}{Colors.ENDC} \"{Colors.INFO}{caa['value']}{Colors.ENDC}\"")
        else:
            print(f"      {Colors.WARNING}⚠ {Colors.ENDC} No CAA records found")

        print(f"\n{Colors.HEADER}{'='*60}{Colors.ENDC}\n")
        return dns_info


class OSINTEnumerator:
    """OSINT-based subdomain discovery with PROGRESS INDICATORS"""

    def __init__(self, domain: str, timeout: int = 10, verbose: bool = False,
                 proxy_manager: Optional[ProxyManager] = None, max_retries: int = 2):
        self.domain = domain
        self.timeout = timeout
        self.verbose = verbose
        self.proxy_manager = proxy_manager
        self.max_retries = max_retries
        self.session = self._create_session()

    def _create_session(self) -> requests.Session:
        session = requests.Session()
        if self.proxy_manager:
            user_agent = self.proxy_manager.get_random_user_agent()
        else:
            user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        session.headers.update({'User-Agent': user_agent})
        if self.proxy_manager:
            proxies = self.proxy_manager.get_proxy_config()
            if proxies:
                session.proxies.update(proxies)
        from requests.adapters import HTTPAdapter
        try:
            from urllib3.util.retry import Retry
            retry_strategy = Retry(total=self.max_retries, backoff_factor=2, status_forcelist=[429, 500, 502, 503, 504])
            adapter = HTTPAdapter(max_retries=retry_strategy)
            session.mount("http://", adapter)
            session.mount("https://", adapter)
        except:
            pass
        return session

    def _get_with_retry(self, url: str, **kwargs) -> Optional[requests.Response]:
        if 'timeout' not in kwargs:
            kwargs['timeout'] = self.timeout
        for attempt in range(self.max_retries):
            try:
                response = self.session.get(url, **kwargs)
                if response.status_code == 200:
                    return response
                elif response.status_code == 429:
                    time.sleep(3 * (attempt + 1))
                    continue
            except requests.exceptions.Timeout:
                if attempt < self.max_retries - 1:
                    time.sleep(2)
                    continue
            except:
                if attempt < self.max_retries - 1:
                    time.sleep(1)
                    continue
        return None

    def search_crtsh(self) -> Set[str]:
        """Search Certificate Transparency logs via crt.sh WITH SPINNER"""
        print(f"  {Colors.INFO}[*]{Colors.ENDC} Searching crt.sh (SSL Certificates)...")
        subdomains = set()

        spinner = Spinner("Querying certificate transparency logs...", style='dots')
        spinner.start()

        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            response = self._get_with_retry(url, timeout=60)

            if response and response.status_code == 200:
                try:
                    spinner.update_message("Parsing certificate data...")
                    data = response.json()
                    for entry in data:
                        name = entry.get('name_value', '')
                        for subdomain in name.split('\n'):
                            subdomain = subdomain.strip().replace('*.', '')
                            if subdomain.endswith(self.domain) and subdomain:
                                subdomains.add(subdomain)

                    spinner.stop()  # Stop spinner first
                    print(f"      {Colors.SUCCESS}✓{Colors.ENDC} Found {Colors.HIGHLIGHT}{len(subdomains)}{Colors.ENDC} subdomains")
                except:
                    spinner.stop()
                    print(f"      {Colors.ERROR}✗{Colors.ENDC} Invalid JSON response")
            else:
                spinner.stop()
                print(f"      {Colors.ERROR}✗{Colors.ENDC} crt.sh unavailable")
        except:
            spinner.stop()
            print(f"      {Colors.ERROR}✗{Colors.ENDC} crt.sh timed out")

        return subdomains

    def search_hackertarget(self) -> Set[str]:
        """Search HackerTarget API WITH SPINNER"""
        print(f"  {Colors.INFO}[*]{Colors.ENDC} Searching HackerTarget API...")
        subdomains = set()

        spinner = Spinner("Querying HackerTarget database...", style='dots')
        spinner.start()

        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
            response = self.session.get(url, timeout=self.timeout)

            if response.status_code == 200:
                spinner.update_message("Processing results...")
                lines = response.text.split('\n')
                for line in lines:
                    if ',' in line:
                        subdomain = line.split(',')[0].strip()
                        if subdomain and subdomain.endswith(self.domain):
                            subdomains.add(subdomain)

                spinner.stop()  # Stop spinner first
                print(f"      {Colors.SUCCESS}✓{Colors.ENDC} Found {Colors.HIGHLIGHT}{len(subdomains)}{Colors.ENDC} subdomains")
        except:
            spinner.stop()
            print(f"      {Colors.ERROR}✗{Colors.ENDC} HackerTarget unavailable")

        return subdomains

    def enumerate_all(self) -> Set[str]:
        """Run all OSINT sources"""
        print(f"\n{Colors.HEADER}{'='*60}{Colors.ENDC}")
        print(f"{Colors.HEADER}OSINT Subdomain Discovery{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*60}{Colors.ENDC}\n")

        all_subdomains = set()

        sources = [self.search_crtsh, self.search_hackertarget]

        for source in sources:
            try:
                results = source()
                all_subdomains.update(results)
                time.sleep(0.5)
            except:
                pass

        print(f"\n  {Colors.SUCCESS}✓{Colors.ENDC} Total unique subdomains from OSINT: {Colors.HIGHLIGHT}{len(all_subdomains)}{Colors.ENDC}\n")
        return all_subdomains


class SubdomainEnumerator:
    """Main subdomain enumerator WITH PROGRESS INDICATORS"""

    def __init__(self, domain: str, timeout: int = 5, max_workers: int = 50,
                 dns_server: Optional[str] = None, verbose: bool = False,
                 proxy_manager: Optional[ProxyManager] = None):
        self.domain = domain
        self.timeout = timeout
        self.max_workers = max_workers
        self.verbose = verbose
        self.proxy_manager = proxy_manager
        self.dns_resolver = DNSResolver(timeout=timeout, dns_server=dns_server)
        self.osint_enum = OSINTEnumerator(domain, timeout=30, verbose=verbose, proxy_manager=proxy_manager)

    def resolve_subdomain(self, subdomain: str) -> Tuple[str, List[str], Optional[str]]:
        ipv4_addresses = self.dns_resolver.resolve(subdomain, 'A')
        cname = None
        cnames = self.dns_resolver.resolve(subdomain, 'CNAME')
        if cnames:
            cname = cnames[0]
        return subdomain, ipv4_addresses, cname

    def verify_subdomains(self, subdomains: Set[str], show_progress: bool = True) -> Tuple[Dict[str, List[str]], Dict[str, str]]:
        """Verify discovered subdomains using DNS WITH PROGRESS COUNTER"""
        print(f"\n{Colors.HEADER}{'='*60}{Colors.ENDC}")
        print(f"{Colors.HEADER}Verifying {len(subdomains)} subdomains with DNS{Colors.ENDC}")
        print(f"{Colors.INFO}Timeout: {self.timeout}s | Workers: {self.max_workers}{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*60}{Colors.ENDC}\n")

        results = {}
        cname_map = {}
        total = len(subdomains)
        completed = 0

        spinner = Spinner(f"Resolving subdomains... (0/{total})", style='dots')
        if not show_progress:
            spinner.start()

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_subdomain = {executor.submit(self.resolve_subdomain, subdomain): subdomain for subdomain in subdomains}

            for future in concurrent.futures.as_completed(future_to_subdomain):
                subdomain = future_to_subdomain[future]
                completed += 1

                try:
                    full_domain, ipv4_list, cname = future.result()

                    if ipv4_list:
                        results[full_domain] = ipv4_list
                        if cname:
                            cname_map[full_domain] = cname

                        if show_progress:
                            colored_ips = [f"{Colors.IP}{ip}{Colors.ENDC}" for ip in ipv4_list]
                            cname_info = f" {Colors.INFO}[CNAME: {cname}]{Colors.ENDC}" if cname else ""
                            print(f"[{completed}/{total}] {Colors.SUCCESS}✓{Colors.ENDC} {Colors.DOMAIN}{full_domain}{Colors.ENDC} -> {', '.join(colored_ips)}{cname_info}")
                        else:
                            spinner.update_message(f"Resolving subdomains... ({completed}/{total}) - Found: {len(results)}")
                except:
                    pass

                if show_progress and completed % 50 == 0:
                    print(f"\n{Colors.INFO}Progress: {completed}/{total} verified, {len(results)} alive{Colors.ENDC}\n")

        if not show_progress:
            spinner.stop(f"{Colors.SUCCESS}✓{Colors.ENDC} Completed: {completed}/{total} verified, {len(results)} alive")

        return results, cname_map

    def enumerate_deep(self, use_osint: bool = True, use_bruteforce: bool = True,
                       wordlist: Optional[List[str]] = None) -> Tuple[Dict[str, List[str]], Dict[str, str]]:
        """Deep enumeration combining OSINT and brute force"""
        all_subdomains = set()

        if use_osint:
            osint_subs = self.osint_enum.enumerate_all()
            all_subdomains.update(osint_subs)

        if use_bruteforce and wordlist:
            print(f"\n{Colors.HEADER}{'='*60}{Colors.ENDC}")
            print(f"{Colors.HEADER}Brute Force Discovery - Testing {len(wordlist)} names{Colors.ENDC}")
            print(f"{Colors.HEADER}{'='*60}{Colors.ENDC}\n")
            bruteforce_subs = [f"{word}.{self.domain}" for word in wordlist]
            all_subdomains.update(bruteforce_subs)

        if all_subdomains:
            verified, cname_map = self.verify_subdomains(all_subdomains, show_progress=True)
            return verified, cname_map

        return {}, {}


class RedTeamEnumerator:
    """Enhanced enumerator with all red team features WITH PROGRESS INDICATORS"""

    def __init__(self, domain: str, config: Dict):
        self.domain = domain
        self.config = config
        self.takeover_checker = TakeoverChecker()
        self.port_scanner = PortScanner()
        self.http_prober = HTTPProber()
        self.waf_detector = WAFDetector()
        self.ssl_analyzer = SSLAnalyzer()
        self.cloud_finder = CloudAssetFinder()
        self.whois_lookup = WHOISLookup()
        self.ip_geo = IPGeolocation()
        self.api_discovery = APIEndpointDiscovery()
        self.github_searcher = GitHubDorkSearcher(config.get('github_token') or GITHUB_TOKEN or None)
        self.shodan_searcher = ShodanSearcher(config.get('shodan_key') or SHODAN_API_KEY or None)
        self.censys_searcher = CensysSearcher(
            config.get('censys_id') or CENSYS_API_ID or None,
            config.get('censys_secret') or CENSYS_API_SECRET or None
        )
        self.change_tracker = ChangeTracker()

    def run_red_team_scan(self, subdomains: Dict[str, List[str]], cname_map: Dict[str, str]) -> Dict:
        """Run comprehensive red team scan WITH LIVE PROGRESS INDICATORS"""
        print(f"\n{Colors.HEADER}{'='*60}{Colors.ENDC}")
        print(f"{Colors.HEADER}Red Team Reconnaissance - Scanning {len(subdomains)} targets{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*60}{Colors.ENDC}\n")

        results = {
            'http_probes': {},
            'takeovers': [],
            'open_ports': {},
            'waf_detected': {},
            'ssl_certs': {},
            'cloud_assets': {},
            'api_endpoints': {},
            'github_leaks': [],
            'shodan_results': [],
            'censys_results': [],
            'ip_geolocation': {},
            'whois_info': {}
        }

        subdomain_list = list(subdomains.keys())

        # 1. HTTP Probing - WITH LIVE COUNTER
        if self.config.get('http_probe', True):
            print(f"{Colors.INFO}[*] HTTP/HTTPS Probing {len(subdomain_list)} subdomains...{Colors.ENDC}")
            probed = 0
            total_subs = len(subdomain_list)

            for subdomain in subdomain_list:
                probed += 1
                sys.stdout.write(f'\r  {Colors.INFO}[{probed}/{total_subs}]{Colors.ENDC} Probing {subdomain[:40]}...')
                sys.stdout.flush()

                probe_result = self.http_prober.probe(subdomain)
                results['http_probes'][subdomain] = probe_result
                if probe_result.get('https') or probe_result.get('http'):
                    status = probe_result.get('status_code', 'N/A')
                    title = probe_result.get('title') or 'No title'
                    title = title[:50] if title else 'No title'
                    tech = ', '.join(probe_result.get('technologies', [])[:3])
                    tech_info = f" [{tech}]" if tech else ""
                    sys.stdout.write('\r' + ' ' * 100 + '\r')
                    print(f"  {Colors.SUCCESS}✓{Colors.ENDC} {subdomain} [{status}] - {title}{tech_info}")

            sys.stdout.write('\r' + ' ' * 100 + '\r')
            print(f"  {Colors.SUCCESS}✓{Colors.ENDC} Completed HTTP probing\n")

        # 2. Subdomain Takeover Detection - WITH SPINNER
        if self.config.get('takeover_check', True):
            print(f"{Colors.INFO}[*] Checking Subdomain Takeovers...{Colors.ENDC}")
            takeover_count = 0
            checked = 0
            total_cnames = len(cname_map)

            spinner = Spinner(f"Checking takeover vulnerabilities... (0/{total_cnames})", style='dots')
            spinner.start()

            for subdomain, cname in cname_map.items():
                checked += 1
                spinner.update_message(f"Checking takeover vulnerabilities... ({checked}/{total_cnames})")

                takeover_result = self.takeover_checker.check_takeover(subdomain, cname)
                if takeover_result['vulnerable']:
                    results['takeovers'].append(takeover_result)
                    takeover_count += 1
                    spinner.stop()
                    print(f"  {Colors.ERROR}⚠  VULNERABLE: {subdomain} -> {cname} ({takeover_result['service']}){Colors.ENDC}")
                    spinner.start()

            if takeover_count == 0:
                spinner.stop(f"  {Colors.SUCCESS}✓ No takeover vulnerabilities found{Colors.ENDC}\n")
            else:
                spinner.stop()
                print()

        # 3. SSL Certificate Analysis - WITH LIVE COUNTER
        if self.config.get('ssl_analysis', True):
            print(f"{Colors.INFO}[*] Analyzing SSL Certificates...{Colors.ENDC}")
            extra_subdomains = set()
            analyzed = 0
            total_ssl = len(subdomain_list)

            for subdomain in subdomain_list:
                analyzed += 1
                sys.stdout.write(f'\r  {Colors.INFO}[{analyzed}/{total_ssl}]{Colors.ENDC} Analyzing {subdomain[:40]}...')
                sys.stdout.flush()

                cert_info = self.ssl_analyzer.analyze_certificate(subdomain)
                results['ssl_certs'][subdomain] = cert_info

                if cert_info['has_ssl']:
                    for san_domain in cert_info['san_domains']:
                        if san_domain.endswith(self.domain) and san_domain not in subdomains:
                            extra_subdomains.add(san_domain)

                    issuer = cert_info['issuer']
                    expired = '(EXPIRED)' if cert_info['expired'] else ''
                    sys.stdout.write('\r' + ' ' * 100 + '\r')
                    print(f"  {Colors.SUCCESS}✓{Colors.ENDC} {subdomain} - {issuer} {expired}")

            sys.stdout.write('\r' + ' ' * 100 + '\r')

            if extra_subdomains:
                print(f"  {Colors.HIGHLIGHT}[+] Found {len(extra_subdomains)} additional subdomains from SSL SANs{Colors.ENDC}")
                results['ssl_discovered_subdomains'] = list(extra_subdomains)
            print()

        # 4. Port Scanning - WITH LIVE COUNTER
        if self.config.get('port_scan', True):
            print(f"{Colors.INFO}[*] Scanning Public Ports ({len(self.port_scanner.PUBLIC_PORTS)} ports) on all IPs...{Colors.ENDC}")
            scanned = 0
            total_ips = sum(len(ips) for ips in subdomains.values())

            for subdomain, ips in subdomains.items():
                for ip in ips:
                    scanned += 1
                    sys.stdout.write(f'\r  {Colors.INFO}[{scanned}/{total_ips}]{Colors.ENDC} Scanning {ip}...')
                    sys.stdout.flush()

                    open_ports = self.port_scanner.scan_ports(ip, timeout=0.3)
                    if open_ports:
                        results['open_ports'][f"{subdomain}_{ip}"] = open_ports
                        ports_info = []
                        for port, info in open_ports.items():
                            banner_info = f" [{info['banner'][:50]}]" if info.get('banner') else ""
                            ports_info.append(f"{port}/{info['service']}{banner_info}")
                        ports_str = ', '.join(ports_info[:5])
                        if len(open_ports) > 5:
                            ports_str += f" ... +{len(open_ports)-5} more"
                        sys.stdout.write('\r' + ' ' * 100 + '\r')
                        print(f"  {Colors.SUCCESS}✓{Colors.ENDC} {subdomain} ({ip}): {ports_str}")

            sys.stdout.write('\r' + ' ' * 100 + '\r')
            print(f"  {Colors.SUCCESS}✓{Colors.ENDC} Completed port scanning\n")

        # 5. WAF Detection - WITH SPINNER
        if self.config.get('waf_detect', True):
            print(f"{Colors.INFO}[*] Detecting WAF/CDN...{Colors.ENDC}")
            detected_count = 0
            checked_waf = 0
            total_waf = len(subdomain_list)

            spinner = Spinner(f"Checking for WAF/CDN... (0/{total_waf})", style='dots')
            spinner.start()

            for subdomain in subdomain_list:
                checked_waf += 1
                spinner.update_message(f"Checking for WAF/CDN... ({checked_waf}/{total_waf})")

                waf_result = self.waf_detector.detect(subdomain)
                if waf_result['waf_detected']:
                    results['waf_detected'][subdomain] = waf_result
                    detected_count += 1
                    spinner.stop()
                    print(f"  {Colors.WARNING}[!]{Colors.ENDC} {subdomain} - {waf_result['waf_name']}")
                    spinner.start()

            if detected_count == 0:
                spinner.stop(f"  {Colors.SUCCESS}✓{Colors.ENDC} No WAF/CDN detected\n")
            else:
                spinner.stop()
                print()

        # 6. Cloud Asset Discovery - WITH SPINNERS
        if self.config.get('cloud_assets', True):
            print(f"{Colors.INFO}[*] Searching for Cloud Assets...{Colors.ENDC}")

            spinner = Spinner("Searching for S3 buckets...", style='dots')
            spinner.start()

            s3_buckets = self.cloud_finder.find_s3_buckets(self.domain)
            if s3_buckets:
                results['cloud_assets']['s3_buckets'] = s3_buckets
                spinner.stop()
                for bucket in s3_buckets:
                    status = 'PUBLIC' if bucket['public'] else 'PRIVATE'
                    listable = '(LISTABLE!)' if bucket.get('listable') else ''
                    print(f"  {Colors.HIGHLIGHT}[S3]{Colors.ENDC} {bucket['bucket_name']} - {status} {listable}")
            else:
                spinner.stop()

            spinner = Spinner("Searching for Azure blobs...", style='dots')
            spinner.start()

            azure_blobs = self.cloud_finder.find_azure_blobs(self.domain)
            if azure_blobs:
                results['cloud_assets']['azure_blobs'] = azure_blobs
                spinner.stop()
                for blob in azure_blobs:
                    print(f"  {Colors.HIGHLIGHT}[Azure]{Colors.ENDC} {blob['blob_name']}")
            else:
                spinner.stop()
            print()

        # 7. WHOIS Lookup - WITH SPINNER
        if self.config.get('whois', True):
            print(f"{Colors.INFO}[*] WHOIS Lookup...{Colors.ENDC}")

            spinner = Spinner("Querying WHOIS database...", style='dots')
            spinner.start()

            whois_info = self.whois_lookup.lookup(self.domain)
            results['whois_info'] = whois_info

            spinner.stop()
            if not whois_info.get('error'):
                print(f"  Registrar: {whois_info.get('registrar', 'N/A')}")
                print(f"  Created: {whois_info.get('creation_date', 'N/A')}")
                print(f"  Expires: {whois_info.get('expiration_date', 'N/A')}")
            else:
                print(f"  {Colors.WARNING}⚠ {whois_info.get('error')}{Colors.ENDC}")
            print()

        # 8. IP Geolocation - WITH LIVE COUNTER
        if self.config.get('ip_geo', True):
            print(f"{Colors.INFO}[*] IP Geolocation...{Colors.ENDC}")
            unique_ips = set()
            for ips in subdomains.values():
                unique_ips.update(ips)

            geolocated = 0
            total_geo = len(unique_ips)

            for ip in unique_ips:
                geolocated += 1
                sys.stdout.write(f'\r  {Colors.INFO}[{geolocated}/{total_geo}]{Colors.ENDC} Geolocating {ip}...')
                sys.stdout.flush()

                geo_info = self.ip_geo.geolocate(ip)
                results['ip_geolocation'][ip] = geo_info
                country = geo_info.get('country', 'Unknown')
                org = geo_info.get('org', 'Unknown')
                sys.stdout.write('\r' + ' ' * 100 + '\r')
                print(f"  {Colors.IP}{ip}{Colors.ENDC} - {country} ({org})")

            sys.stdout.write('\r' + ' ' * 100 + '\r')
            print()

        # 9. API Endpoint Discovery - WITH SPINNER
        if self.config.get('api_discovery', True):
            print(f"{Colors.INFO}[*] Discovering API Endpoints...{Colors.ENDC}")
            discovered_count = 0
            checked_api = 0
            total_api = len(subdomain_list)

            spinner = Spinner(f"Discovering API endpoints... (0/{total_api})", style='dots')
            spinner.start()

            for subdomain in subdomain_list:
                checked_api += 1
                spinner.update_message(f"Discovering API endpoints... ({checked_api}/{total_api})")

                endpoints = self.api_discovery.discover(subdomain)
                if endpoints:
                    results['api_endpoints'][subdomain] = endpoints
                    discovered_count += 1
                    spinner.stop()
                    for endpoint in endpoints:
                        print(f"  {Colors.SUCCESS}✓{Colors.ENDC} {endpoint['url']} [{endpoint['status']}]")
                    spinner.start()

            if discovered_count == 0:
                spinner.stop(f"  {Colors.INFO}No API endpoints discovered{Colors.ENDC}\n")
            else:
                spinner.stop()
                print()

        # 10. GitHub Dork Search - WITH SPINNER
        if self.config.get('github_search', False):
            print(f"{Colors.INFO}[*] Searching GitHub for leaks...{Colors.ENDC}")

            spinner = Spinner("Querying GitHub API...", style='dots')
            spinner.start()

            github_results = self.github_searcher.search(self.domain)
            if github_results:
                results['github_leaks'] = github_results
                spinner.stop()
                for result in github_results[:5]:
                    print(f"  {Colors.WARNING}[!]{Colors.ENDC} {result['repository']} - {result['file']}")
            else:
                spinner.stop(f"  {Colors.INFO}No GitHub leaks found{Colors.ENDC}")
            print()

        # 11. Shodan Search - WITH SPINNER
        if self.config.get('shodan', False):
            print(f"{Colors.INFO}[*] Querying Shodan...{Colors.ENDC}")

            spinner = Spinner("Searching Shodan database...", style='dots')
            spinner.start()

            shodan_results = self.shodan_searcher.search(self.domain)
            if shodan_results:
                results['shodan_results'] = shodan_results
                spinner.stop()
                for result in shodan_results[:5]:
                    print(f"  {Colors.HIGHLIGHT}[Shodan]{Colors.ENDC} {result['ip']}:{result.get('port')} - {result.get('org', 'N/A')}")
            else:
                spinner.stop(f"  {Colors.INFO}No Shodan results found{Colors.ENDC}")
            print()

        # 12. Censys Search - WITH SPINNER
        if self.config.get('censys', False):
            print(f"{Colors.INFO}[*] Querying Censys...{Colors.ENDC}")

            spinner = Spinner("Searching Censys database...", style='dots')
            spinner.start()

            censys_results = self.censys_searcher.search(self.domain)
            if censys_results:
                results['censys_results'] = censys_results
                spinner.stop(f"  {Colors.SUCCESS}✓{Colors.ENDC} Found {len(censys_results)} certificates")
            else:
                spinner.stop(f"  {Colors.INFO}No Censys results found{Colors.ENDC}")
            print()

        # 13. Change Tracking
        if self.config.get('track_changes', True):
            print(f"{Colors.INFO}[*] Tracking Changes...{Colors.ENDC}")
            previous_scan = self.change_tracker.load_previous_scan(self.domain)
            if previous_scan:
                comparison = self.change_tracker.compare(
                    previous_scan.get('results', {}),
                    {'subdomains': subdomains}
                )
                results['changes'] = comparison

                if comparison['new_subdomains']:
                    print(f"  {Colors.SUCCESS}[+] New subdomains: {len(comparison['new_subdomains'])}{Colors.ENDC}")
                    for sub in comparison['new_subdomains'][:5]:
                        print(f"    - {sub}")

                if comparison['removed_subdomains']:
                    print(f"  {Colors.WARNING}[-] Removed subdomains: {len(comparison['removed_subdomains'])}{Colors.ENDC}")

                if comparison['ip_changes']:
                    print(f"  {Colors.WARNING}[~] IP changes: {len(comparison['ip_changes'])}{Colors.ENDC}")
            else:
                print(f"  {Colors.INFO}[i] No previous scan found - establishing baseline{Colors.ENDC}")

            self.change_tracker.save_scan(self.domain, {'subdomains': subdomains})
            print()

        print(f"{Colors.HEADER}{'='*60}{Colors.ENDC}")
        print(f"{Colors.SUCCESS}✓ Red Team Scan Complete!{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*60}{Colors.ENDC}\n")

        return results

    def generate_red_team_report(self, results: Dict, subdomain_count: int) -> str:
        """Generate comprehensive red team report"""
        report = f"\n{Colors.HEADER}{'='*70}\n"
        report += "RED TEAM RECONNAISSANCE REPORT\n"
        report += f"{'='*70}{Colors.ENDC}\n"
        report += f"Domain: {Colors.DOMAIN}{self.domain}{Colors.ENDC}\n"
        report += f"Timestamp: {datetime.now().isoformat()}\n"
        report += f"Total Subdomains: {subdomain_count}\n\n"

        report += f"{Colors.ERROR}CRITICAL FINDINGS:{Colors.ENDC}\n"
        critical_count = 0

        if results.get('takeovers'):
            critical_count += len(results['takeovers'])
            report += f"  {Colors.ERROR}⚠  {len(results['takeovers'])} Subdomain Takeover Vulnerabilities{Colors.ENDC}\n"
            for takeover in results['takeovers'][:3]:
                report += f"    - {takeover['subdomain']} -> {takeover.get('cname')} ({takeover.get('service')})\n"

        cloud_assets = results.get('cloud_assets', {})
        public_buckets = [b for b in cloud_assets.get('s3_buckets', []) if b.get('public')]
        if public_buckets:
            critical_count += len(public_buckets)
            report += f"  {Colors.ERROR}⚠  {len(public_buckets)} Public S3 Buckets{Colors.ENDC}\n"
            for bucket in public_buckets[:3]:
                listable = '(LISTABLE!)' if bucket.get('listable') else ''
                report += f"    - {bucket['bucket_name']} {listable}\n"

        if critical_count == 0:
            report += f"  {Colors.SUCCESS}✓ No critical vulnerabilities detected{Colors.ENDC}\n"

        report += "\n"

        http_probes = results.get('http_probes', {})
        https_count = sum(1 for p in http_probes.values() if p.get('https'))
        http_count = sum(1 for p in http_probes.values() if p.get('http'))

        report += f"{Colors.HEADER}HTTP/HTTPS SERVICES:{Colors.ENDC}\n"
        report += f"  HTTPS: {https_count}\n"
        report += f"  HTTP: {http_count}\n\n"

        open_ports = results.get('open_ports', {})
        if open_ports:
            report += f"{Colors.HEADER}OPEN PORTS:{Colors.ENDC}\n"
            port_summary = defaultdict(int)
            for host_ports in open_ports.values():
                for port, info in host_ports.items():
                    service = info.get('service', 'Unknown') if isinstance(info, dict) else info
                    port_summary[f"{port}/{service}"] += 1

            for port_service, count in sorted(port_summary.items(), key=lambda x: x[1], reverse=True)[:15]:
                report += f"  {port_service}: {count} hosts\n"
            report += "\n"

        waf_detected = results.get('waf_detected', {})
        if waf_detected:
            report += f"{Colors.HEADER}WAF/CDN DETECTED:{Colors.ENDC}\n"
            waf_counts = defaultdict(int)
            for waf_info in waf_detected.values():
                waf_counts[waf_info.get('waf_name')] += 1
            for waf_name, count in waf_counts.items():
                report += f"  {waf_name}: {count} hosts\n"
            report += "\n"

        api_endpoints = results.get('api_endpoints', {})
        if api_endpoints:
            total_apis = sum(len(eps) for eps in api_endpoints.values())
            report += f"{Colors.HEADER}API ENDPOINTS DISCOVERED:{Colors.ENDC}\n"
            report += f"  Total: {total_apis} endpoints on {len(api_endpoints)} hosts\n\n"

        ip_geo = results.get('ip_geolocation', {})
        if ip_geo:
            countries = defaultdict(int)
            for geo in ip_geo.values():
                country = geo.get('country', 'Unknown')
                countries[country] += 1

            report += f"{Colors.HEADER}IP GEOLOCATION:{Colors.ENDC}\n"
            for country, count in sorted(countries.items(), key=lambda x: x[1], reverse=True)[:5]:
                report += f"  {country}: {count} IPs\n"
            report += "\n"

        changes = results.get('changes')
        if changes:
            report += f"{Colors.HEADER}CHANGES SINCE LAST SCAN:{Colors.ENDC}\n"
            if changes.get('new_subdomains'):
                report += f"  {Colors.SUCCESS}[+] New: {len(changes['new_subdomains'])}{Colors.ENDC}\n"
            if changes.get('removed_subdomains'):
                report += f"  {Colors.WARNING}[-] Removed: {len(changes['removed_subdomains'])}{Colors.ENDC}\n"
            if changes.get('ip_changes'):
                report += f"  {Colors.WARNING}[~] IP Changes: {len(changes['ip_changes'])}{Colors.ENDC}\n"
            report += "\n"

        report += f"{Colors.HEADER}{'='*70}{Colors.ENDC}\n"

        return report

    def export_to_nuclei(self, subdomains: List[str], filename: str = 'nuclei_targets.txt'):
        """Export targets for Nuclei scanner"""
        with open(filename, 'w') as f:
            for subdomain in subdomains:
                f.write(f"https://{subdomain}\n")
                f.write(f"http://{subdomain}\n")
        print(f"{Colors.SUCCESS}✓{Colors.ENDC} Nuclei targets exported to {filename}")

    def export_to_nmap(self, subdomains: Dict[str, List[str]], filename: str = 'nmap_targets.txt'):
        """Export IP targets for Nmap"""
        unique_ips = set()
        for ips in subdomains.values():
            unique_ips.update(ips)

        with open(filename, 'w') as f:
            for ip in unique_ips:
                f.write(f"{ip}\n")
        print(f"{Colors.SUCCESS}✓{Colors.ENDC} Nmap targets exported to {filename}")


# ============================================================================
# MAIN EXECUTION
# ============================================================================

if __name__ == "__main__":
    print(f"{Colors.HEADER}{'='*70}{Colors.ENDC}")
    print(f"{Colors.HEADER}Advanced Red Team Subdomain Enumerator v4.1{Colors.ENDC}")
    print(f"{Colors.HEADER}WITH LIVE PROGRESS INDICATORS - No More Stuck Screens!{Colors.ENDC}")
    print(f"{Colors.HEADER}{'='*70}{Colors.ENDC}\n")

    domain = input(f"{Colors.OKCYAN}Enter target domain: {Colors.ENDC}").strip()

    if not domain:
        print(f"{Colors.FAIL}✖ Error: Domain cannot be empty!{Colors.ENDC}")
        sys.exit(1)

    domain = domain.replace('https://', '').replace('http://', '').replace('www.', '')
    if '/' in domain:
        domain = domain.split('/')[0]

    print(f"\n{Colors.SUCCESS}✓ Target: {Colors.DOMAIN}{domain}{Colors.ENDC}\n")

    dns_info_choice = input(f"{Colors.OKCYAN}Show comprehensive DNS information? (y/n, default=y): {Colors.ENDC}").strip().lower()

    dns_info = None
    if dns_info_choice != 'n':
        temp_resolver = DNSResolver(timeout=5)
        dns_info = temp_resolver.get_comprehensive_dns_info(domain)

    print(f"{Colors.HEADER}Red Team Scan Options:{Colors.ENDC}")
    print("1. Quick Scan (OSINT + DNS + HTTP Probing)")
    print("2. Standard Scan (+ Port Scan + WAF Detection)")
    print("3. Deep Scan (+ SSL Analysis + Cloud Assets + API Discovery)")
    print("4. Full Red Team Scan (Everything + Shodan/Censys if keys provided)")

    scan_level = input(f"\n{Colors.OKCYAN}Select scan level (1-4, default=2): {Colors.ENDC}").strip() or "2"

    config = {
        'http_probe': True,
        'takeover_check': True,
        'ssl_analysis': False,
        'port_scan': False,
        'waf_detect': False,
        'cloud_assets': False,
        'whois': True,
        'ip_geo': True,
        'api_discovery': False,
        'github_search': False,
        'shodan': False,
        'censys': False,
        'track_changes': True
    }

    if scan_level in ['2', '3', '4']:
        config.update({'port_scan': True, 'waf_detect': True})

    if scan_level in ['3', '4']:
        config.update({'ssl_analysis': True, 'cloud_assets': True, 'api_discovery': True})

    if scan_level == '4':
        config.update({
            'github_search': True if GITHUB_TOKEN else False,
            'shodan': True if SHODAN_API_KEY else False,
            'censys': True if CENSYS_API_ID else False
        })

        print(f"\n{Colors.INFO}API Keys Status:{Colors.ENDC}")
        print(f"  GitHub: {'✓ Configured' if GITHUB_TOKEN else '✗ Not configured'}")
        print(f"  Shodan: {'✓ Configured' if SHODAN_API_KEY else '✗ Not configured'}")
        print(f"  Censys: {'✓ Configured' if CENSYS_API_ID and CENSYS_API_SECRET else '✗ Not configured'}")

    print(f"\n{Colors.HEADER}Enumeration Method:{Colors.ENDC}")
    print("1. OSINT only (fast, passive)")
    print("2. OSINT + Brute force (comprehensive)")
    print("3. Brute force only (wordlist)")

    method = input(f"\n{Colors.OKCYAN}Choose method (1-3, default=2): {Colors.ENDC}").strip() or "2"

    common_wordlist = [
        "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
        "admin", "api", "blog", "dev", "stage", "staging", "test", "portal", "cdn",
        "shop", "store", "app", "mobile", "m", "vpn", "support", "help", "docs",
        "status", "git", "secure", "my", "remote", "server", "host", "beta", "cloud",
        "ftp2", "ns3", "mx", "email", "direct", "cpanel", "forum", "search", "dns",
        "intranet", "web", "bbs", "demo", "news", "mysql", "backup", "old", "new",
        "assets", "static", "media", "images", "img", "files", "uploads", "downloads",
        "api-gateway", "gateway", "proxy", "lb", "balancer", "edge", "node",
        "client", "customer", "partner", "vendor", "internal", "external",
        "dashboard", "console", "manage", "control", "monitor", "analytics",
        "ws", "websocket", "socket", "realtime", "live", "stream", "broadcast"
    ]

    if method in ["2", "3"]:
        print(f"\n{Colors.HEADER}Wordlist Options:{Colors.ENDC}")
        print(f"  1. Use built-in wordlist ({len(common_wordlist)} subdomains)")
        print("  2. Load from local file")
        print("  3. Load from URL")

        wordlist_choice = input(f"\n{Colors.OKCYAN}Choose wordlist source (1-3, default=1): {Colors.ENDC}").strip() or "1"

        if wordlist_choice == "2":
            wordlist_path = input(f"{Colors.OKCYAN}Enter path to wordlist file: {Colors.ENDC}").strip()
            try:
                with open(wordlist_path, 'r') as f:
                    common_wordlist = [line.strip() for line in f if line.strip()]
                print(f"{Colors.SUCCESS}✓ Loaded {len(common_wordlist)} words from {wordlist_path}{Colors.ENDC}")
            except:
                print(f"{Colors.ERROR}✗ Error loading file. Using built-in wordlist.{Colors.ENDC}")

        elif wordlist_choice == "3":
            print(f"{Colors.INFO}Popular subdomain wordlists (copy-paste):{Colors.ENDC}")
            print(f"{Colors.INFO}https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt{Colors.ENDC}")
            print(f"{Colors.INFO}https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-20000.txt{Colors.ENDC}")
            print(f"{Colors.INFO}https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/fierce-hostlist.txt{Colors.ENDC}")

            wordlist_url = input(f"{Colors.OKCYAN}Enter URL to wordlist: {Colors.ENDC}").strip()
            try:
                print(f"{Colors.INFO}[*] Downloading wordlist...{Colors.ENDC}")
                response = requests.get(wordlist_url, timeout=30)
                if response.status_code == 200:
                    common_wordlist = [line.strip() for line in response.text.split('\n') if line.strip()]
                    print(f"{Colors.SUCCESS}✓ Loaded {len(common_wordlist)} words from URL{Colors.ENDC}")
                else:
                    print(f"{Colors.ERROR}✗ Failed to download. Using built-in wordlist.{Colors.ENDC}")
            except:
                print(f"{Colors.ERROR}✗ Error downloading. Using built-in wordlist.{Colors.ENDC}")

    print(f"\n{Colors.HEADER}Anonymity Options:{Colors.ENDC}")
    print("1. No proxy (direct connection)")
    print("2. Use TOR network")
    print("3. Use custom proxy")

    proxy_choice = input(f"\n{Colors.OKCYAN}Choose option (1-3, default=1): {Colors.ENDC}").strip() or "1"

    proxy_manager = None

    if proxy_choice == "2":
        print(f"\n{Colors.INFO}[*] Checking TOR connection...{Colors.ENDC}")
        proxy_manager = ProxyManager(use_tor=True)

        if proxy_manager.tor_available:
            print(f"{Colors.SUCCESS}✓ TOR is running on 127.0.0.1:9050{Colors.ENDC}")

            print(f"{Colors.INFO}[*] Testing TOR connection...{Colors.ENDC}")
            if proxy_manager.test_tor_connection():
                print(f"{Colors.SUCCESS}✓ Successfully connected through TOR network!{Colors.ENDC}")
            else:
                print(f"{Colors.WARNING}⚠  TOR connection test failed{Colors.ENDC}")
        else:
            print(f"{Colors.ERROR}✗ TOR is not running!{Colors.ENDC}")
            print(f"\n{Colors.INFO}To use TOR:{Colors.ENDC}")
            print("  - Windows: Download TOR Expert Bundle from torproject.org")
            print("  - Linux: sudo apt install tor && sudo systemctl start tor")
            print("  - macOS: brew install tor && brew services start tor")
            print(f"\n{Colors.WARNING}Continuing without TOR...{Colors.ENDC}")
            proxy_manager = None

    elif proxy_choice == "3":
        print(f"\n{Colors.INFO}Proxy format: http://proxy.com:8080 or socks5://proxy.com:1080{Colors.ENDC}")
        proxy_input = input(f"{Colors.OKCYAN}Enter proxy URL: {Colors.ENDC}").strip()

        if proxy_input:
            proxy_manager = ProxyManager(proxy_list=[proxy_input])
            print(f"{Colors.SUCCESS}✓ Proxy configured{Colors.ENDC}")
        else:
            print(f"{Colors.WARNING}⚠  No proxy provided{Colors.ENDC}")

    print(f"\n{Colors.SUCCESS}✓ Configuration complete{Colors.ENDC}")
    print(f"\n{Colors.INFO}Starting enumeration...{Colors.ENDC}")

    # Initialize Subdomain Enumerator
    enumerator = SubdomainEnumerator(
        domain,
        timeout=5,
        max_workers=50,
        verbose=False,
        proxy_manager=proxy_manager
    )

    # Run enumeration based on chosen method
    if method == "1":
        subdomains, cname_map = enumerator.enumerate_deep(use_osint=True, use_bruteforce=False)
    elif method == "3":
        subdomains, cname_map = enumerator.enumerate_deep(use_osint=False, use_bruteforce=True, wordlist=common_wordlist)
    else:
        subdomains, cname_map = enumerator.enumerate_deep(use_osint=True, use_bruteforce=True, wordlist=common_wordlist)

    # Display enumeration results
    print(f"\n{Colors.HEADER}{'='*60}{Colors.ENDC}")
    print(f"{Colors.HEADER}DNS Enumeration Complete!{Colors.ENDC}")
    print(f"{Colors.HEADER}{'='*60}{Colors.ENDC}")
    print(f"{Colors.SUCCESS}Found {Colors.HIGHLIGHT}{len(subdomains)}{Colors.ENDC}{Colors.SUCCESS} active subdomains{Colors.ENDC}\n")

    if not subdomains:
        print(f"{Colors.WARNING}No subdomains found. Exiting...{Colors.ENDC}")
        sys.exit(0)

    # Initialize Red Team Enumerator
    red_team = RedTeamEnumerator(domain, config)

    # Run Red Team Scan on ALL discovered subdomains and IPs
    print(f"{Colors.INFO}Starting Red Team reconnaissance on all {len(subdomains)} targets...{Colors.ENDC}")
    red_team_results = red_team.run_red_team_scan(subdomains, cname_map)

    # Generate and display report
    report = red_team.generate_red_team_report(red_team_results, len(subdomains))
    print(report)

    # Export for other tools
    export_choice = input(f"\n{Colors.OKCYAN}Export targets for other tools? (y/n, default=y): {Colors.ENDC}").strip().lower()
    if export_choice != 'n':
        red_team.export_to_nuclei(list(subdomains.keys()))
        red_team.export_to_nmap(subdomains)

    # Save full results
    output_file = f"{domain}_redteam_scan.json"

    # Extract all unique IPs from subdomains
    all_ips = set()
    for ips in subdomains.values():
        all_ips.update(ips)

    full_results = {
        'domain': domain,
        'timestamp': datetime.now().isoformat(),
        'scan_level': scan_level,
        'dns_info': dns_info,
        'config': {k: v for k, v in config.items() if not k.endswith('_key') and not k.endswith('_token')},
        'statistics': {
            'total_subdomains': len(subdomains),
            'total_unique_ips': len(all_ips),
            'http_enabled': len([p for p in red_team_results.get('http_probes', {}).values() if p.get('http') or p.get('https')]),
            'takeover_vulnerabilities': len(red_team_results.get('takeovers', [])),
            'open_ports_found': len(red_team_results.get('open_ports', {})),
            'waf_detected': len(red_team_results.get('waf_detected', {})),
            'api_endpoints': sum(len(eps) for eps in red_team_results.get('api_endpoints', {}).values())
        },
        'subdomains': subdomains,
        'all_ips': list(all_ips),
        'cname_map': cname_map,
        'red_team_results': red_team_results
    }

    with open(output_file, 'w') as f:
        json.dump(full_results, f, indent=2, default=str)

    print(f"\n{Colors.SUCCESS}✓ Full results saved to {output_file}{Colors.ENDC}")

    # Summary statistics
    print(f"\n{Colors.HEADER}{'='*70}{Colors.ENDC}")
    print(f"{Colors.HEADER}SCAN SUMMARY{Colors.ENDC}")
    print(f"{Colors.HEADER}{'='*70}{Colors.ENDC}")
    print(f"  Total Subdomains: {Colors.HIGHLIGHT}{len(subdomains)}{Colors.ENDC}")
    print(f"  Unique IP Addresses: {Colors.HIGHLIGHT}{len(all_ips)}{Colors.ENDC}")
    print(f"  HTTP/HTTPS Services: {Colors.HIGHLIGHT}{full_results['statistics']['http_enabled']}{Colors.ENDC}")
    print(f"  Takeover Vulnerabilities: {Colors.ERROR if red_team_results.get('takeovers') else Colors.SUCCESS}{full_results['statistics']['takeover_vulnerabilities']}{Colors.ENDC}")
    print(f"  Open Ports Found: {Colors.HIGHLIGHT}{full_results['statistics']['open_ports_found']}{Colors.ENDC}")
    print(f"  WAF/CDN Detected: {Colors.HIGHLIGHT}{full_results['statistics']['waf_detected']}{Colors.ENDC}")
    print(f"  API Endpoints: {Colors.HIGHLIGHT}{full_results['statistics']['api_endpoints']}{Colors.ENDC}")

    cloud_assets = red_team_results.get('cloud_assets', {})
    if cloud_assets.get('s3_buckets'):
        print(f"  S3 Buckets Found: {Colors.HIGHLIGHT}{len(cloud_assets['s3_buckets'])}{Colors.ENDC}")
    if cloud_assets.get('azure_blobs'):
        print(f"  Azure Blobs Found: {Colors.HIGHLIGHT}{len(cloud_assets['azure_blobs'])}{Colors.ENDC}")

    print(f"{Colors.HEADER}{'='*70}{Colors.ENDC}")
    print(f"{Colors.SUCCESS}✓ Red Team Enumeration Complete!{Colors.ENDC}")
    print(f"{Colors.HEADER}{'='*70}{Colors.ENDC}\n")

    print(f"{Colors.INFO}Output Files:{Colors.ENDC}")
    print(f"  • {output_file} - Full JSON results")
    if export_choice != 'n':
        print(f"  • nuclei_targets.txt - For Nuclei scanner")
        print(f"  • nmap_targets.txt - For Nmap scanner")
    print(f"  • scan_history.json - Change tracking\n")

    print(f"\n{Colors.SUCCESS}{'='*70}{Colors.ENDC}")
    print(f"{Colors.SUCCESS}✓ ALL OPERATIONS COMPLETED WITH LIVE PROGRESS INDICATORS!{Colors.ENDC}")
    print(f"{Colors.SUCCESS}{'='*70}{Colors.ENDC}\n")
