import re
import sys
import os
import argparse
import time
import hashlib
import random
import multiprocessing
import threading
import socket
import json
import logging
from collections import Counter
from urllib.parse import urlparse, unquote

# external modules
from subbrute import subbrute
import dns.resolver
import requests

# Disable SSL warnings
try:
    requests.packages.urllib3.disable_warnings()
except AttributeError:
    # requests.packages.urllib3 might not exist in some environments
    pass

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

# Console Colors (simplified for Python 3 consistency and common terminals)
class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RED = '\033[91m'
    WHITE = '\033[0m'
    
    @staticmethod
    def disable():
        global G, Y, B, R, W
        G = Y = B = R = W = ''

# Assign global color variables
G = Colors.GREEN
Y = Colors.YELLOW
B = Colors.BLUE
R = Colors.RED
W = Colors.WHITE

def banner():
    print(f"{R}                 ____        _     _ _     _   _____")
    print(f"                / ___| _   _| |__ | (_)___| |_|___ / _ __")
    print(f"                \\___ \\| | | | '_ \\| | / __| __| |_ \\ '__|")
    print(f"                 ___) | |_| | |_) | | \\__ \\ |_ ___) | |")
    print(f"                |____/ \\__,_|_.__/|_|_|___/\\__|____/|_|{W}{Y}")
    print(f"\n                # Coded By Ahmed Aboul-Ela - @aboul3la")
    print(f"                # Modernized by Savaid Khan - Copyright (C) 2025{W}\n")


def parser_error(errmsg):
    banner()
    logger.error(f"{R}Error: {errmsg}{W}")
    sys.exit(1)


def parse_args():
    parser = argparse.ArgumentParser(epilog=f'\tExample: \r\npython {sys.argv[0]} -d google.com')
    parser.error = parser_error
    parser._optionals.title = "OPTIONS"
    parser.add_argument('-d', '--domain', help="Domain name to enumerate its subdomains", required=True)
    parser.add_argument('-b', '--bruteforce', help='Enable the subbrute bruteforce module', nargs='?', const=True, default=False)
    parser.add_argument('-p', '--ports', help='Scan the found subdomains against specified tcp ports')
    parser.add_argument('-v', '--verbose', help='Enable Verbosity and display results in realtime', nargs='?', const=True, default=False)
    parser.add_argument('-t', '--threads', help='Number of threads to use for subbrute bruteforce', type=int, default=30)
    parser.add_argument('-e', '--engines', help='Specify a comma-separated list of search engines')
    parser.add_argument('-o', '--output', help='Save the results to text file')
    parser.add_argument('-n', '--no-color', help='Output without color', action='store_true')
    return parser.parse_args()


def write_file(filename, subdomains):
    logger.info(f"{Y}Saving results to file: {R}{filename}{W}")
    try:
        with open(str(filename), 'wt') as f:
            for subdomain in subdomains:
                f.write(subdomain + os.linesep)
    except IOError as e:
        logger.error(f"{R}Error saving to file {filename}: {e}{W}")


def subdomain_sorting_key(hostname):
    parts = hostname.split('.')[::-1]
    if parts and parts[-1] == 'www':
        return parts[:-1], 1
    return parts, 0


class enumratorBase(object):
    def __init__(self, engine_name, domain, subdomains=None, silent=False, verbose=True):
        self.domain = urlparse(domain).netloc or domain # Handle cases where domain might not have scheme
        self.session = requests.Session()
        self.subdomains = subdomains or []
        self.timeout = 25
        self.engine_name = engine_name
        self.silent = silent
        self.verbose = verbose
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.8',
            'Accept-Encoding': 'gzip',
        }
        self.base_url = self._load_engine_url(engine_name)
        self.print_banner()

    def _load_engine_url(self, engine_name):
        try:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            engines_file_path = os.path.join(current_dir, 'engines.json')
            with open(engines_file_path, 'r') as f:
                engines_data = json.load(f)
            return engines_data.get(engine_name)
        except FileNotFoundError:
            logger.error(f"{R}Error: engines.json not found. Please ensure it's in the same directory as sublist3r.py.{W}")
            sys.exit(1)
        except json.JSONDecodeError as e:
            logger.error(f"{R}Error parsing engines.json: {e}. Please check the file format.{W}")
            sys.exit(1)
        except Exception as e:
            logger.error(f"{R}An unexpected error occurred while loading engine URLs: {e}{W}")
            sys.exit(1)

    def print_(self, text):
        if not self.silent:
            logger.info(text)
        return

    def print_banner(self):
        self.print_(f"{G}Searching now in {self.engine_name}...{W}")
        return

    def send_req(self, query, page_no=1):
        url = self.base_url.format(query=query, page_no=page_no)
        try:
            resp = self.session.get(url, headers=self.headers, timeout=self.timeout)
            resp.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
        except requests.exceptions.Timeout:
            logger.warning(f"{Y}Timeout occurred for {self.engine_name} at {url}{W}")
            return None
        except requests.exceptions.TooManyRedirects:
            logger.warning(f"{Y}Too many redirects for {self.engine_name} at {url}{W}")
            return None
        except requests.exceptions.RequestException as e:
            logger.error(f"{R}Request failed for {self.engine_name} at {url}: {e}{W}")
            return None
        return self.get_response(resp)

    def get_response(self, response):
        if response is None:
            return None
        return response.text

    def check_max_subdomains(self, count):
        return self.MAX_DOMAINS != 0 and count >= self.MAX_DOMAINS

    def check_max_pages(self, num):
        return self.MAX_PAGES != 0 and num >= self.MAX_PAGES

    def extract_domains(self, resp):
        raise NotImplementedError # Child class must implement this

    def check_response_errors(self, resp):
        return True # Child class can override for specific error checks

    def should_sleep(self):
        pass # Child class can implement if sleeping is required

    def generate_query(self):
        raise NotImplementedError # Child class must implement this

    def get_page(self, num):
        return num + 10 # Default pagination increment

    def enumerate(self, altquery=False):
        page_no = 0
        prev_links = []
        retries = 0

        while True:
            query = self.generate_query()
            
            # For search engines like Google, query size might be limited by MAX_DOMAINS
            current_subdomain_count_in_query = query.count(self.domain)
            if self.check_max_subdomains(current_subdomain_count_in_query):
                page_no = self.get_page(page_no)

            if self.check_max_pages(page_no):
                return self.subdomains
            
            resp = self.send_req(query, page_no)

            if resp is None or not self.check_response_errors(resp):
                return self.subdomains

            links = self.extract_domains(resp)

            if links == prev_links:
                retries += 1
                page_no = self.get_page(page_no)
                if retries >= 3: # Max 3 retries for similar pages
                    logger.warning(f"{Y}Repeated results for {self.engine_name}. Assuming end of results.{W}")
                    return self.subdomains
            else:
                retries = 0 # Reset retries if new links are found

            prev_links = links
            self.should_sleep()

        return self.subdomains


class enumratorBaseThreaded(multiprocessing.Process, enumratorBase):
    def __init__(self, engine_name, domain, subdomains=None, q=None, silent=False, verbose=True):
        enumratorBase.__init__(self, engine_name, domain, subdomains, silent=silent, verbose=verbose)
        multiprocessing.Process.__init__(self)
        self.q = q

    def run(self):
        domain_list = self.enumerate()
        for domain_item in domain_list:
            if self.q: # Ensure q is not None
                self.q.append(domain_item)


class GoogleEnum(enumratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None, silent=False, verbose=True):
        self.MAX_DOMAINS = 11
        self.MAX_PAGES = 200
        super().__init__("Google", domain, subdomains, q=q, silent=silent, verbose=verbose)

    def extract_domains(self, resp):
        links_list = []
        link_regx = re.compile(r'<cite.*?>(.*?)<\/cite>')
        try:
            links_list = link_regx.findall(resp)
            for link in links_list:
                link = re.sub(r'<span.*?>', '', link)
                if not link.startswith('http'):
                    link = "http://" + link
                subdomain = urlparse(link).netloc
                if subdomain and subdomain not in self.subdomains and subdomain != self.domain:
                    if self.verbose:
                        self.print_(f"{R}{self.engine_name}: {W}{subdomain}")
                    self.subdomains.append(subdomain.strip())
        except Exception as e:
            logger.error(f"{R}Error extracting domains from {self.engine_name}: {e}{W}")
        return links_list

    def check_response_errors(self, resp):
        if 'Our systems have detected unusual traffic' in resp:
            logger.warning(f"{R}Google is blocking our requests.{W}")
            return False
        return True

    def should_sleep(self):
        time.sleep(random.randint(5, 15)) # Random sleep to mimic human behavior

    def generate_query(self):
        if self.subdomains:
            found = ' -'.join(self.subdomains[:self.MAX_DOMAINS - 2])
            query = f'site:{self.domain} -www.{self.domain} -{found}'
        else:
            query = f"site:{self.domain} -www.{self.domain}"
        return query


class YahooEnum(enumratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None, silent=False, verbose=True):
        self.MAX_DOMAINS = 10
        self.MAX_PAGES = 0 # No explicit page limit, continues until no new results
        super().__init__("Yahoo", domain, subdomains, q=q, silent=silent, verbose=verbose)

    def extract_domains(self, resp):
        link_regx2 = re.compile(r'<span class=" fz-.*? fw-m fc-12th wr-bw.*?">(.*?)</span>')
        link_regx = re.compile(r'<span class="txt"><span class=" cite fw-xl fz-15px">(.*?)</span>')
        links_list = []
        try:
            links = link_regx.findall(resp)
            links2 = link_regx2.findall(resp)
            links_list = links + links2
            for link in links_list:
                link = re.sub(r"<(\/)?b>", "", link)
                if not link.startswith('http'):
                    link = "http://" + link
                subdomain = urlparse(link).netloc
                if not subdomain.endswith(self.domain):
                    continue
                if subdomain and subdomain not in self.subdomains and subdomain != self.domain:
                    if self.verbose:
                        self.print_(f"{R}{self.engine_name}: {W}{subdomain}")
                    self.subdomains.append(subdomain.strip())
        except Exception as e:
            logger.error(f"{R}Error extracting domains from {self.engine_name}: {e}{W}")
        return links_list

    def should_sleep(self):
        time.sleep(random.randint(1, 5)) # Random sleep
        
    def get_page(self, num):
        return num + 10 # Yahoo uses page increments of 10

    def generate_query(self):
        if self.subdomains:
            found = ' -domain:'.join(self.subdomains[:77])
            query = f'site:{self.domain} -domain:www.{self.domain} -domain:{found}'
        else:
            query = f"site:{self.domain}"
        return query


class AskEnum(enumratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None, silent=False, verbose=True):
        self.MAX_DOMAINS = 11
        self.MAX_PAGES = 0
        super().__init__("Ask", domain, subdomains, q=q, silent=silent, verbose=verbose)

    def extract_domains(self, resp):
        links_list = []
        link_regx = re.compile(r'<p class="web-result-url">(.*?)</p>')
        try:
            links_list = link_regx.findall(resp)
            for link in links_list:
                if not link.startswith('http'):
                    link = "http://" + link
                subdomain = urlparse(link).netloc
                if subdomain and subdomain not in self.subdomains and subdomain != self.domain:
                    if self.verbose:
                        self.print_(f"{R}{self.engine_name}: {W}{subdomain}")
                    self.subdomains.append(subdomain.strip())
        except Exception as e:
            logger.error(f"{R}Error extracting domains from {self.engine_name}: {e}{W}")
        return links_list

    def should_sleep(self):
        time.sleep(random.randint(1, 5)) # Random sleep

    def generate_query(self):
        if self.subdomains:
            found = ' -domain:'.join(self.subdomains[:self.MAX_DOMAINS])
            query = f'site:{self.domain} -domain:www.{self.domain} -domain:{found}'
        else:
            query = f"site:{self.domain}"
        return query


class BingEnum(enumratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None, silent=False, verbose=True):
        self.MAX_DOMAINS = 11
        self.MAX_PAGES = 0
        super().__init__("Bing", domain, subdomains, q=q, silent=silent, verbose=verbose)

    def extract_domains(self, resp):
        links_list = []
        link_regx = re.compile(r'<h2><a href="(.*?)"')
        try:
            links_list = link_regx.findall(resp)
            for link in links_list:
                link = re.sub(r'<(\/)?strong>|<span.*?>|<|>', '', link)
                if not link.startswith('http'):
                    link = "http://" + link
                subdomain = urlparse(link).netloc
                if not subdomain.endswith(self.domain):
                    continue
                if subdomain and subdomain not in self.subdomains and subdomain != self.domain:
                    if self.verbose:
                        self.print_(f"{R}{self.engine_name}: {W}{subdomain}")
                    self.subdomains.append(subdomain.strip())
        except Exception as e:
            logger.error(f"{R}Error extracting domains from {self.engine_name}: {e}{W}")
        return links_list

    def should_sleep(self):
        time.sleep(random.randint(1, 5)) # Random sleep

    def get_page(self, num):
        return num + 10 # Bing uses page increments of 10

    def generate_query(self):
        if self.subdomains:
            found = ' -domain:'.join(self.subdomains[:self.MAX_DOMAINS])
            query = f'domain:{self.domain} -www.{self.domain} -{found}'
        else:
            query = f"domain:{self.domain} -www.{self.domain}"
        return query


class BaiduEnum(enumratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None, silent=False, verbose=True):
        self.MAX_DOMAINS = 2
        self.MAX_PAGES = 0
        super().__init__("Baidu", domain, subdomains, q=q, silent=silent, verbose=verbose)

    def extract_domains(self, resp):
        links_list = []
        link_regx = re.compile(r'<a.*?href="(.*?)".*?>.*?</a>')
        try:
            links_list = link_regx.findall(resp)
            for link in links_list:
                if not link.startswith('http'):
                    link = "http://" + link
                subdomain = urlparse(link).netloc
                if not subdomain.endswith(self.domain):
                    continue
                if subdomain and subdomain not in self.subdomains and subdomain != self.domain:
                    if self.verbose:
                        self.print_(f"{R}{self.engine_name}: {W}{subdomain}")
                    self.subdomains.append(subdomain.strip())
        except Exception as e:
            logger.error(f"{R}Error extracting domains from {self.engine_name}: {e}{W}")
        return links_list

    def should_sleep(self):
        time.sleep(random.randint(1, 5)) # Random sleep

    def generate_query(self):
        if self.subdomains:
            found = ' -'.join(self.subdomains[:self.MAX_DOMAINS])
            query = f'site:{self.domain} -www.{self.domain} -{found}'
        else:
            query = f"site:{self.domain} -www.{self.domain}"
        return query


class NetcraftEnum(enumratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None, silent=False, verbose=True):
        self.MAX_DOMAINS = 0
        self.MAX_PAGES = 0
        super().__init__("Netcraft", domain, subdomains, q=q, silent=silent, verbose=verbose)
        self.url = self.base_url.format(domain=self.domain)

    def get_cookies(self, headers):
        cookies = {}
        if 'set-cookie' in headers:
            cookies_list = headers['set-cookie'].split("=")
            cookies[cookies_list[0]] = cookies_list[1].split(';')[0]
            # hashlib.sha1 requires utf-8 encoded str
            cookies['netcraft_js_verification_response'] = hashlib.sha1(unquote(cookies_list[1].split(';')[0]).encode('utf-8')).hexdigest()
        return cookies

    def enumerate(self):
        start_url = self.base_url.format(domain='example.com')
        resp = self.send_req(start_url, cookies={}) # Pass empty cookies initially
        if resp is None:
            return self.subdomains

        cookies = self.get_cookies(requests.Response().headers) # Get headers from a dummy response

        url = self.base_url.format(domain=self.domain)
        while True:
            resp_content = self.send_req(url, cookies=cookies) # Pass the extracted cookies
            if resp_content is None:
                return self.subdomains

            self.extract_domains(resp_content)
            
            # Check for "Next Page" link
            next_page_match = re.search(r'<a href="([^"]+)">Next Page<\/a>', resp_content)
            if not next_page_match:
                break
            url = urlparse(url).scheme + "://" + urlparse(url).netloc + next_page_match.group(1)
            self.should_sleep()
        return self.subdomains


    def extract_domains(self, resp):
        links_list = []
        link_regx = re.compile(r'<a class="results-table__host" href="(.*?)"')
        try:
            links_list = link_regx.findall(resp)
            for link in links_list:
                subdomain = urlparse(link).netloc
                if not subdomain.endswith(self.domain):
                    continue
                if subdomain and subdomain not in self.subdomains and subdomain != self.domain:
                    if self.verbose:
                        self.print_(f"{R}{self.engine_name}: {W}{subdomain}")
                    self.subdomains.append(subdomain.strip())
        except Exception as e:
            logger.error(f"{R}Error extracting domains from {self.engine_name}: {e}{W}")
        return links_list


class Virustotal(enumratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None, silent=False, verbose=True):
        super().__init__("Virustotal", domain, subdomains, q=q, silent=silent, verbose=verbose)
        self.url = self.base_url.format(domain=self.domain)

    def send_req(self, url):
        try:
            resp = self.session.get(url, headers=self.headers, timeout=self.timeout)
            resp.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
        except requests.exceptions.RequestException as e:
            logger.error(f"{R}Request failed for {self.engine_name} at {url}: {e}{W}")
            return None
        return self.get_response(resp)

    def enumerate(self):
        while self.url:
            resp = self.send_req(self.url)
            if resp is None:
                break
            try:
                resp_json = json.loads(resp)
            except json.JSONDecodeError as e:
                logger.error(f"{R}Error decoding JSON from {self.engine_name}: {e}{W}")
                break

            if 'error' in resp_json:
                logger.warning(f"{R}{self.engine_name} is blocking our requests: {resp_json.get('error', 'Unknown error')}{W}")
                break
            
            if 'links' in resp_json and 'next' in resp_json['links']:
                self.url = resp_json['links']['next']
            else:
                self.url = '' # No more pages

            self.extract_domains(resp_json) # Pass parsed JSON

        return self.subdomains

    def extract_domains(self, resp):
        # resp is already parsed as json
        try:
            if 'data' in resp:
                for item in resp['data']:
                    if item.get('type') == 'domain':
                        subdomain = item.get('id')
                        if subdomain and subdomain.endswith(self.domain) and \
                           subdomain not in self.subdomains and subdomain != self.domain:
                            if self.verbose:
                                self.print_(f"{R}{self.engine_name}: {W}{subdomain}")
                            self.subdomains.append(subdomain.strip())
        except Exception as e:
            logger.error(f"{R}Error extracting domains from {self.engine_name} JSON data: {e}{W}")


class ThreatCrowd(enumratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None, silent=False, verbose=True):
        super().__init__("ThreatCrowd", domain, subdomains, q=q, silent=silent, verbose=verbose)

    def send_req(self, url):
        try:
            resp = self.session.get(url, headers=self.headers, timeout=self.timeout)
            resp.raise_for_status()
        except requests.exceptions.RequestException as e:
            logger.error(f"{R}Request failed for {self.engine_name} at {url}: {e}{W}")
            return None
        return self.get_response(resp)

    def enumerate(self):
        url = self.base_url.format(domain=self.domain)
        resp = self.send_req(url)
        if resp is None:
            return self.subdomains

        try:
            resp_json = json.loads(resp)
        except json.JSONDecodeError as e:
            logger.error(f"{R}Error decoding JSON from {self.engine_name}: {e}{W}")
            return self.subdomains

        if resp_json.get('response_code') != '1': # Check response_code for success
            logger.warning(f"{Y}ThreatCrowd API returned an error or no results for {self.domain}. Response: {resp_json.get('verbose_message', 'No message provided.')}{W}")
            return self.subdomains

        self.extract_domains(resp_json)
        return self.subdomains

    def extract_domains(self, resp):
        try:
            if 'subdomains' in resp:
                for subdomain in resp['subdomains']:
                    if subdomain and subdomain.endswith(self.domain) and \
                       subdomain not in self.subdomains and subdomain != self.domain:
                        if self.verbose:
                            self.print_(f"{R}{self.engine_name}: {W}{subdomain}")
                        self.subdomains.append(subdomain.strip())
        except Exception as e:
            logger.error(f"{R}Error extracting domains from {self.engine_name} JSON data: {e}{W}")


class CrtSearch(enumratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None, silent=False, verbose=True):
        super().__init__("CrtSearch", domain, subdomains, q=q, silent=silent, verbose=verbose)
        self.url = self.base_url.format(domain=self.domain)

    def send_req(self, url):
        try:
            resp = self.session.get(url, headers=self.headers, timeout=self.timeout)
            resp.raise_for_status()
        except requests.exceptions.RequestException as e:
            logger.error(f"{R}Request failed for {self.engine_name} at {url}: {e}{W}")
            return None
        return self.get_response(resp)

    def enumerate(self):
        resp = self.send_req(self.url)
        if resp is None:
            return self.subdomains
        self.extract_domains(resp)
        return self.subdomains

    def extract_domains(self, resp):
        links_list = []
        # Regex to find domain names in crt.sh output
        link_regx = re.compile(r'(?:\<TD\>([^\<\>\s]+\.' + re.escape(self.domain) + r'))(?:\<\/TD\>)?')
        try:
            links = link_regx.findall(resp)
            for link in links:
                subdomain = link.strip()
                if subdomain.startswith('*.'): # Handle wildcard certificates
                    subdomain = subdomain[2:]
                
                # Further clean common artifacts from certificates
                subdomain = subdomain.split('<BR>')[0].strip() # Take only the first domain if multiple
                subdomain = subdomain.replace('<td>', '').replace('</td>', '') # Clean any remaining tags
                subdomain = subdomain.lower() # Domains are case-insensitive

                if subdomain and subdomain not in self.subdomains and \
                   subdomain.endswith(self.domain) and subdomain != self.domain:
                    if self.verbose:
                        self.print_(f"{R}{self.engine_name}: {W}{subdomain}")
                    self.subdomains.append(subdomain)
        except Exception as e:
            logger.error(f"{R}Error extracting domains from {self.engine_name}: {e}{W}")


class DNSdumpster(enumratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None, silent=False, verbose=True):
        super().__init__("DNSdumpster", domain, subdomains, q=q, silent=silent, verbose=verbose)
        self.live_subdomains = []
        self.lock = threading.Lock() # For concurrent DNS queries

    def check_host(self, host):
        is_valid = False
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['8.8.8.8', '8.8.4.4'] # Use reliable public DNS
        resolver.timeout = 5
        resolver.lifetime = 5
        
        with self.lock: # Ensure only one thread modifies live_subdomains at a time
            try:
                ip = resolver.query(host, 'A')[0].to_text()
                if ip:
                    if self.verbose:
                        self.print_(f"{R}{self.engine_name} (Live DNS): {W}{host}")
                    is_valid = True
                    self.live_subdomains.append(host)
            except (dns.resolver.NXDOMAIN, dns.resolver.Timeout, dns.resolver.NoAnswer, dns.resolver.NoNameservers, Exception) as e:
                # logger.debug(f"DNS query failed for {host}: {e}") # Log detailed DNS errors if needed
                pass
        return is_valid

    def req(self, req_method, url, params=None):
        params = params or {}
        headers = dict(self.headers)
        headers['Referer'] = 'https://dnsdumpster.com'
        try:
            if req_method == 'GET':
                resp = self.session.get(url, headers=headers, timeout=self.timeout)
            else: # Assuming POST for other methods, specifically for CSRF token
                resp = self.session.post(url, headers=headers, data=params, timeout=self.timeout)
            resp.raise_for_status()
        except requests.exceptions.RequestException as e:
            logger.error(f"{R}Request failed for {self.engine_name} at {url}: {e}{W}")
            return None
        return self.get_response(resp)

    def enumerate(self):
        try:
            # Get CSRF token
            initial_resp = self.req('GET', self.base_url)
            if initial_resp is None:
                return self.subdomains
            
            csrf_token_match = re.search(r'<input type="hidden" name="csrf_token" value="([^"]+)">', initial_resp)
            if not csrf_token_match:
                logger.error(f"{R}CSRF token not found for DNSdumpster. Enumeration aborted.{W}")
                return self.subdomains
            csrf_token = csrf_token_match.group(1)

            data = {
                'targetip': self.domain,
                'csrf_token': csrf_token
            }
            resp_content = self.req('POST', self.base_url, params=data)
            if resp_content is None:
                return self.subdomains

            self.extract_domains(resp_content)

            # Initiate concurrent DNS checks for found subdomains
            threads = []
            for subdomain in self.subdomains:
                t = threading.Thread(target=self.check_host, args=(subdomain,))
                threads.append(t)
                t.start()
            
            for t in threads:
                t.join() # Wait for all DNS check threads to complete

            # Add only live subdomains to the main list
            for s in self.live_subdomains:
                if s not in self.subdomains: # Avoid duplicates if already added by extract_domains
                    self.subdomains.append(s)

        except Exception as e:
            logger.error(f"{R}An error occurred during DNSdumpster enumeration: {e}{W}")
        return self.subdomains

    def extract_domains(self, resp):
        # Extract from tables (A records, MX records, NS records)
        tables = re.findall(r'<table class=".*?">.*?</table>', resp, re.DOTALL)
        for table in tables:
            # Extract hostnames from table rows
            hosts = re.findall(r'<tr>\s*<td class=".*?">\s*(.*?)\s*</td>', table)
            for host_entry in hosts:
                # Clean up and normalize
                subdomain = host_entry.split('<br/>')[0].strip()
                subdomain = re.sub(r'\(.*\)', '', subdomain).strip() # Remove IPs in parentheses
                
                if subdomain.startswith('<a'): # Remove anchor tags
                    subdomain = re.sub(r'<a[^>]*>(.*?)<\/a>', r'\1', subdomain).strip()

                if subdomain.endswith(self.domain) and subdomain not in self.subdomains and subdomain != self.domain:
                    if self.verbose:
                        self.print_(f"{R}{self.engine_name}: {W}{subdomain}")
                    self.subdomains.append(subdomain)
        # Note: DNSdumpster also provides live checks, which are handled in enumerate() via check_host


class PassiveDNS(enumratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None, silent=False, verbose=True):
        super().__init__("PassiveDNS", domain, subdomains, q=q, silent=silent, verbose=verbose)

    def send_req(self, url):
        try:
            resp = self.session.get(url, headers=self.headers, timeout=self.timeout)
            resp.raise_for_status()
        except requests.exceptions.RequestException as e:
            logger.error(f"{R}Request failed for {self.engine_name} at {url}: {e}{W}")
            return None
        return self.get_response(resp)

    def enumerate(self):
        url = self.base_url.format(domain=self.domain)
        resp = self.send_req(url)
        if resp is None:
            return self.subdomains
        
        try:
            json_resp = json.loads(resp)
            if isinstance(json_resp, list): # The API returns a list of subdomains directly
                self.extract_domains(json_resp)
        except json.JSONDecodeError as e:
            logger.error(f"{R}Error decoding JSON from {self.engine_name}: {e}{W}")
        
        return self.subdomains

    def extract_domains(self, domains_list):
        for subdomain in domains_list:
            if isinstance(subdomain, str) and subdomain.endswith(self.domain) and \
               subdomain not in self.subdomains and subdomain != self.domain:
                if self.verbose:
                    self.print_(f"{R}{self.engine_name}: {W}{subdomain}")
                self.subdomains.append(subdomain.strip())


def main():
    args = parse_args()

    if args.no_color:
        Colors.disable()
    if args.verbose:
        logger.setLevel(logging.DEBUG) # Set logger to DEBUG for verbose output

    banner()

    subdomains_queue = multiprocessing.Manager().list() # Use Manager().list() for shared list
    subdomains_queue.append(args.domain) # Add the main domain to the list

    # Define supported engines mapping
    supported_engines = {
        'google': GoogleEnum,
        'yahoo': YahooEnum,
        'bing': BingEnum,
        'ask': AskEnum,
        'baidu': BaiduEnum,
        'netcraft': NetcraftEnum,
        'virustotal': Virustotal,
        'threatcrowd': ThreatCrowd,
        'dnsdumpster': DNSdumpster,
        'crtsearch': CrtSearch,
        'passivedns': PassiveDNS
    }

    chosenEnums = []
    if args.engines is None:
        # If no engines specified, use all by default
        chosenEnums = list(supported_engines.values())
    else:
        engines_list = [e.strip().lower() for e in args.engines.split(',')]
        for engine_name in engines_list:
            if engine_name in supported_engines:
                chosenEnums.append(supported_engines[engine_name])
            else:
                logger.warning(f"{Y}Engine '{engine_name}' is not supported. Skipping.{W}")

    # Start the engines enumeration
    enums = [
        enum_class(
            args.domain,
            list(subdomains_queue), # Pass a copy of initial subdomains if any
            q=subdomains_queue,
            silent=(not args.verbose), # Silent if not verbose
            verbose=args.verbose
        ) for enum_class in chosenEnums
    ]

    for enum_instance in enums:
        enum_instance.start()
    
    for enum_instance in enums:
        enum_instance.join()

    # Consolidate and sort unique subdomains
    unique_subdomains = sorted(list(set(subdomains_queue)), key=subdomain_sorting_key)

    if args.output:
        write_file(args.output, unique_subdomains)

    if args.bruteforce:
        logger.info(f"{G}Starting SubBrute bruteforce module...{W}")
        # Subbrute will also append to subdomains_queue
        # Passing unique_subdomains for subbrute to work on existing found subdomains
        try:
            subbrute.main(args.domain, 
                          output=args.output, 
                          threads=args.threads, 
                          ipv4_only=False, # Assuming default to query all types
                          subdomains_list=unique_subdomains # Pass current unique subdomains
            )
            # After subbrute runs, we might need to re-sort and re-deduplicate
            # as subbrute directly modifies the queue.
            unique_subdomains = sorted(list(set(subdomains_queue)), key=subdomain_sorting_key)
            if args.output:
                write_file(args.output, unique_subdomains) # Overwrite with updated list
        except Exception as e:
            logger.error(f"{R}An error occurred during bruteforce: {e}{W}")

    # Final output of all found subdomains
    logger.info(f"\n{G}Found {len(unique_subdomains)} unique subdomains for {args.domain}:{W}")
    for subdomain in unique_subdomains:
        logger.info(f"{B}{subdomain}{W}")

    if args.ports:
        logger.info(f"{G}Scanning ports for found subdomains (feature not implemented in detail yet, conceptual)...{W}")
        # This part would require a separate port scanning module/logic
        # For a real implementation, you'd iterate through unique_subdomains
        # and attempt to connect to specified ports.
        logger.warning(f"{Y}Port scanning functionality is a placeholder. Needs full implementation.{W}")


if __name__ == "__main__":
    multiprocessing.freeze_support() # Required for multiprocessing to work in bundled executables
    main()