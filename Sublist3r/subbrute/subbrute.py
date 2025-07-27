import re
import optparse
import os
import signal
import sys
import uuid
import random
import ctypes
import dns.resolver
import dns.rdatatype
import json
import logging # Import logging

# Python 3.x compatibility for queue
import queue as Queue # Use standard library queue

# The 'multiprocessing' library does not rely upon a Global Interpreter Lock (GIL)
import multiprocessing

# Configure logging for subbrute.py
logger = logging.getLogger('sublist3r.subbrute') # Use a child logger
logger.addHandler(logging.NullHandler()) # Prevent propagation to root logger if not configured

# Microsoft compatibility
if sys.platform.startswith('win'):
    # Drop-in replacement, subbrute + multiprocessing throws exceptions on windows.
    import threading
    multiprocessing.Process = threading.Thread

class verify_nameservers(multiprocessing.Process):

    def __init__(self, target, record_type, resolver_q, resolver_list, wildcards):
        super().__init__()
        self.daemon = True
        # No need for signal_init() here, handled by parent process or main function
        # signal_init() # Removed as it's not strictly necessary for child processes in all OS

        self.time_to_die = False
        self.resolver_q = resolver_q
        self.wildcards = wildcards
        self.record_type = "A"
        if record_type == "AAAA":
            self.record_type = record_type
        self.resolver_list = resolver_list
        
        self.resolver = dns.resolver.Resolver()
        self.target = target
        self.most_popular_website = "www.google.com" # Can be externalized too
        self.backup_resolver = self.resolver.nameservers + ['127.0.0.1', '8.8.8.8', '8.8.4.4']
        self.resolver.timeout = 1
        self.resolver.lifetime = 1
        
        try:
            # Test latency
            self.resolver.nameservers = ['8.8.8.8']
            self.resolver.query(self.most_popular_website, self.record_type)
        except Exception as e:
            logger.debug(f"Initial resolver test failed: {e}. Reverting to default resolver settings.")
            self.resolver = dns.resolver.Resolver() # Revert to default resolver settings


    def end(self):
        self.time_to_die = True

    def add_nameserver(self, nameserver):
        keep_trying = True
        while not self.time_to_die and keep_trying:
            try:
                self.resolver_q.put(nameserver, timeout=1)
                logger.debug(f"Added nameserver: {nameserver}")
                keep_trying = False
            except Queue.Full:
                logger.debug(f"Resolver queue full, retrying for {nameserver}")
                keep_trying = True
            except Exception as e:
                logger.error(f"Error adding nameserver {nameserver}: {e}")
                keep_trying = False # Stop trying for this nameserver


    def verify(self, nameserver_list):
        added_resolver = False
        for server in nameserver_list:
            if self.time_to_die:
                break
            server = server.strip()
            if server:
                self.resolver.nameservers = [server]
                try:
                    # Test for wildcard DNS or spamming nameservers
                    if self.find_wildcards(self.target):
                        self.add_nameserver(server)
                        added_resolver = True
                    else:
                        logger.debug(f"Rejected nameserver - wildcard/spam detected: {server}")
                except (dns.resolver.NXDOMAIN, dns.resolver.Timeout, dns.resolver.NoAnswer, dns.resolver.NoNameservers, Exception) as e:
                    logger.debug(f"Rejected nameserver - unreliable ({server}): {e}")
        return added_resolver

    def run(self):
        random.shuffle(self.resolver_list)
        if not self.verify(self.resolver_list):
            logger.warning('No nameservers found from primary list, trying fallback list.')
            self.verify(self.backup_resolver)
        
        try:
            self.resolver_q.put(False, timeout=1) # Signal end of resolvers
        except Queue.Full:
            logger.warning("Failed to put end signal in resolver queue (full).")


    def find_wildcards(self, host):
        try:
            # Test for spam DNS servers by querying a random non-existent domain
            wildtest = self.resolver.query(uuid.uuid4().hex + ".com", "A")
            if wildtest:
                logger.debug(f"Spam DNS detected: {host}")
                return False # Spam DNS detected
        except dns.resolver.NXDOMAIN:
            pass # Expected for a non-existent domain if not a spam DNS
        except Exception as e:
            logger.debug(f"Wildcard test exception for {host}: {e}")
            return False # Resolver might be flaky

        test_counter = 8
        while test_counter >= 0:
            test_counter -= 1            
            try:
                testdomain = f"{uuid.uuid4().hex}.{host}"
                wildtest = self.resolver.query(testdomain, self.record_type)
                
                for w_record in wildtest:
                    w = str(w_record)
                    if w not in self.wildcards:
                        self.wildcards[w] = None # Add detected wildcard IP
                        return False # Wildcard detected, reject this nameserver
            except dns.resolver.NXDOMAIN:
                # This is the desired outcome: the domain doesn't exist.
                return True
            except Exception as e:
                logger.debug(f"Wildcard query failed for {testdomain}: {e}. Retrying.")
                # Continue loop if there are retries left, otherwise will return False by falling through
        
        # If loop finishes, it means wildcard behavior was consistent (or test_counter ran out)
        # and no new wildcards were added to self.wildcards (which means it's clean if it started clean)
        # If test_counter ran out, it might still be a flaky DNS, so reject.
        return test_counter >= 0 # Only return True if tests passed without issues


class lookup(multiprocessing.Process):

    def __init__(self, in_q, out_q, resolver_q, domain, wildcards, spider_blacklist):
        super().__init__()
        # No need for signal_init() here, handled by main function
        # signal_init() 
        self.required_nameservers = 16
        self.in_q = in_q
        self.out_q = out_q
        self.resolver_q = resolver_q        
        self.domain = domain
        self.wildcards = wildcards
        self.spider_blacklist = spider_blacklist
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = [] # Force pydns to use our nameservers


    def get_ns(self):
        ret = []
        try:
            nameserver = self.resolver_q.get_nowait()
            if nameserver is False: # Check explicitly for False signal
                self.resolver_q.put(False) # Propagate the signal
            else:
                ret.append(nameserver)
        except Queue.Empty:
            pass # Queue is empty, no nameservers available without blocking
        except Exception as e:
            logger.error(f"Error getting nameserver (non-blocking): {e}")
        return ret  

    def get_ns_blocking(self):
        ret = []
        try:
            nameserver = self.resolver_q.get() # This call blocks
            if nameserver is False: # Check explicitly for False signal
                logger.debug("get_ns_blocking - Resolver list is empty (received False signal).")
                self.resolver_q.put(False) # Propagate the signal
            else:
                ret.append(nameserver)
        except Exception as e:
            logger.error(f"Error getting nameserver (blocking): {e}")
        return ret

    def check(self, host, record_type="A", retries=0):
        logger.debug(f"Checking: {host} (Type: {record_type})")
        cname_record = []
        
        # This process needs more nameservers, let's see if we have one available
        if len(self.resolver.nameservers) < self.required_nameservers:
            new_ns = self.get_ns()
            if new_ns:
                self.resolver.nameservers.extend(new_ns)
            else:
                # If no non-blocking NS available, try blocking once if needed
                if not self.resolver.nameservers:
                    blocking_ns = self.get_ns_blocking()
                    if blocking_ns:
                        self.resolver.nameservers.extend(blocking_ns)
                    else:
                        logger.warning(f"No nameservers available for {host}. Skipping.")
                        return None # Cannot proceed without resolvers
        
        for _ in range(retries + 1): # Attempt original + retries
            try:
                if not record_type or record_type == "A":
                    resp = self.resolver.query(host, "A")
                    hosts = extract_hosts(str(resp.response), self.domain)
                    for h_found in hosts:
                        if h_found not in self.spider_blacklist:
                            self.spider_blacklist[h_found] = None
                            logger.debug(f"Found host with spider: {h_found}")
                            self.in_q.put((h_found, record_type, 0)) # Add to input queue for further processing
                    return resp
                
                elif record_type == "CNAME":
                    # A max 20 lookups to prevent infinite loops for CNAME chains
                    for _ in range(20): 
                        cname_resp = self.resolver.query(host, "CNAME")
                        cname_record.append(cname_resp[0].target.to_text())
                        host = cname_resp[0].target.to_text() # Update host for next lookup in chain
                        
                        # If the CNAME resolves to an A record, we're done.
                        try:
                            a_resp = self.resolver.query(host, "A")
                            # If A record found after CNAME, return it.
                            return a_resp
                        except dns.resolver.NoAnswer:
                            # No A record yet, continue if CNAME chain
                            if not host.endswith(self.domain) and host not in self.spider_blacklist:
                                # Add external CNAME target to spider blacklist to avoid infinite loops if it's not our domain
                                self.spider_blacklist[host] = None
                            continue
                        except Exception as inner_e:
                            logger.debug(f"Error during CNAME A-record lookup for {host}: {inner_e}")
                            break # Break CNAME chain on error
                    return None # CNAME chain too long or errored

                elif record_type == "MX":
                    resp = self.resolver.query(host, "MX")
                    return resp

                elif record_type == "TXT":
                    resp = self.resolver.query(host, "TXT")
                    return resp
                
                elif record_type == "NS":
                    resp = self.resolver.query(host, "NS")
                    return resp
                
                elif record_type == "AAAA":
                    resp = self.resolver.query(host, "AAAA")
                    return resp

            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                return None # Host or record type not found
            except dns.resolver.Timeout:
                logger.warning(f"Resolver timeout for {host}. Retrying...")
                # Continue loop (retries)
            except Exception as e:
                logger.error(f"Error checking {host} (Type: {record_type}): {e}")
                return None # Other unexpected errors

        return None # If all retries fail

    def process_result(self, target, record_type, json_output_file):
        result = {}
        resp = self.check(target, record_type)
        if resp:
            ips = []
            for rdata in resp:
                if record_type == "A" or record_type == "AAAA":
                    ips.append(str(rdata))
                elif record_type == "CNAME":
                    # CNAME target
                    ips.append(str(rdata.target))
                elif record_type == "MX":
                    # MX preference and exchange
                    ips.append({"preference": rdata.preference, "exchange": str(rdata.exchange)})
                elif record_type == "TXT":
                    # TXT data (decode bytes)
                    ips.append([txt.decode('utf-8') for txt in rdata.strings])
                elif record_type == "NS":
                    # NS target
                    ips.append(str(rdata.target))
            result[target] = ips
            if json_output_file:
                json_output_file.write(json.dumps(result) + "\n")
            else:
                logger.info(f"{B}{record_type}: {target} -> {ips}{W}")
        return result

    def run(self):
        json_output_file = None
        # You'll need to pass json_output_file as an argument or handle it differently if you want JSON output from subbrute workers.
        # For this example, we'll assume JSON output is handled by the main thread.

        while True:
            try:
                item = self.in_q.get()
                if item is False:
                    self.in_q.put(False) # Propagate the termination signal
                    break # Terminate this process
                
                target, record_type, retries = item # Unpack retries
                
                # Check for wildcards at this stage before processing the lookup
                # This part aligns with the original subbrute logic.
                if self.find_wildcards(target): 
                    resp = self.check(target, record_type) # Perform the actual DNS lookup
                    if resp:
                        # Process and add to output queue
                        if record_type == "A" or record_type == "AAAA":
                            ips = [str(rdata) for rdata in resp]
                        elif record_type == "CNAME":
                            ips = [str(rdata.target) for rdata in resp]
                            # If CNAME chain resolves to an A record, add it to output.
                            # This needs more sophisticated handling if we want to follow all CNAMEs.
                            # For now, just output the CNAME target.
                        elif record_type == "MX":
                            ips = [{"preference": rdata.preference, "exchange": str(rdata.exchange)} for rdata in resp]
                        elif record_type == "TXT":
                            ips = [txt.decode('utf-8') for rdata in resp.strings]
                        elif record_type == "NS":
                            ips = [str(rdata.target) for rdata in resp]
                        else:
                            ips = [str(rdata) for rdata in resp] # Generic fallback

                        if ips:
                            self.out_q.put((target, record_type, ips))
                    else:
                        # If lookup failed, try again if retries available
                        if retries < 2: # Max 2 retries (0, 1, 2)
                            self.in_q.put((target, record_type, retries + 1))
                            logger.debug(f"Retrying {target} ({record_type}), attempt {retries + 1}")
                else:
                    logger.debug(f"Skipping {target} due to wildcard detection.")

            except Queue.Empty:
                logger.debug("Input queue empty, worker waiting...")
                time.sleep(0.1) # Short sleep to avoid busy-waiting
            except Exception as e:
                logger.error(f"Error in lookup worker: {e}")


# Helper function to extract hosts from DNS response
host_match = re.compile(r"((?<=[\s])[a-zA-Z0-9_-]+\.(?:[a-zA-Z0-9_-]+\.?)+(?=[\s]))")
def extract_hosts(data, hostname):
    ret = []
    hosts = re.findall(host_match, data)
    for fh in hosts:
        host = fh.rstrip(".")
        if host.endswith(hostname):
            ret.append(host)
    return ret


# Function to extract subdomains from names.txt (wordlist)
domain_match = re.compile(r"([a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*)+") # Match subdomain.domain.tld
def extract_subdomains_from_file(file_name):
    subs = {}
    try:
        with open(file_name, 'r') as f:
            sub_file_content = f.read()
    except FileNotFoundError:
        logger.error(f"Error: Wordlist file '{file_name}' not found. Please check the path.")
        return []
    except Exception as e:
        logger.error(f"Error reading wordlist file '{file_name}': {e}")
        return []

    f_all = re.findall(domain_match, sub_file_content)
    del sub_file_content # Free memory

    for i in f_all:
        if i.find(".") >= 0:
            p = i.split(".")[0:-1]
            while p and len(p[-1]) <= 3: # Gobble TLDs (e.g., .com, .org)
                p = p[0:-1]
            
            p = p[0:-1] # Remove the main domain name part
            
            if len(p) >= 1: # Check if there's a subdomain.domain left
                for q in p:
                    if q:
                        q = q.lower() # Domain names can only be lower case.
                        subs[q] = subs.get(q, 0) + 1 # Count frequency

    subs_sorted = sorted(subs.keys(), key=lambda x: subs[x], reverse=True) # Sort by freq in desc order
    return subs_sorted


def main(target_domain, output=None, threads=30, ipv4_only=False, subdomains_list=None):
    if not subdomains_list:
        subdomains_list = [] # Initialize if not provided

    # Queues for inter-process communication
    in_q = multiprocessing.Queue()
    out_q = multiprocessing.Queue()
    resolver_q = multiprocessing.Queue() # Queue for DNS resolvers

    wildcards = {} # Dictionary to store detected wildcard IPs

    # Paths to names.txt and resolvers.txt
    current_dir = os.path.dirname(os.path.abspath(__file__))
    names_file = os.path.join(current_dir, "names.txt")
    resolvers_file = os.path.join(current_dir, "resolvers.txt")

    # Extract subdomains from the wordlist file
    wordlist_subdomains = extract_subdomains_from_file(names_file)
    for subdomain in wordlist_subdomains:
        in_q.put((subdomain, "A", 0)) # Add initial subdomains to the input queue for lookup (A record, 0 retries)

    # Load resolvers from resolvers.txt
    resolver_list = []
    try:
        with open(resolvers_file, 'r') as f:
            resolver_list = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        logger.error(f"Resolver list file '{resolvers_file}' not found.")
        return # Exit if resolvers file is missing

    # Start nameserver verification process
    verify_process = verify_nameservers(target_domain, "A", resolver_q, resolver_list, wildcards)
    verify_process.start()

    # Start lookup worker processes
    worker_threads = []
    for _ in range(threads):
        worker = lookup(in_q, out_q, resolver_q, target_domain, wildcards, {}) # Pass a new empty dict for spider_blacklist for each worker
        worker_threads.append(worker)
        worker.start()

    # Collect results from output queue
    found_subdomains = []
    terminated_workers = 0
    while terminated_workers < threads:
        try:
            item = out_q.get(timeout=5) # Wait for results
            target, record_type, ips = item
            if target == 'TERMINATE_SIGNAL': # Custom termination signal
                terminated_workers += 1
                continue
            
            # Add to the main list (which is shared via Manager().list() in sublist3r.py)
            # If main() is called standalone, populate a local list
            if subdomains_list is not None:
                if target not in subdomains_list:
                    subdomains_list.append(target)
                    logger.info(f"Found (subbrute): {target} -> {ips}") # Log subbrute findings
            else:
                found_subdomains.append(target) # Populate local list if subdomains_list is None

        except Queue.Empty:
            logger.debug("Output queue empty, main thread waiting...")
            time.sleep(0.5) # Short sleep to avoid busy-waiting
            # Check if all workers have finished
            active_workers = sum(1 for w in worker_threads if w.is_alive())
            if active_workers == 0:
                break # All workers finished and queues are empty
        except Exception as e:
            logger.error(f"Error collecting results: {e}")
            break

    # Ensure all workers are truly terminated
    for worker in worker_threads:
        if worker.is_alive():
            worker.terminate()
            worker.join()

    verify_process.terminate()
    verify_process.join()

    logger.info("SubBrute bruteforce finished.")
    
    # If run standalone, return the found subdomains
    if subdomains_list is None:
        return sorted(list(set(found_subdomains)), key=subdomain_sorting_key)
    else:
        # If run as part of sublist3r.py, the shared list `subdomains_list` is already updated.
        pass


if __name__ == "__main__":
    # This block will run only if subbrute.py is executed directly.
    # When run via sublist3r.py, the main() function of subbrute is called directly.
    # The arguments would typically be parsed by sublist3r.py's main.

    # Simplified argument parsing for standalone execution
    parser = optparse.OptionParser("usage: %prog [options] target")
    parser.add_option("-s", "--subs", dest="subs", default="names.txt", type="string",
                      help="(optional) list of subdomains, default = 'names.txt'")
    parser.add_option("-r", "--resolvers", dest="resolvers", default="resolvers.txt", type="string",
                      help="(optional) A list of DNS resolvers, if this list is empty it will OS's internal resolver default = 'resolvers.txt'")
    parser.add_option("-t", "--targets_file", dest="targets", default="", type="string",
                      help="(optional) A list of targets to enumerate.")
    parser.add_option("-p", "--processes", dest="processes", default=multiprocessing.cpu_count() * 4, type="int",
                      help="(optional) Number of processes to employ, default = CPU_COUNT * 4")
    parser.add_option("-o", "--output", dest="output", default="", type="string",
                      help="(optional) Output json file.")
    parser.add_option("-v", "--ipv4", dest="ipv4", default=False, action="store_true",
                      help="(optional) Only lookup for IPv4 A records.")
    parser.add_option("-T", "--type", dest="type", default=False, type="string",
                      help="(optional) Lookup for a specific record type (A, AAAA, CNAME, NS, MX, TXT).")

    (options, args) = parser.parse_args()

    if len(args) != 1 and not options.targets:
        parser.error("You must provide a target domain or a file with targets.")
        sys.exit(1)
    
    target_domains = []
    if options.targets:
        try:
            with open(options.targets, 'r') as f:
                target_domains = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            logger.error(f"Target file '{options.targets}' not found.")
            sys.exit(1)
    else:
        target_domains = [args[0]]

    for target_domain in target_domains:
        logger.info(f"Starting bruteforce for: {target_domain}")
        # Call the main logic of subbrute.py
        # For standalone, we pass subdomains_list=None so it populates its own list.
        # This will be sorted and returned from main().
        found_subs = main(target_domain, output=options.output, threads=options.processes, 
                          ipv4_only=options.ipv4, subdomains_list=None) 
        if found_subs:
            logger.info(f"Found {len(found_subs)} subdomains for {target_domain}:")
            for sub in found_subs:
                logger.info(sub)