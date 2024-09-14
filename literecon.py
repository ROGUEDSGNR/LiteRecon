#!/usr/bin/env python3
# LiteRecon Tool
# Developed by: [Your Name]
# Version: 2.0

import whois
import dns.resolver
import requests
from bs4 import BeautifulSoup
import re
import ipaddress
import argparse
import logging
import threading
import time
import sys
import textwrap

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('literecon.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

try:
    from colorama import Back, Fore, Style, init
    init(autoreset=True)
except ImportError:
    # Define colorama placeholders if not installed
    class Style:
        RESET_ALL = ''
    class Fore:
        RED = ''
        GREEN = ''
        BLUE = ''
        CYAN = ''
        YELLOW = ''
        LIGHTBLACK_EX = ''
        LIGHTWHITE_EX = ''
    class Back:
        RED = ''
        GREEN = ''
    def init():
        pass

# Global variable to control loader
loading = [False]

def loader(loading):
    """
    A simple rotating loader to show while processing.
    """
    while loading[0]:
        for c in '-\\|/':
            if not loading[0]:
                break
            print(f'\r{Fore.GREEN}{c} {Style.RESET_ALL}', end='', flush=True)
            time.sleep(0.1)
    print('\r', end='', flush=True)

def start_loader(loading):
    """
    Start the loader in a separate thread.
    """
    loading[0] = True
    t = threading.Thread(target=loader, args=(loading,))
    t.start()
    return t

def stop_loader(loading, thread):
    """
    Stop the loader.
    """
    loading[0] = False
    thread.join()

def is_ip_address(input_str):
    """
    Check if the input string is a valid IP address.
    """
    try:
        ipaddress.ip_address(input_str)
        return True
    except ValueError:
        return False

def is_valid_domain(domain):
    """
    Check if the input string is a valid domain name.
    """
    domain_pattern = re.compile(
        r"^(?:[a-zA-Z0-9]"
        r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,}$"
    )
    return domain_pattern.match(domain) is not None

def domain_info(domain):
    """
    Perform WHOIS lookup on a domain.
    """
    try:
        w = whois.whois(domain)
        return w
    except Exception as e:
        logging.error(f"WHOIS lookup failed for {domain}: {e}")
        return f"WHOIS lookup failed: {e}"

def dns_info(domain):
    """
    Gather DNS information for a domain.
    """
    dns_records = {}
    record_types = ['A', 'MX', 'NS', 'TXT', 'CNAME']
    for record in record_types:
        try:
            answers = dns.resolver.resolve(domain, record, lifetime=5)
            dns_records[record] = [str(rdata) for rdata in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
            dns_records[record] = []
        except Exception as e:
            dns_records[record] = [f"Error retrieving {record} record: {str(e)}"]
    return dns_records

def reverse_dns_lookup(ip):
    """
    Perform reverse DNS lookup on an IP address.
    """
    try:
        result = dns.resolver.resolve_address(ip, lifetime=5)
        return str(result[0])
    except Exception as e:
        logging.error(f"Reverse DNS lookup failed for {ip}: {e}")
        return f"Reverse DNS lookup failed: {e}"

def reverse_ip_domains(ip):
    """
    Perform reverse IP lookup to find domains hosted on the same server.
    """
    # Note: This function uses an external API and may have rate limits.
    # Use responsibly and consider alternative methods if necessary.
    try:
        response = requests.get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}", timeout=10)
        if response.status_code == 200:
            domains = response.text.strip().splitlines()
            if "error" in domains[0].lower():
                logging.error(f"Error in reverse IP lookup: {domains[0]}")
                return f"Error in reverse IP lookup: {domains[0]}"
            return domains
        else:
            logging.error(f"Unable to fetch domains hosted on the server for IP {ip}")
            return f"Error: Unable to fetch domains hosted on the server for IP {ip}"
    except Exception as e:
        logging.error(f"Reverse IP lookup failed for {ip}: {e}")
        return f"Reverse IP lookup failed: {e}"

def get_geolocation(ip):
    """
    Get geolocation data for an IP address.
    """
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=10)
        if response.status_code == 200:
            geo_info = response.json()
            return geo_info
        else:
            logging.error(f"Unable to fetch geolocation data for IP {ip}")
            return f"Error: Unable to fetch geolocation data for IP {ip}"
    except Exception as e:
        logging.error(f"Geolocation lookup failed for {ip}: {e}")
        return f"Geolocation lookup failed: {e}"

def web_scraping(domain):
    """
    Scrape a website for emails.
    """
    emails = set()
    headers = {'User-Agent': 'Mozilla/5.0'}
    schemes = ['http', 'https']
    email_regex = re.compile(
        r"(?:[a-zA-Z0-9!'#$%&'*+/=?^_`{|}~-]+"
        r"(?:\.[a-zA-Z0-9!'#$%&'*+/=?^_`{|}~-]+)*"
        r'|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-'
        r'\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@'
        r"(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}"
        r"[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}\.?|"
        r"\[(?:(?:[01]?\d\d?|2[0-4]\d|25[0-5])\.){3}"
        r"(?:[01]?\d\d?|2[0-4]\d|25[0-5])\])"
    )

    for scheme in schemes:
        url = f"{scheme}://{domain}"
        try:
            response = robust_request(url, headers)
            if response and response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')

                # Extract emails from visible text using regex
                text = soup.get_text()
                new_emails = set(email_regex.findall(text))
                emails.update(new_emails)
            else:
                logging.info(f"Unable to access {url}")
        except Exception as e:
            logging.error(f"Error scraping {url}: {e}")
            continue

    return emails if emails else "No emails found or an error occurred."

def robust_request(url, headers, retries=3):
    """
    Make a robust HTTP GET request with retries.
    """
    for attempt in range(retries):
        try:
            response = requests.get(url, headers=headers, timeout=10)
            return response
        except requests.exceptions.RequestException as e:
            if attempt == retries - 1:
                logging.error(f"Failed to retrieve {url}: {e}")
                return None
            time.sleep(2)

def print_wrapped(text, indent=0):
    """
    Print text with word wrapping.
    """
    wrapper = textwrap.TextWrapper(width=70, subsequent_indent=' ' * indent)
    print(wrapper.fill(text))

def print_report(input_value, report_data, use_color=True):
    """
    Print the gathered reconnaissance report.
    """
    if use_color:
        print(f"\n{Back.RED + Fore.BLACK} Lite Recon Report for {Fore.CYAN}{input_value} {Style.RESET_ALL}\n")
    else:
        print(f"\nLite Recon Report for {input_value}\n")

    if 'whois' in report_data:
        title = "--> Domain Information (WHOIS)"
        print(f"{Fore.YELLOW}{title}{Style.RESET_ALL}" if use_color else title)
        whois_data = report_data['whois']
        if isinstance(whois_data, dict):
            for key, value in whois_data.items():
                if value:
                    print(f"{Fore.GREEN}{key}: {Fore.LIGHTWHITE_EX}{value}{Style.RESET_ALL}" if use_color else f"{key}: {value}")
                else:
                    print(f"{Fore.LIGHTBLACK_EX}{key}: Not available{Style.RESET_ALL}" if use_color else f"{key}: Not available")
        else:
            print(Fore.LIGHTBLACK_EX + str(whois_data) + Style.RESET_ALL if use_color else str(whois_data))
        print("")

    if 'dns' in report_data:
        title = "--> DNS Information"
        print(f"{Fore.YELLOW}{title}{Style.RESET_ALL}" if use_color else title)
        for record_type, records in report_data['dns'].items():
            if records:
                print(f"{Fore.GREEN}{record_type} Records:{Style.RESET_ALL}" if use_color else f"{record_type} Records:")
                if isinstance(records, list):
                    for record in records:
                        print(f"  - {Fore.LIGHTWHITE_EX}{record}{Style.RESET_ALL}" if use_color else f"  - {record}")
                else:
                    print(f"  - {Fore.LIGHTBLACK_EX}{records}{Style.RESET_ALL}" if use_color else f"  - {records}")
            else:
                print(f"{Fore.LIGHTBLACK_EX}{record_type} Records: None found{Style.RESET_ALL}" if use_color else f"{record_type} Records: None found")
        print("")

    if 'reverse_dns' in report_data:
        title = "--> Reverse DNS Lookup"
        print(f"{Fore.YELLOW}{title}{Style.RESET_ALL}" if use_color else title)
        reverse_dns_result = report_data['reverse_dns']
        if reverse_dns_result:
            print(Fore.GREEN + reverse_dns_result + Style.RESET_ALL if use_color else reverse_dns_result)
        else:
            print(Fore.LIGHTBLACK_EX + "No reverse DNS records found." + Style.RESET_ALL if use_color else "No reverse DNS records found.")
        print("")

    if 'reverse_ip_domains' in report_data:
        title = "--> Domains Hosted on the Server"
        print(f"{Fore.YELLOW}{title}{Style.RESET_ALL}" if use_color else title)
        domains = report_data['reverse_ip_domains']
        if isinstance(domains, list) and domains:
            for domain in domains:
                print(f"  - {Fore.LIGHTWHITE_EX}{domain}{Style.RESET_ALL}" if use_color else f"  - {domain}")
        else:
            print(Fore.LIGHTBLACK_EX + "No domains found or an error occurred." + Style.RESET_ALL if use_color else "No domains found or an error occurred.")
        print("")

    if 'geolocation' in report_data:
        title = "--> Server Geolocation"
        print(f"{Fore.YELLOW}{title}{Style.RESET_ALL}" if use_color else title)
        geo_info = report_data['geolocation']
        if isinstance(geo_info, dict) and geo_info:
            for key, value in geo_info.items():
                print(f"  {Fore.LIGHTWHITE_EX}{key}: {value}{Style.RESET_ALL}" if use_color else f"  {key}: {value}")
        else:
            print(Fore.LIGHTBLACK_EX + "Geolocation data not available." + Style.RESET_ALL if use_color else "Geolocation data not available.")
        print("")

    if 'emails' in report_data:
        title = "--> Emails Found"
        print(f"{Fore.YELLOW}{title}{Style.RESET_ALL}" if use_color else title)
        emails = report_data['emails']
        if isinstance(emails, set) and emails:
            for email in emails:
                print(f"  - {Fore.LIGHTWHITE_EX}{email}{Style.RESET_ALL}" if use_color else f"  - {email}")
        else:
            print(Fore.LIGHTBLACK_EX + "No emails found or an error occurred." + Style.RESET_ALL if use_color else "No emails found or an error occurred.")
        print("")

def threaded_function(target, args, result_dict, key):
    """
    Run a function in a thread and store the result.
    """
    result_dict[key] = target(*args)

class LiteRecon:
    """
    LiteRecon Tool Class
    """

    def __init__(self, input_value):
        self.input_value = input_value
        self.report_data = {}
        self.use_color = True

    def perform_recon(self):
        """
        Perform reconnaissance based on input type.
        """
        loader_thread = start_loader(loading)  # Start the loader
        threads = []
        try:
            if is_ip_address(self.input_value):
                functions = [
                    (reverse_dns_lookup, (self.input_value,), 'reverse_dns'),
                    (reverse_ip_domains, (self.input_value,), 'reverse_ip_domains'),
                    (get_geolocation, (self.input_value,), 'geolocation')
                ]
            else:
                domain = self.input_value
                functions = [
                    (domain_info, (domain,), 'whois'),
                    (dns_info, (domain,), 'dns'),
                    (web_scraping, (domain,), 'emails'),
                ]

            for func, args, key in functions:
                thread = threading.Thread(target=threaded_function, args=(func, args, self.report_data, key))
                thread.start()
                threads.append(thread)

            # Wait for all threads to complete
            for thread in threads:
                thread.join()

            # If domain, get geolocation of the server IP
            if 'dns' in self.report_data and 'A' in self.report_data['dns'] and self.report_data['dns']['A']:
                server_ip = self.report_data['dns']['A'][0]
                self.report_data['geolocation'] = get_geolocation(server_ip)

        finally:
            stop_loader(loading, loader_thread)  # Stop the loader

    def generate_report(self):
        """
        Generate and print the reconnaissance report.
        """
        print_report(self.input_value, self.report_data, self.use_color)

def parse_arguments():
    """
    Parse command-line arguments.
    """
    parser = argparse.ArgumentParser(description='Lite Recon Tool')
    parser.add_argument('target', help='Domain or IP address to scan')
    parser.add_argument('--no-color', action='store_true', help='Disable colored output')
    args = parser.parse_args()
    return args

def main():
    """
    Main function to run the LiteRecon tool.
    """
    print("This tool is intended for authorized use only. Please ensure you have permission to perform reconnaissance on the target domain or IP address.\n")
    args = parse_arguments()
    input_value = args.target.strip()
    recon = LiteRecon(input_value)
    if args.no_color:
        recon.use_color = False
    recon.perform_recon()
    recon.generate_report()
    if recon.use_color:
        print(f"\n{Fore.RED} Lite Recon Done. Godspeed! ❤ \n")
    else:
        print("\nLite Recon Done. Godspeed!\n")

if __name__ == "__main__":
    main()
