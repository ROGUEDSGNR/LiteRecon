import whois
import dns.resolver
import requests
from bs4 import BeautifulSoup
import re
from colorama import Back, Fore, Style, init
from threading import Thread
import itertools
import time
import sys

# Initialize colorama
init(autoreset=True)

# Global variable to control loader
loading = False

def loader():
    """
    A simple rotating loader to show while processing.
    """
    for c in itertools.cycle(['|', '/', '-', '\\']):
        if not loading:
            break
        sys.stdout.write(f'\r{Fore.GREEN}{c} {Style.RESET_ALL}')
        sys.stdout.flush()
        time.sleep(0.1)

def start_loader():
    """
    Start the loader in a separate thread.
    """
    global loading
    loading = True
    t = Thread(target=loader)
    t.start()
    return t

def stop_loader(thread):
    """
    Stop the loader.
    """
    global loading
    loading = False
    thread.join()
    sys.stdout.write('\r')
    sys.stdout.flush()

def is_ip_address(input_str):
    """
    Check if the input string is a valid IP address.
    """
    ip_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    return ip_pattern.match(input_str) is not None

def is_valid_domain(domain):
    """
    Check if the input string is a valid domain name.
    """
    domain_pattern = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.(?!-)[A-Za-z]{2,6}$")
    return domain_pattern.match(domain) is not None

def domain_info(domain):
    """
    Perform WHOIS lookup on a domain.
    """
    try:
        w = whois.whois(domain)
        return w
    except Exception as e:
        return str(e)

def dns_info(domain):
    """
    Gather DNS information for a domain.
    """
    dns_records = {}
    try:
        for record in ['A', 'MX', 'NS', 'TXT', 'CNAME']:
            answers = dns.resolver.resolve(domain, record)
            dns_records[record] = [str(rdata) for rdata in answers]
    except Exception as e:
        dns_records['error'] = str(e)
    return dns_records

def reverse_dns_lookup(ip):
    """
    Perform reverse DNS lookup on an IP address.
    """
    try:
        result = dns.resolver.resolve_address(ip)
        return str(result[0])
    except Exception as e:
        return f"Reverse DNS lookup failed: {str(e)}"

def reverse_ip_domains(ip):
    """
    Perform reverse IP lookup to find domains hosted on the same server.
    """
    try:
        response = requests.get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}")
        if response.status_code == 200:
            domains = response.text.strip().splitlines()
            if "error" in domains[0].lower():
                return f"Error in reverse IP lookup: {domains[0]}"
            return domains
        else:
            return f"Error: Unable to fetch domains hosted on the server for IP {ip}"
    except Exception as e:
        return str(e)

def web_scraping(domain):
    """
    Scrape a website for emails, trying both HTTP and HTTPS.
    """
    emails = set()
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
    
    for scheme in ['http', 'https']:
        try:
            url = f"{scheme}://{domain}"
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Extract emails from mailto links
                mailto_links = {a['href'].replace('mailto:', '') for a in soup.find_all('a', href=True) if 'mailto:' in a['href']}
                emails.update(mailto_links)
                
                # Extract emails from visible text using regex
                text_emails = set(re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", response.text))
                emails.update(text_emails)
                
        except Exception as e:
            print(f"{Fore.RED}Error scraping {url}: {e}{Style.RESET_ALL}")

    return emails if emails else "No emails found or an error occurred."

def get_geolocation(ip):
    """
    Get geolocation data for an IP address.
    """
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        if response.status_code == 200:
            geo_info = response.json()
            return geo_info
        else:
            return f"Error: Unable to fetch geolocation data for IP {ip}"
    except Exception as e:
        return str(e)

def print_report(input_value, report_data):
    """
    Print the gathered reconnaissance report.
    """
    print(f"\n{Back.RED + Fore.BLACK} Lite Recon Report for {Fore.CYAN}{input_value} {Style.RESET_ALL}\n")

    if 'whois' in report_data:
        print(f"{Fore.YELLOW}--> Domain Information (WHOIS){Style.RESET_ALL}")
        whois_data = report_data['whois']
        if isinstance(whois_data, dict):
            for key, value in whois_data.items():
                if value:
                    print(f"{Fore.GREEN}{key}: {Fore.LIGHTBLACK_EX if not value else Fore.LIGHTWHITE_EX}{value}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.LIGHTBLACK_EX}{key}: Not available{Style.RESET_ALL}")
        else:
            print(Fore.LIGHTBLACK_EX + str(whois_data) + Style.RESET_ALL)
        print("")

    if 'dns' in report_data:
        print(f"{Fore.YELLOW}--> DNS Information{Style.RESET_ALL}")
        for record_type, records in report_data['dns'].items():
            if records:
                print(f"{Fore.GREEN}{record_type} Records:{Style.RESET_ALL}")
                if isinstance(records, list):
                    for record in records:
                        print(f"  - {Fore.LIGHTWHITE_EX if record else Fore.LIGHTBLACK_EX}{record}{Style.RESET_ALL}")
                else:
                    print(f"  - {Fore.LIGHTBLACK_EX}{records}{Style.RESET_ALL}")
            else:
                print(f"{Fore.LIGHTBLACK_EX}{record_type} Records: None found{Style.RESET_ALL}")
        print("")

    if 'reverse_dns' in report_data:
        print(f"{Fore.YELLOW}--> Reverse DNS Lookup{Style.RESET_ALL}")
        reverse_dns_result = report_data['reverse_dns']
        if reverse_dns_result:
            print(Fore.GREEN + reverse_dns_result + Style.RESET_ALL)
        else:
            print(Fore.LIGHTBLACK_EX + "No reverse DNS records found." + Style.RESET_ALL)
        print("")

    if 'reverse_ip_domains' in report_data:
        print(f"{Fore.YELLOW}--> Domains Hosted on the Server{Style.RESET_ALL}")
        domains = report_data['reverse_ip_domains']
        if isinstance(domains, list) and domains:
            for domain in domains:
                print(f"  - {Fore.LIGHTWHITE_EX}{domain}{Style.RESET_ALL}")
        else:
            print(Fore.LIGHTBLACK_EX + "No domains found or an error occurred." + Style.RESET_ALL)
        print("")

    if 'geolocation' in report_data:
        print(f"{Fore.YELLOW}--> Server Geolocation{Style.RESET_ALL}")
        geo_info = report_data['geolocation']
        if isinstance(geo_info, dict) and geo_info:
            for key, value in geo_info.items():
                print(f"  {Fore.LIGHTWHITE_EX if value else Fore.LIGHTBLACK_EX}{key}: {value}{Style.RESET_ALL}")
        else:
            print(Fore.LIGHTBLACK_EX + "Geolocation data not available." + Style.RESET_ALL)
        print("")

    if 'emails' in report_data:
        print(f"{Fore.YELLOW}--> Emails Found{Style.RESET_ALL}")
        emails = report_data['emails']
        if isinstance(emails, set) and emails:
            for email in emails:
                print(f"  - {Fore.LIGHTWHITE_EX}{email}{Style.RESET_ALL}")
        else:
            print(Fore.LIGHTBLACK_EX + "No emails found or an error occurred." + Style.RESET_ALL)
        print("")

def main(input_value):
    # Validate input: ensure it is not blank and is either a valid IP or domain
    while not input_value or (not is_ip_address(input_value) and not is_valid_domain(input_value)):
        print(f"{Fore.RED}Invalid input. Please enter a valid domain name or IP address.{Style.RESET_ALL}")
        input_value = input(Fore.BLUE + "Enter the domain name or IP address:" + Style.RESET_ALL).strip()

    report_data = {}
    loader_thread = start_loader()  # Start the loader

    try:
        if is_ip_address(input_value):
            print(f"Input is an IP address: {input_value}")
            print(f"Performing reverse DNS lookup...")
            report_data['reverse_dns'] = reverse_dns_lookup(input_value)
            
            print(f"Fetching domains hosted on the server...")
            report_data['reverse_ip_domains'] = reverse_ip_domains(input_value)

            print(f"Fetching server geolocation...")
            report_data['geolocation'] = get_geolocation(input_value)
        else:
            domain = input_value
            print(f"Gathering WHOIS information for {domain}...")
            report_data['whois'] = domain_info(domain)
            
            print(f"Gathering DNS information for {domain}...")
            report_data['dns'] = dns_info(domain)
            
            print(f"Scraping website for emails...")
            report_data['emails'] = web_scraping(domain)
            
            if 'A' in report_data['dns']:
                server_ip = report_data['dns']['A'][0]
                print(f"Fetching server geolocation for {server_ip}...")
                report_data['geolocation'] = get_geolocation(server_ip)
    finally:
        stop_loader(loader_thread)  # Stop the loader

    print(f"Printing the report...\n")
    print_report(input_value, report_data)
    
    print(f"\n{Fore.RED} Lite Recon Done. Godspeed! ❤ \n")

if __name__ == "__main__":
    print(f"\n{Back.GREEN + Fore.BLACK} ⋆R⋆O⋆G⋆U⋆E⋆DSGNR⋆ ⋆A⋆R⋆M⋆Y⋆K⋆N⋆I⋆F⋆E⋆ {Style.RESET_ALL}\n")
    input_value = input(Fore.BLUE + "Enter the domain name or IP address:" + Style.RESET_ALL).strip()
    main(input_value)
