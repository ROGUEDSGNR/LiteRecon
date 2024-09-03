
# Lite Recon Documentation

## Overview

**Lite Recon** is a Python-based reconnaissance tool designed to gather information about domain names and IP addresses. It performs WHOIS lookups, DNS record retrievals, reverse DNS lookups, reverse IP lookups, geolocation fetches, and web scraping for emails. The tool features a rotating loader during processing to enhance user experience and provides clear, color-coded outputs for easy interpretation.

## Features

- **WHOIS Lookup**: Retrieves domain registration details.
- **DNS Records**: Collects A, MX, NS, TXT, and CNAME records for domains.
- **Reverse DNS Lookup**: Resolves IP addresses to their associated domain names.
- **Reverse IP Lookup**: Identifies other domains hosted on the same IP address.
- **Geolocation**: Obtains geographical information for IP addresses.
- **Email Scraping**: Extracts email addresses from websites.
- **Rotating Loader**: Displays a rotating loader during data processing.
- **Input Validation**: Ensures user input is valid for domain name or IP address.

## Installation

Ensure Python is installed on your system. Then, install the required dependencies with the following command:

```bash
pip install python-whois dnspython requests beautifulsoup4 colorama
```

## Usage

Run the script using Python:

```bash
python literecon.py
```

### Input

- **Domain Name**: Enter a valid domain name, e.g., `example.com`.
- **IP Address**: Enter a valid IP address, e.g., `192.168.1.1`.

The script validates the input and prompts the user to re-enter if the input is invalid.

### Output

Lite Recon provides a detailed report with the following sections:

- **Domain Information (WHOIS)**
- **DNS Information**: A, MX, NS, TXT, and CNAME records
- **Reverse DNS Lookup**
- **Domains Hosted on the Server**
- **Server Geolocation**
- **Emails Found**

**Color Coding**:
- **Valid Data**: Shown in green or white.
- **Missing or Error Data**: Shown in grey.

## Script Details

### Functions

- **`is_ip_address(input_str)`**: Checks if the input is a valid IP address.
- **`is_valid_domain(domain)`**: Checks if the input is a valid domain name.
- **`domain_info(domain)`**: Performs a WHOIS lookup on the domain.
- **`dns_info(domain)`**: Retrieves DNS records for the domain.
- **`reverse_dns_lookup(ip)`**: Performs a reverse DNS lookup on an IP address.
- **`reverse_ip_domains(ip)`**: Finds domains hosted on the same IP address.
- **`web_scraping(domain)`**: Scrapes websites for email addresses.
- **`get_geolocation(ip)`**: Fetches geolocation data for IP addresses.
- **`print_report(input_value, report_data)`**: Prints the gathered reconnaissance report.
- **`loader()`**: Displays a rotating loader while processing.
- **`start_loader()`**: Starts the loader in a separate thread.
- **`stop_loader(thread)`**: Stops the loader.

### Validation

The script includes checks to ensure valid input:
- Verifies that input is not blank.
- Confirms the input is a valid IP address or domain name.
- Prompts the user until valid input is provided.

## Example

[Images Coming Soon]

## Error Handling

The script includes error handling for:
- Invalid domain or IP address inputs.
- Network-related issues during API requests.
- Missing or empty data in responses.

## Contribution

Contributions are welcome! You can submit issues or pull requests on GitHub to improve Lite Recon.

## License

This project is licensed under the MIT License.
