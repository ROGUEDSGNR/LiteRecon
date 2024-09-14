# Lite Recon Documentation (Version 2.0)

## Overview

Lite Recon is a Python-based reconnaissance tool designed to gather comprehensive information about domain names and IP addresses. This updated version enhances performance, usability, and reliability by introducing multithreading, improved input validation, better error handling, and additional features like command-line arguments and logging.

---

## What's New in Version 2.0

- **Improved Input Validation**: Enhanced domain and IP address validation using Python's built-in libraries.
- **Multithreading**: Network requests are handled concurrently, significantly improving performance.
- **Command-Line Interface (CLI)**: Added support for command-line arguments using `argparse`.
- **Logging**: Implemented logging to better track the tool's operations and errors.
- **Enhanced Error Handling**: Robust exception handling across all functions to ensure smooth execution.
- **Modular Code Structure**: Refactored into a class-based design for better maintainability and scalability.
- **Optional Colored Output**: Users can disable coloured output for better compatibility with different terminal environments.
- **Disclaimers and Usage Policies**: Added guidelines to promote ethical and authorized use of the tool.

---

## Features

- **WHOIS Lookup**: Retrieves domain registration details.
- **DNS Records Retrieval**: Collects A, MX, NS, TXT, and CNAME records for domains.
- **Reverse DNS Lookup**: Resolves IP addresses to their associated domain names.
- **Reverse IP Lookup**: Identifies other domains hosted on the same IP address.
- **Geolocation Fetching**: Obtains geographical information for IP addresses.
- **Email Scraping**: Extracts email addresses from websites.
- **Multithreading**: Performs network requests concurrently for faster results.
- **Logging**: Logs detailed information and errors to a file and console.
- **Command-Line Arguments**: Users can specify targets and options directly from the terminal.
- **Enhanced Output Formatting**: Provides clear, word-wrapped, and optionally color-coded outputs for easy interpretation.

---

## Installation

### Prerequisites

- **Python 3.6 or higher**: Ensure Python is installed on your system.

### Install Dependencies

1. **Clone the Repository** (if applicable):

   ```bash
   git clone https://github.com/ROGUEDSGNR/lite-recon.git
   cd literecon
   ```

2. **Install Required Packages**:

   Create a `requirements.txt` file (or use ours) with the following content:

   ```txt
   whois
   dnspython
   requests
   beautifulsoup4
   colorama
   ```

   Install the dependencies using pip:

   ```bash
   pip install -r requirements.txt
   ```

   Alternatively, you can install the packages individually:

   ```bash
   pip install whois dnspython requests beautifulsoup4 colorama
   ```

---

## Usage

### Basic Usage

Run the script using Python, specifying the target domain or IP address:

```bash
python literecon.py example.com
```

### Command-Line Arguments

- **Target**: The domain or IP address to scan.

- **Options**:
  - `--no-color`: Disable colored output in the terminal.

**Example**:

```bash
python literecon.py example.com --no-color
```

### Help

To display the help message with all available options:

```bash
python literecon.py -h
```

---

## Output

Lite Recon provides a detailed report with the following sections:

- **Domain Information (WHOIS)**
- **DNS Information**: A, MX, NS, TXT, and CNAME records.
- **Reverse DNS Lookup**
- **Domains Hosted on the Server**
- **Server Geolocation**
- **Emails Found**

### Color Coding (Optional)

- **Valid Data**: Shown in green or white.
- **Missing or Error Data**: Shown in grey.

---

## Example Output

```
Lite Recon Report for example.com

--> Domain Information (WHOIS)
domain_name: example.com
creation_date: 1995-08-14 04:00:00
...

--> DNS Information
A Records:
  - 93.184.216.34
MX Records:
  - ...

--> Reverse DNS Lookup
93.184.216.34.in-addr.arpa

--> Domains Hosted on the Server
  - example.com
  - ...

--> Server Geolocation
ip: 93.184.216.34
city: Los Angeles
region: California
country: US
...

--> Emails Found
  - admin@example.com

Lite Recon Done. Godspeed!
```

---

## Detailed Features

### Input Validation

- **Domain Validation**: Enhanced regex patterns ensure accurate validation of domain names.
- **IP Address Validation**: Utilizes the `ipaddress` module for reliable IP address validation.

### Multithreading

- **Concurrent Execution**: Network requests are handled in separate threads, reducing total execution time.

### Logging

- **Log File**: Detailed logs are saved to `literecon.log`.
- **Console Output**: Important messages and errors are displayed in the terminal.

### Modular Code Structure

- **Class-Based Design**: The `LiteRecon` class encapsulates all functionalities, making the code easier to maintain and extend.

### Command-Line Interface

- **Argparse Module**: Provides a robust and user-friendly command-line interface.
- **Optional Arguments**: Users can customize the tool's behaviour using flags and options.

### Enhanced Error Handling

- **Exception Handling**: All functions include try-except blocks to handle exceptions gracefully.
- **Retries**: Network requests implement retries to handle temporary failures.

---

## Ethical Use and Disclaimers

- **Authorized Use Only**: Ensure you have explicit permission to perform reconnaissance on the target domain or IP address.
- **Compliance**: Be aware of and comply with all applicable laws and regulations regarding data privacy and network scanning.
- **Responsibility**: The user assumes all responsibility for the use of this tool.

---

## Contribution

Contributions are welcome! You can submit issues or pull requests on [GitHub](https://github.com/ROGUEDSGNR/lite-recon) to improve Lite Recon.

---

## License

This project is licensed under the [MIT License](LICENSE).

---

## Support

For any questions or support, please contact [hello@roguedsgnr.com](mailto:hello@roguedsgnr.com)

---

## Troubleshooting

### Common Issues

- **ImportError**: If you encounter import errors, ensure all dependencies are installed correctly.
- **Network Errors**: Network-related errors may occur due to connectivity issues or API rate limits.

### Solutions

- **Dependency Installation**: Reinstall the dependencies using `pip install -r requirements.txt`.
- **API Rate Limits**: Wait for some time before retrying if you suspect rate limiting.
- **Permissions**: Run the script with appropriate permissions if required.

---

## Future Enhancements

- **Asynchronous Programming**: Implementing `asyncio` for even better performance.
- **Additional Modules**: Adding support for SSL certificate analysis and port scanning.
- **GUI Version**: Developing a graphical user interface for ease of use.

---

## Acknowledgements

- **Open-Source Libraries**: Thanks to the developers of `whois`, `dnspython`, `requests`, `beautifulsoup4`, and `colorama`.
- **Community Feedback**: Appreciation to users who provided feedback for improving Lite Recon.

---

## Important Notes

- **External Services**: Lite Recon uses external APIs (e.g., `hackertarget.com`, `ipinfo.io`) which may have usage limitations.
- **Data Accuracy**: The accuracy of the data retrieved depends on the external services and the availability of information.
- **Privacy**: Be cautious when handling sensitive data obtained through reconnaissance.

---

## Contact Information

- **Developer**: Your Name
- **Email**: [hello@roguedsgnr.com](mailto:hello@roguedsgnr.com)
- **GitHub**: [github.com/ROGUEDSGNR](https://github.com/ROGUEDSGNR/)

---

By using Lite Recon, you agree to use it responsibly and ethically, respecting all applicable laws and regulations.
