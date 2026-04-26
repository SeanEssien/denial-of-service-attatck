# SOFT2202 Formal Element Assignment
# Author: SeanEssien
# Date: April 2026
# DDoS Log Analyzer - Complete Program (Parts 1-4)

import ipwhois


# ============ PART 1: Extract IP Addresses ============

def is_valid_ip(ip):
    """Check if a string is a valid IPv4 address"""
    parts = ip.split('.')
    
    if len(parts) != 4:
        return False
    
    for part in parts:
        if not part.isdigit():
            return False
        num = int(part)
        if num < 0 or num > 255:
            return False
    
    return True


def extract_ips_from_file(input_filename):
    """Read log file and extract unique IP addresses"""
    unique_ips = set()
    
    try:
        with open(input_filename, 'r') as file:
            for line in file:
                start = line.find("[client ")
                if start != -1:
                    after_client = line[start + 8:]
                    end = after_client.find("]")
                    if end != -1:
                        ip = after_client[:end]
                        if is_valid_ip(ip):
                            unique_ips.add(ip)
        
        print(f"Found {len(unique_ips)} unique IP addresses")
        return unique_ips
    
    except FileNotFoundError:
        print(f"Error: {input_filename} not found!")
        return set()


def save_unique_ips(ips, output_filename):
    """Save unique IPs to a file"""
    with open(output_filename, 'w') as file:
        file.write("Unique IP Addresses from DDoS Log\n")
        file.write("=" * 40 + "\n\n")
        for ip in sorted(ips):
            file.write(f"{ip}\n")
    print(f"Saved {len(ips)} unique IPs to {output_filename}")


# ============ PART 2: Classify IP Addresses ============

def classify_ip(ip):
    """Classify IP address as Class A, B, C, D, or E"""
    first_octet = int(ip.split('.')[0])
    
    if 1 <= first_octet <= 126:
        return "Class A"
    elif 128 <= first_octet <= 191:
        return "Class B"
    elif 192 <= first_octet <= 223:
        return "Class C"
    elif 224 <= first_octet <= 239:
        return "Class D (Multicast)"
    elif 240 <= first_octet <= 255:
        return "Class E (Reserved)"
    elif first_octet == 0:
        return "Class A (Zero - Reserved)"
    elif first_octet == 127:
        return "Class A (Loopback)"
    else:
        return "Unknown"


# ============ PART 3: Whois Lookup ============

def get_ip_info(ip):
    """Get country and description using whois lookup"""
    try:
        whois = ipwhois.IPWhois(ip)
        result = whois.lookup_rdap()
        
        country = result.get('asn_country_code', 'Unknown')
        description = result.get('asn_description', 'No description available')
        
        return country, description
    
    except Exception as e:
        return "Error", f"Lookup failed: {str(e)[:50]}"


# ============ PART 4: Generate Report ============

def generate_report(ips, output_filename):
    """Generate final report with all information"""
    
    with open(output_filename, 'w') as file:
        file.write("=" * 60 + "\n")
        file.write("DDoS ATTACK ANALYSIS REPORT\n")
        file.write("=" * 60 + "\n\n")
        
        for ip in sorted(ips):
            ip_class = classify_ip(ip)
            
            print(f"Looking up {ip}...")
            country, description = get_ip_info(ip)
            
            file.write(f"IP Address: {ip}\n")
            file.write(f"Class:      {ip_class}\n")
            file.write(f"Country:    {country}\n")
            file.write(f"Description: {description}\n")
            file.write("-" * 60 + "\n\n")
    
    print(f"\nReport saved to {output_filename}")


# ============ MAIN FUNCTION ============

def main():
    """Main function - coordinates all parts"""
    print("\n" + "=" * 50)
    print("DDoS LOG ANALYZER")
    print("=" * 50 + "\n")
    
    input_file = "DDoDRawLog.txt"
    unique_ips_file = "unique_ips.txt"
    report_file = "ddos_report.txt"
    
    # PART 1
    print("PART 1: Extracting IP addresses...")
    print("-" * 30)
    unique_ips = extract_ips_from_file(input_file)
    
    if len(unique_ips) == 0:
        print("No IP addresses found. Check if DDoDRawLog.txt exists!")
        return
    
    save_unique_ips(unique_ips, unique_ips_file)
    
    # PART 2, 3, 4
    print("\nPART 2 & 3: Classifying IPs and looking up whois info...")
    print("-" * 50)
    print("(This may take a while for many IPs...)\n")
    
    generate_report(unique_ips, report_file)
    
    # SUMMARY
    print("\n" + "=" * 50)
    print("SUMMARY")
    print("=" * 50)
    print(f"Total unique IPs found: {len(unique_ips)}")
    print(f"Unique IPs saved to: {unique_ips_file}")
    print(f"Full report saved to: {report_file}")
    print("=" * 50 + "\n")


# Run the program
if __name__ == "__main__":
    main()


   
