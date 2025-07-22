import whois
import socket
import dns.resolver
import requests
import datetime
from ipwhois import IPWhois
import ssl
import json

def get_domain_info(domain_name):
    try:
        domain_name = domain_name.replace('http://', '').replace('https://', '').split('/')[0]
        
        print(f"\n[+] Gathering information for: {domain_name}")
        print("="*60)
        
        print("\n[WHOIS INFORMATION]")
        print("-"*50)
        get_whois_info(domain_name)
        
        print("\n[DNS RECORDS]")
        print("-"*50)
        get_dns_records(domain_name)
        
        print("\n[IP INFORMATION]")
        print("-"*50)
        get_ip_info(domain_name)
        
        print("\n[SSL CERTIFICATE INFORMATION]")
        print("-"*50)
        get_ssl_info(domain_name)
        
        print("\n[HTTP HEADERS]")
        print("-"*50)
        get_http_headers(domain_name)
        
        print("\n[+] Information gathering complete")
        print("="*60)
        
    except Exception as e:
        print(f"Error: {e}")

def get_whois_info(domain):
    try:
        domain_info = whois.whois(domain)
        
        if isinstance(domain_info.text, str) and "Domain Name:" in domain_info.text:
            whois_text = domain_info.text
            
            fields_to_extract = [
                'Domain Name:', 'Registry Domain ID:', 'Registrar WHOIS Server:',
                'Registrar URL:', 'Updated Date:', 'Creation Date:', 
                'Registry Expiry Date:', 'Registrar:', 'Registrar IANA ID:',
                'Registrar Abuse Contact Email:', 'Registrar Abuse Contact Phone:',
                'Domain Status:', 'Name Server:', 'DNSSEC:'
            ]
            
            for line in whois_text.split('\n'):
                line = line.strip()
                if any(field in line for field in fields_to_extract):
                    print(line)
        else:
            print("\nWHOIS Information:")
            print("-"*50)
            
            print(f"Domain: {domain_info.domain_name}")
            print(f"Registrar: {domain_info.registrar}")
            
            if domain_info.creation_date:
                date = domain_info.creation_date[0] if isinstance(domain_info.creation_date, list) else domain_info.creation_date
                print(f"Creation Date: {date.strftime('%Y-%m-%d %H:%M:%S')}")
            
            if domain_info.expiration_date:
                date = domain_info.expiration_date[0] if isinstance(domain_info.expiration_date, list) else domain_info.expiration_date
                print(f"Expiration Date: {date.strftime('%Y-%m-%d %H:%M:%S')}")
                today = datetime.datetime.now()
                days_left = (date - today).days
                print(f"Days Until Expiration: {days_left}")
            
            if domain_info.updated_date:
                date = domain_info.updated_date[0] if isinstance(domain_info.updated_date, list) else domain_info.updated_date
                print(f"Last Updated: {date.strftime('%Y-%m-%d %H:%M:%S')}")
            
            if domain_info.name_servers:
                print("\nName Servers:")
                ns_list = domain_info.name_servers if isinstance(domain_info.name_servers, list) else [domain_info.name_servers]
                for ns in set(ns.upper() for ns in ns_list):
                    print(f"- {ns}")
            
            if hasattr(domain_info, 'name') or hasattr(domain_info, 'org'):
                print("\nRegistrant Info:")
                if domain_info.name:
                    print(f"Name: {domain_info.name}")
                if domain_info.org:
                    print(f"Organization: {domain_info.org}")
                if domain_info.country:
                    print(f"Country: {domain_info.country}")
            
            if domain_info.status:
                print("\nDomain Status:")
                status_list = domain_info.status if isinstance(domain_info.status, list) else [domain_info.status]
                for status in status_list:
                    print(f"- {status}")
    
    except Exception as e:
            if e.args and isinstance(e.args[0], str) and "Domain Name:" in e.args[0]:
                filter_and_print_whois_data(e.args[0])
            else:
                print(f"WHOIS lookup completely failed for {domain}")


def filter_and_print_whois_data(raw_data):
    relevant_fields = [
        'Domain Name:', 'Registry Domain ID:', 'Registrar WHOIS Server:',
        'Registrar URL:', 'Updated Date:', 'Creation Date:',
        'Registry Expiry Date:', 'Registrar:', 'Registrar IANA ID:',
        'Registrar Abuse Contact Email:', 'Registrar Abuse Contact Phone:',
        'Domain Status:', 'Name Server:', 'DNSSEC:'
    ]
    
    patterns = [
        r'Domain:\s*(.+)',
        r'Registrar:\s*(.+)',
        r'Creation Date:\s*(.+)',
        r'Expiration Date:\s*(.+)',
        r'Updated Date:\s*(.+)',
        r'Name Server:\s*(.+)',
        r'Status:\s*(.+)'
    ]
    
    found_data = False
    
    for line in raw_data.split('\n'):
        line = line.strip()
        if any(field in line for field in relevant_fields):
            print(line)
            found_data = True
    
    if not found_data:
        matches = {}
        for line in raw_data.split('\n'):
            line = line.strip()
            for pattern in patterns:
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    field = pattern.split(':')[0].strip()
                    value = match.group(1).strip()
                    matches[field] = value
        
        if matches:
            if 'Domain' in matches:
                print(f"Domain Name: {matches['Domain']}")
            if 'Registrar' in matches:
                print(f"Registrar: {matches['Registrar']}")
            if 'Creation Date' in matches:
                print(f"Creation Date: {matches['Creation Date']}")
            if 'Expiration Date' in matches:
                print(f"Expiration Date: {matches['Expiration Date']}")
            if 'Updated Date' in matches:
                print(f"Updated Date: {matches['Updated Date']}")
            if 'Name Server' in matches:
                print("\nName Servers:")
                print(f"- {matches['Name Server']}")
            if 'Status' in matches:
                print(f"\nDomain Status: {matches['Status']}")
        else:
            print("No parsable WHOIS information found")

def display_structured_whois(domain_info):
    print(f"Domain: {domain_info.domain_name}")
    print(f"Registrar: {domain_info.registrar}")
    
    if domain_info.creation_date:
        date = domain_info.creation_date[0] if isinstance(domain_info.creation_date, list) else domain_info.creation_date
        print(f"Creation Date: {date.strftime('%Y-%m-%d %H:%M:%S')}")
    
    if domain_info.expiration_date:
        date = domain_info.expiration_date[0] if isinstance(domain_info.expiration_date, list) else domain_info.expiration_date
        print(f"Expiration Date: {date.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Days Until Expiration: {(date - datetime.datetime.now()).days}")
    
    if domain_info.name_servers:
        print("\nName Servers:")
        for ns in set(ns.upper() for ns in (domain_info.name_servers if isinstance(domain_info.name_servers, list) else [domain_info.name_servers])):
            print(f"- {ns}")
    
    if domain_info.status:
        print("\nDomain Status:")
        for status in (domain_info.status if isinstance(domain_info.status, list) else [domain_info.status]):
            print(f"- {status}")



def get_dns_records(domain):
    try:
        try:
            a_records = dns.resolver.resolve(domain, 'A')
            print("\nA Records:")
            for record in a_records:
                print(f"- {record.address}")
        except:
            pass
        
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            print("\nMX Records:")
            for record in mx_records:
                print(f"- {record.exchange} (Priority: {record.preference})")
        except:
            pass
        
        try:
            ns_records = dns.resolver.resolve(domain, 'NS')
            print("\nNS Records:")
            for record in ns_records:
                print(f"- {record.target}")
        except:
            pass
        
        try:
            txt_records = dns.resolver.resolve(domain, 'TXT')
            print("\nTXT Records:")
            for record in txt_records:
                print(f"- {record.strings}")
        except:
            pass
        
        try:
            cname_records = dns.resolver.resolve(domain, 'CNAME')
            print("\nCNAME Records:")
            for record in cname_records:
                print(f"- {record.target}")
        except:
            pass
    
    except Exception as e:
        print(f"DNS lookup failed: {e}")

def get_ip_info(domain):
    try:
        ip_list = []
        try:
            addrinfo = socket.getaddrinfo(domain, None)
            for info in addrinfo:
                ip = info[4][0]
                if ip not in ip_list:
                    ip_list.append(ip)
            
            print("\nIP Addresses:")
            for ip in ip_list:
                print(f"- {ip}")
                
                try:
                    obj = IPWhois(ip)
                    results = obj.lookup_rdap()
                    
                    print(f"  - ASN: {results.get('asn', 'N/A')}")
                    print(f"  - ASN Description: {results.get('asn_description', 'N/A')}")
                    print(f"  - Network: {results.get('network', {}).get('cidr', 'N/A')}")
                    print(f"  - Country: {results.get('asn_country_code', 'N/A')}")
                    
                except:
                    print("  - IP WHOIS lookup failed")
                    
        except:
            print("IP address resolution failed")
        
        if ip_list:
            try:
                response = requests.get(f"http://ip-api.com/json/{ip_list[0]}?fields=status,message,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,reverse,mobile,proxy,hosting,query")
                geo_data = response.json()
                
                if geo_data.get('status') == 'success':
                    print("\nGeolocation Info:")
                    print(f"- Country: {geo_data.get('country', 'N/A')} ({geo_data.get('countryCode', 'N/A')})")
                    print(f"- Region: {geo_data.get('regionName', 'N/A')} ({geo_data.get('region', 'N/A')})")
                    print(f"- City: {geo_data.get('city', 'N/A')}")
                    print(f"- ZIP: {geo_data.get('zip', 'N/A')}")
                    print(f"- Coordinates: {geo_data.get('lat', 'N/A')}, {geo_data.get('lon', 'N/A')}")
                    print(f"- Timezone: {geo_data.get('timezone', 'N/A')}")
                    print(f"- ISP: {geo_data.get('isp', 'N/A')}")
                    print(f"- Organization: {geo_data.get('org', 'N/A')}")
                    print(f"- AS: {geo_data.get('as', 'N/A')}")
                    print(f"- Reverse DNS: {geo_data.get('reverse', 'N/A')}")
                    print(f"- Mobile: {'Yes' if geo_data.get('mobile') else 'No'}")
                    print(f"- Proxy: {'Yes' if geo_data.get('proxy') else 'No'}")
                    print(f"- Hosting: {'Yes' if geo_data.get('hosting') else 'No'}")
            except:
                print("Geolocation lookup failed")
    
    except Exception as e:
        print(f"IP information gathering failed: {e}")

def get_ssl_info(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
                print("\nSSL Certificate Info:")
                print(f"- Issuer: {dict(x[0] for x in cert['issuer'])}")
                print(f"- Subject: {dict(x[0] for x in cert['subject'])}")
                print(f"- Version: {cert.get('version', 'N/A')}")
                print(f"- Serial Number: {cert.get('serialNumber', 'N/A')}")
                print(f"- Valid From: {cert['notBefore']}")
                print(f"- Valid Until: {cert['notAfter']}")
                
                not_after = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                if datetime.datetime.now() > not_after:
                    print("- Status: EXPIRED")
                else:
                    print("- Status: VALID")
                
                if 'subjectAltName' in cert:
                    print("\nSubject Alternative Names:")
                    for san in cert['subjectAltName']:
                        print(f"- {san[0]}: {san[1]}")
    
    except Exception as e:
        print(f"SSL certificate check failed: {e}")

def get_http_headers(domain):
    try:
        url = f"http://{domain}" if not domain.startswith(('http://', 'https://')) else domain
        response = requests.get(url, timeout=10)
        
        print("\nHTTP Headers:")
        for header, value in response.headers.items():
            print(f"- {header}: {value}")
        
        print(f"\nHTTP Status Code: {response.status_code}")
        print(f"Server: {response.headers.get('Server', 'N/A')}")
        print(f"Content-Type: {response.headers.get('Content-Type', 'N/A')}")
        print(f"Content-Length: {response.headers.get('Content-Length', 'N/A')}")
        
        security_headers = [
            'Strict-Transport-Security',
            'Content-Security-Policy',
            'X-Frame-Options',
            'X-Content-Type-Options',
            'X-XSS-Protection',
            'Referrer-Policy'
        ]
        
        print("\nSecurity Headers:")
        for header in security_headers:
            value = response.headers.get(header, 'Not Present')
            print(f"- {header}: {value}")
    
    except Exception as e:
        print(f"HTTP headers check failed: {e}")

if __name__ == "__main__":
    print("""
    ██████╗  ██████╗ ███╗   ███╗ █████╗ ██╗███╗   ██╗
    ██╔══██╗██╔═══██╗████╗ ████║██╔══██╗██║████╗  ██║
    ██║  ██║██║   ██║██╔████╔██║███████║██║██╔██╗ ██║
    ██║  ██║██║   ██║██║╚██╔╝██║██╔══██║██║██║╚██╗██║
    ██████╔╝╚██████╔╝██║ ╚═╝ ██║██║  ██║██║██║ ╚████║
    ╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝
    """)
    print("Domain Information Gathering Tool")
    print("By Issam Belayachi")
    print("--------------------------------")
    domain = input("Enter domain name (e.g., example.com): ").strip()
    get_domain_info(domain)
