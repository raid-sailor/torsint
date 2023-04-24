#!/usr/bin/env python

import requests
import json
import csv
from colorama import Fore, Back, Style
import argparse
from rich import print
from rich.console import Console
from rich.table import Table
import time
from censys.search import CensysHosts
from censys.search import CensysCertificates
from dotenv import load_dotenv
import os 

load_dotenv()
console = Console()
api_urlscan = os.getenv("URLSCAN")
shodan_api = os.getenv("SHODAN")
greynoise_api = os.getenv("GREYNOISE")
whois_api = os.getenv("WHOIS")

def logo():

    print("""
▄▄▄█████▓ ▒█████   ██▀███    ██████  ██▓ ███▄    █ ▄▄▄█████▓
▓  ██▒ ▓▒▒██▒  ██▒▓██ ▒ ██▒▒██    ▒ ▓██▒ ██ ▀█   █ ▓  ██▒ ▓▒
▒ ▓██░ ▒░▒██░  ██▒▓██ ░▄█ ▒░ ▓██▄   ▒██▒▓██  ▀█ ██▒▒ ▓██░ ▒░
░ ▓██▓ ░ ▒██   ██░▒██▀▀█▄    ▒   ██▒░██░▓██▒  ▐▌██▒░ ▓██▓ ░ 
  ▒██▒ ░ ░ ████▓▒░░██▓ ▒██▒▒██████▒▒░██░▒██░   ▓██░  ▒██▒ ░ 
  ▒ ░░   ░ ▒░▒░▒░ ░ ▒▓ ░▒▓░▒ ▒▓▒ ▒ ░░▓  ░ ▒░   ▒ ▒   ▒ ░░   
    ░      ░ ▒ ▒░   ░▒ ░ ▒░░ ░▒  ░ ░ ▒ ░░ ░░   ░ ▒░    ░    
  ░      ░ ░ ░ ▒    ░░   ░ ░  ░  ░   ▒ ░   ░   ░ ░   ░      
             ░ ░     ░           ░   ░           ░          
                                                                   
    """)

def parse_arguments():
    parser = argparse.ArgumentParser(description='Process domain and IP address')
    parser.add_argument('--domain', type=str, required=False,
                        help='Domain name to lookup')
    parser.add_argument('--ip', type=str, required=False,
                        help='IP address to lookup')
    parser.add_argument('--output-format', type=str, required=False, choices=['json', 'csv'],
                        help='Output format (json or csv)')
    return parser.parse_args()

def query_ip_shodan(ip, shodan_api):
    url_ip = 'https://api.shodan.io/shodan/host/{}?key={}&minify=true'.format(ip, shodan_api)
    url_domain = f"https://api.shodan.io/shodan/host/{domain}?key={shodan_api}"
    response_ip = requests.request("GET", url_ip)
    response_domain = requests.request("GET", url_domain)
    json_response = json.loads(response_ip.text)
    json_response_domain = json.loads(response_domain.text)
    hostnames = json_response.get("hostnames")
    org = json_response.get("org")
    os = json_response.get("os")
    data = json_response.get("data")
    ports = json_response.get("ports")
    tags = json_response_domain.get("tags")
    subdomains = json_response_domain.get("subdomains")
    return (hostnames, org, os, data, ports, tags, subdomains)

def ip_details_from_json(data):
    details = {}
    for key in data:
        details[key] = data[key]
    return details

def standard_url_params():
    return {"strictness": 1}

def query_ip(ip, greynoise_api):
    url = f"https://api.greynoise.io/v3/community/{ip}"
    headers = {
      'key': '{{greynoise_api}}'
    }
    response = requests.request("GET", url, headers=headers)
    json_response = json.loads(response.text)
    category = json_response.get("category")
    classification = json_response.get("classification")
    last_seen = json_response.get("last_seen")
    return (category, classification, last_seen)

def crtsh(domain):
    url = "https://crt.sh/?q=%25.{}&output=json".format(domain)
    response = requests.request("GET", url)
    if response.status_code == 200:
        response = requests.get(url)
        parsed_json = json.loads(response.text)
        unique_names = set()
        saved_to_file = False # Add a flag to keep track of whether the message has already been printed or not
        for entry in parsed_json:
            unique_names.add(entry["name_value"])
        if len(unique_names) > 10:
            if not saved_to_file:
                print("[bold blue]\nThere's more than 10 results, they have been saved to cert.csv: [/bold blue]")
                saved_to_file = True # Set the flag to True to indicate that the message has been printed
            with open("cert.csv", "w", newline='') as output_file:
                dict_writer = csv.DictWriter(output_file, fieldnames=["domain"])
                dict_writer.writeheader()
                for name in unique_names:
                    dict_writer.writerow({"domain": name})
                    
def urlscan(domain, api_urlscan):
    # Make the scan request
    headers = {
        "Content-Type": "application/json",
        "API-Key": api_urlscan,
    }
    data = {
        "url": domain,
        "public": "off",
        "useragent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36 Edge/16.16299",
    }
    response = requests.post("https://urlscan.io/api/v1/scan/", headers=headers, json=data)
    if response.status_code != 200:
        print("Scan request failed:", response.status_code)
        exit()
    result = response.json()
    # Get the scan result
    result_url = result['api']
    headers = {"API-Key": api_urlscan}
    max_time = 60  # maximum wait time in seconds
    start_time = time.time()  # current time in seconds
    while True:
        response = requests.get(result_url, headers=headers)
        if response.status_code == 200:
            parsed_json = json.loads(response.text)
            unique_names = set()
            for name in unique_names:
                print(name)
        elif time.time() - start_time >= max_time:
            print(f"Timed out after {max_time} seconds.")
            break  # exit the loop if time limit is reached
        else:
            print(f"URL Scan timed out, retrying in 5 seconds...")
            time.sleep(5)

def whois(domain, whois_api):
    url = f"https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey={whois_api}&domainName={domain}&outputFormat=JSON"
    response = requests.get(url)
    json_data = response.json()

    if 'WhoisRecord' not in json_data:
        print(f"[bold magenta]No WHOIS information found for: [/bold magenta]{domain}.")
        return

    if 'createdDate' in json_data['WhoisRecord']:
        print(f"[bold magenta]Created Date: [/bold magenta]{json_data['WhoisRecord']['createdDate']}")
    else:
        print(f"[bold magenta]Created Date: [/bold magenta]Not available")
    if 'updatedDate' in json_data['WhoisRecord']:
        print(f"[bold magenta]Updated Date: [/bold magenta]{json_data['WhoisRecord']['updatedDate']}")
    else:
        print(f"[bold magenta]Updated Date: [/bold magenta]Not available")
    if 'expirationDate' in json_data['WhoisRecord']:
        print(f"[bold magenta]Expiration Date: [/bold magenta]{json_data['WhoisRecord']['expirationDate']}")
    else:
        print(f"[bold magenta]Expiration Date: [/bold magenta]Not available")
    if 'registrant' in json_data['WhoisRecord']:
        if 'name' in json_data['WhoisRecord']['registrant']:
            print(f"[bold magenta]Registrant Name: [/bold magenta]{json_data['WhoisRecord']['registrant']['name']}")
        else:
            print(f"[bold magenta]Registrant Name: [/bold magenta]Not available")
        if 'email' in json_data['WhoisRecord']['registrant']:
            print(f"[bold magenta]Registrant Email: [/bold magenta]{json_data['WhoisRecord']['registrant']['email']}")
        else:
            print(f"[bold magenta]Registrant Email: [/bold magenta]Not available")
    else:
        print(f"[bold magenta]Registrant Name: [/bold magenta]Not available")

def censys(ip): 
    h = CensysHosts()
    c = CensysCertificates()
    # Fetch a specific host and its services
    host = h.view(ip)
    for service in host["services"]:
        if "tls" in service:
            tls_data = service["tls"]
            cert_data = tls_data["certificates"]
            print("\n[bold magenta]Protocol: [/bold magenta]", service['service_name'])
            print("[bold magenta]TLS leaf fingerprint:[/bold magenta]", cert_data["leaf_fp_sha_256"])
            print("[bold magenta]TLS subject DN:[/bold magenta]", cert_data["leaf_data"]["subject_dn"])
            print("[bold magenta]TLS issuer DN:[/bold magenta]", cert_data["leaf_data"]["issuer_dn"])

def geoip(ip):
    response = requests.get(f"http://ip-api.com/json/{ip}")
    json_response = json.loads(response.text)
    country = json_response.get("country")
    isp = json_response.get("isp")
    asn = json_response.get("as")
    city = json_response.get("city")

    print("[bold blue]ISP:[/bold blue]", isp)
    print("[bold blue]City:[/bold blue]", city)
    print("[bold blue]Country:[/bold blue]", country)
    print("[bold blue]ASN:[/bold blue]", asn)

if __name__ == '__main__':
    args = parse_arguments()
    domain = args.domain
    ip = args.ip
    output_format = args.output_format
    logo()
    if args.ip:
        category, classification, last_seen = query_ip(ip, greynoise_api)
    elif args.domain:
        category, classification, last_seen = query_ip(domain, greynoise_api)
    else:
        raise ValueError('Either --ip or --domain must be provided')
    
    if args.output_format == 'json':
        results = {
            "shodan": query_ip_shodan(args.ip, shodan_api),
            "crtsh": crtsh(domain)
        }
        with open("output.json", "w") as f:
            json.dump(results, f, indent=4)
    
    if args.ip:
        hostnames, org, os, data, ports, tags, subdomains = query_ip_shodan(args.ip, shodan_api)
        print("[bold blue]Greynoise classifies this as:[/bold blue]", classification)
        print("[bold blue]Last seen on Greynoise[/bold blue]:", last_seen)
        print("[bold blue]Operating detected:[/bold blue]", os)
        print("[bold blue]Operating ports:[/bold blue]", str(ports))
        geoip(ip)
        censys(ip)
        
    elif args.domain:
        hostnames, org, os, data, ports, tags, subdomains = query_ip_shodan(args.domain, shodan_api) 
        print("[bold magenta]Shodan Tags:[/bold magenta]", tags)
        print("[bold magenta]Shodan Subdomains:[/bold magenta]", subdomains)
        whois(domain, whois_api)
        crtsh(domain)
        urlscan(domain, api_urlscan)
    else:
        raise ValueError('Either --ip or --domain must be provided')

    