import argparse
import requests
import re
from bs4 import BeautifulSoup
import csv
import os

DIRECTORY_URL = "https://collector.torproject.org/recent/exit-lists/"

def fetch_latest_exit_list_url():
    response = requests.get(DIRECTORY_URL, stream=True) 
    soup = BeautifulSoup(response.content, 'html.parser')
    latest_file = sorted(link.get('href') for link in soup.find_all('a')
                           if link.get('href').endswith('00'))[-1]
    return DIRECTORY_URL + latest_file

def fetch_tor_exit_list():
    exit_nodes = getattr(fetch_tor_exit_list, "cached_exit_nodes", None)
    if exit_nodes is None:
        latest_file_url = fetch_latest_exit_list_url()
        try:
            response = requests.get(latest_file_url, timeout=10, stream=True)
            response.raise_for_status()
            exit_nodes = set(re.findall(r'ExitAddress (\d+\.\d+\.\d+\.\d+)', response.text))
            print("Fetched details from the latest file on the website.")
            fetch_tor_exit_list.cached_exit_nodes = exit_nodes
        except requests.RequestException as e:
            print(f"Error fetching list: {e}")
            exit_nodes = set()
    return exit_nodes

def is_tor_exit(ip, exit_nodes):
    return ip in exit_nodes

def main():
    parser = argparse.ArgumentParser(description="Check if IPs are Tor exit nodes using real-time data with regex extraction")
    parser.add_argument("--ip", type=str, help="Single IP address to check")
    parser.add_argument("--ip-list", type=str, help="File path containing a list of IPs")
    args = parser.parse_args()

    if args.ip:
        exit_nodes = fetch_tor_exit_list() 
        is_exit = is_tor_exit(args.ip, exit_nodes)
        print(f"{args.ip} is a Tor exit node: {is_exit}")
    elif args.ip_list:
        file_counter = 1
        results_filename = "results.csv"
        while os.path.exists(results_filename):
            results_filename = f"results{file_counter}.csv"
            file_counter += 1
            
        try:
            with open(args.ip_list, "r") as f, open(results_filename, "w", newline="") as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(["IP", "Exit Node (True/False)"])
                exit_nodes = fetch_tor_exit_list()
                for ip in f:
                    ip = ip.strip()
                    is_exit = is_tor_exit(ip, exit_nodes)
                    writer.writerow([ip, str(is_exit)])
            print(f"Results written to {results_filename}")
        except FileNotFoundError:
            print(f"Error: File not found: {args.ip_list}")
    else:
        print("Please provide either --ip or --ip-list argument.")

if __name__ == "__main__":
    main()