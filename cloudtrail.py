import ijson
import requests
from collections import Counter
from pathlib import Path
import json

global_source_ip_counter = Counter()

def parsing_data(record, created_s3_buckets, kali_user_agents, created_EC2_instances, api_actions_counter, root_account_operations):
    global global_source_ip_counter
    source_ip = record.get('sourceIPAddress')
    if source_ip:
        global_source_ip_counter[source_ip] += 1
    
    user_identity = record.get('userIdentity', {})
    event_name = record.get('eventName')
    user_agent = record.get('userAgent', '').lower()

    api_actions_counter[event_name] += 1
    if user_identity.get('type') == 'Root':
        root_account_operations[event_name] += 1
        if event_name == "CreateBucket" and 'errorCode' not in record:
            bucket_name = record.get('requestParameters', {}).get('bucketName')
            created_s3_buckets.add(bucket_name)
        if event_name == "RunInstances" and 'errorCode' not in record:
            instances_info = record.get('responseElements', {}).get('instancesSet', {}).get('items', [])
            for instance in instances_info:
                instance_id = instance.get('instanceId')
                if instance_id:
                    created_EC2_instances.add(instance_id)
    if 'kali' in user_agent:
        kali_user_agents.add(user_agent)

def parse_cloudtrail_log(file_path):
    created_s3_buckets = set()
    kali_user_agents = set()
    created_EC2_instances = set()
    api_actions_counter = Counter()
    root_account_operations = Counter()

    with open(file_path, 'rb') as file:
        for record in ijson.items(file, 'Records.item'):
            parsing_data(record, created_s3_buckets, kali_user_agents, created_EC2_instances, 
                           api_actions_counter, root_account_operations)

    return {
        'created_s3_buckets': list(created_s3_buckets),
        'created_EC2_instances': list(created_EC2_instances),
        'kali_user_agents': list(kali_user_agents),
        'top_5_api_actions': api_actions_counter.most_common(5),
        'root_account_operations': dict(root_account_operations)
    }

def ip_reputation(top_ips_counts, output_file='ip_reputation.json'):
    url = 'https://api.abuseipdb.com/api/v2/check'
    headers = {
        'Accept': 'application/json',
        'Key': '41cf6b4f24c45a51d0870c0be57407c3c277f82566cab829f7039ed47eca4bfcb3e73235673e9139'
    }
    ip_reputation_data = []

    for serial, (ip, count) in enumerate(top_ips_counts, start=1):
        querystring = {'ipAddress': ip, 'maxAgeInDays': '90'}
        response = requests.request(method='GET', url=url, headers=headers, params=querystring)
        
        if response.status_code == 200:
            decoded_response = response.json()
            ip_data = {
                'IP Address': ip,
                'Count Seen': count,
                'IP Reputation Summary': decoded_response['data']
            }
            ip_reputation_data.append(ip_data)
            ip_reputation_data.append("*" * 40)  # Separator for readability

    with open(output_file, 'w') as file:
        json_string = json.dumps([data for data in ip_reputation_data if data != "*" * 40], indent=4)
        file.write(json_string)


def print_report(results, file_name):
    print(f"\n{'='*60}\nAnalysis Results for file: {file_name}\n{'='*60}")
    print("\nSuccessfully created S3 buckets:\n")
    for bucket in results['created_s3_buckets']:
        print(bucket)

    print("\nSuccessfully created EC2 instances:\n")
    for instance in results['created_EC2_instances']:
        print(instance)

    print("\nUser agents created by Kali:\n")
    for ua in results['kali_user_agents']:
        print(ua)

    print("\nTop 5 API Actions:\n")
    for action, count in results['top_5_api_actions']:
        print(f"{action}: {count} times")

    print("\nRoot account operations found:\n")
    for operation, count in results['root_account_operations'].items():
        print(f"{operation}: {count} times")

def main():
    directory_path = '/home/toxin/Desktop/flaws_cloudtrail_logs/Cloud trail/'  # Update this path
    files = Path(directory_path).glob('*.json')

    for file_path in files:
        results = parse_cloudtrail_log(str(file_path))
        print_report(results, file_path.name)
    
    top_100_ips_counts = global_source_ip_counter.most_common(100)
    
    ip_reputation(top_100_ips_counts, 'ip_reputation_summary.json')
    
    print("\nIP reputation check completed. Results saved to 'ip_reputation_summary.json'.")

if __name__ == "__main__":
    main()
 
