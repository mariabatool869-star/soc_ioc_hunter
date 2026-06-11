import requests
from datetime import datetime

ABUSEIPDB_API_KEY = "your_APi_key_here"   # <-- ADD THIS LINE

print("=" * 50)
print("SOC IOC HUNTER - Threat Intelligence Tool")
print("=" * 50)
print()

# Read IPs from file
ip_list = []
try:
    with open("ips.txt", "r") as file:
        for line in file:
            line = line.strip()
            if line and not line.startswith("#"):
                ip_list.append(line)
    print(f"Loaded {len(ip_list)} IP addresses to check")
except FileNotFoundError:
    print("ERROR: ips.txt file not found!")
    print("Create ips.txt with one IP per line")
    exit()
print()

# Initialize counters
total = len(ip_list)
malicious_count = 0
suspicious_count = 0
safe_count = 0
failed_count = 0

# Open report file
with open("report.csv", "w") as report:
    report.write("Timestamp,IP,Score,Verdict\n")
    
    # Open malicious IPs file
    with open("malicious_ips.txt", "w") as malicious_file:
        malicious_file.write("# Malicious IPs to Block\n")
        malicious_file.write(f"# Generated: {datetime.now()}\n")
        malicious_file.write("#" + "=" * 40 + "\n\n")
        
        # Check each IP
        for index, ip in enumerate(ip_list, 1):
            print(f"Checking IP {index} of {total}: {ip}")
            
            try:
                # Call AbuseIPDB API
                url = "https://api.abuseipdb.com/api/v2/check"
                headers = {
                    "Key": ABUSEIPDB_API_KEY,
                    "Accept": "application/json"
                }
                params = {
                    "ipAddress": ip,
                    "maxAgeInDays": 90
                }
                
                response = requests.get(url, headers=headers, params=params)
                
                # Check if request was successful
                if response.status_code != 200:
                    print(f"  → API Error: Status code {response.status_code}")
                    failed_count += 1
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    report.write(f"{timestamp},{ip},API_ERROR,FAILED\n")
                else:
                    data = response.json()
                    score = data["data"]["abuseConfidenceScore"]
                    
                    # Determine verdict
                    if score >= 51:
                        verdict = "MALICIOUS"
                        malicious_count += 1
                        malicious_file.write(f"{ip} | Score: {score}\n")
                        print(f"  → Score: {score} | 🔴 {verdict}")
                    elif score >= 11:
                        verdict = "SUSPICIOUS"
                        suspicious_count += 1
                        print(f"  → Score: {score} | 🟡 {verdict}")
                    else:
                        verdict = "SAFE"
                        safe_count += 1
                        print(f"  → Score: {score} | 🟢 {verdict}")
                    
                    # Write to report
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    report.write(f"{timestamp},{ip},{score},{verdict}\n")
                
            except Exception as e:
                failed_count += 1
                print(f"  → ❌ ERROR: {e}")
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                report.write(f"{timestamp},{ip},ERROR,FAILED\n")
            
            print()

# Print summary
print("=" * 50)
print("SUMMARY REPORT")
print("=" * 50)
print(f"Total IPs checked: {total}")
print(f"🔴 MALICIOUS: {malicious_count}")
print(f"🟡 SUSPICIOUS: {suspicious_count}")
print(f"🟢 SAFE: {safe_count}")
print(f"❌ FAILED: {failed_count}")
print()
print("Reports saved:")
print("  📄 report.csv - Full investigation log")
print(f"  📄 malicious_ips.txt - {malicious_count} IPs to block")
print()
print("=" * 50)