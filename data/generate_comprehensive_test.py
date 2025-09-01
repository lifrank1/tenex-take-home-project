#!/usr/bin/env python3
"""
Generate comprehensive test logs that trigger all 8 anomaly detection scenarios
"""

import csv
from datetime import datetime, timedelta

def generate_comprehensive_test_logs():
    """Generate logs that trigger all anomaly detection scenarios"""
    
    # Base timestamp
    base_time = datetime(2024, 1, 15, 8, 0, 0)
    
    logs = []
    
    # Normal traffic patterns (first 10 entries)
    for i in range(10):
        timestamp = base_time + timedelta(seconds=i*60)
        user_id = i + 1
        client_ip = f"172.17.1.{100 + i}"
        
        # Normal user behavior
        log = [
            timestamp.strftime("%a %b %d %H:%M:%S %Y"),  # 0. timestamp
            f"user{user_id}",  # 1. login
            "HTTP",  # 2. department
            ["google.com", "github.com", "stackoverflow.com", "linkedin.com", "office365.com"][i % 5],  # 3. company
            "Allowed",  # 4. cloudName
            ["Google", "GitHub", "Stack Overflow", "LinkedIn", "Office 365"][i % 5],  # 5. clientIP
            ["Search Engines", "Development", "Development", "Social Networking", "Productivity"][i % 5],  # 6. clientInternalIP
            ["15", "30", "25", "20", "25"][i % 5],  # 7. clientPublicIP
            ["1024", "2048", "1536", "1024", "512"][i % 5],  # 8. serverIP
            ["2048", "4096", "3072", "2048", "1024"][i % 5],  # 9. location
            ["3072", "6144", "4608", "3072", "1536"][i % 5],  # 10. url
            ["General Surfing", "Technology", "Technology", "Social Networking", "Office Apps"][i % 5],  # 11. host
            ["Search Engines", "Development", "Development", "Social Networking", "Productivity"][i % 5],  # 12. requestMethod
            ["Search", "Code Repositories", "Technical Q&A", "Professional Networking", "Office Applications"][i % 5],  # 13. responseCode
            "None",  # 14. userAgent
            "None",  # 15. referer
            "0",  # 16. contentType
            "None",  # 17. action
            "None",  # 18. reason
            f"user{user_id}",  # 19. ruleType
            ["IT Department", "Engineering Department", "Engineering Department", "Sales Department", "HR Department"][i % 5],  # 20. ruleLabel
            client_ip,  # 21. threatName - CLIENT IP (internal)
            ["8.8.8.8", "140.82.112.3", "151.101.1.69", "13.107.42.14", "13.107.136.9"][i % 5],  # 22. threatSeverity - SERVER IP (external)
            "GET",  # 23. riskScore - REQUEST METHOD
            "200",  # 24. malwareCategory - RESPONSE CODE
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",  # 25. malwareClass - USER AGENT
            "None",  # 26. urlCategory
            "URLFilter",  # 27. urlSuperCategory
            f"URL_Allow_{user_id}",  # 28. urlClass
            "Other",  # 29. appName
            "None",  # 30. appClass
            "NA",  # 31. appRiskScore
            "NA",  # 32. fileName
            "N/A"  # 33. fileType
        ]
        logs.append(log)
    
    # ANOMALY 1: URL Pattern Analysis - Same URL accessed many times
    for i in range(5):
        timestamp = base_time + timedelta(seconds=600 + i)
        log = [
            timestamp.strftime("%a %b %d %H:%M:%S %Y"),
            "attacker1",
            "HTTP",
            "api.example.com/endpoint1",
            "Allowed",
            "API Endpoint",
            "Technology",
            "45",
            "64",
            "128",
            "192",
            "Technology",
            "Technology",
            "API",
            "None",
            "None",
            "0",
            "None",
            "None",
            "attacker1",
            "IT Department",
            "172.17.6.150",
            "192.168.1.1",
            "GET",
            "200",
            "curl/7.68.0",
            "None",
            "URLFilter",
            "API_Allow_1",
            "Other",
            "None",
            "NA",
            "NA",
            "N/A"
        ]
        logs.append(log)
    
    # ANOMALY 2: User Agent Analysis - Suspicious scanning tools
    suspicious_agents = ["sqlmap/1.0", "nikto/2.1.6", "nmap/7.80", "metasploit/6.0.0", "wget/1.20.3"]
    for i in range(5):
        timestamp = base_time + timedelta(seconds=660 + i)
        log = [
            timestamp.strftime("%a %b %d %H:%M:%S %Y"),
            "attacker2",
            "HTTP",
            "admin.example.com/panel",
            "Blocked",
            "Admin Panel",
            "Technology",
            "75",
            "0",
            "0",
            "0",
            "Technology",
            "Security Risk",
            "Admin Access",
            "None",
            "None",
            "0",
            "None",
            "None",
            "attacker2",
            "Engineering Department",
            "172.17.6.151",
            "192.168.1.2",
            "POST",
            "403",
            suspicious_agents[i],
            "None",
            "ThreatProtection",
            f"Suspicious_UA_Block_{i+1}",
            "Other",
            "None",
            "NA",
            "NA",
            "N/A"
        ]
        logs.append(log)
    
    # ANOMALY 3: Geographic Access - Multiple IPs from same country
    for i in range(5):
        timestamp = base_time + timedelta(seconds=720 + i)
        log = [
            timestamp.strftime("%a %b %d %H:%M:%S %Y"),
            "attacker3",
            "HTTP",
            "malware-site.com",
            "Blocked",
            "Malware Site",
            "Malware",
            "95",
            "0",
            "0",
            "0",
            "Security Risk",
            "Malware",
            "Malware Distribution",
            "None",
            "None",
            "0",
            "None",
            "None",
            "attacker3",
            "Security Department",
            f"172.17.6.{152 + i}",
            f"203.208.60.{i + 1}",
            "GET",
            "403",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "None",
            "ThreatProtection",
            f"Malware_Block_{i+1}",
            "Other",
            "None",
            "NA",
            "NA",
            "N/A"
        ]
        logs.append(log)
    
    # ANOMALY 4: Time Pattern Analysis - Traffic spike at 10:00
    for i in range(15):
        timestamp = datetime(2024, 1, 15, 10, 0, i)
        log = [
            timestamp.strftime("%a %b %d %H:%M:%S %Y"),
            "attacker4",
            "HTTP",
            "api.example.com/endpoint2",
            "Allowed",
            "API Endpoint",
            "Technology",
            "45",
            "64",
            "128",
            "192",
            "Technology",
            "Technology",
            "API",
            "None",
            "None",
            "0",
            "None",
            "None",
            "attacker4",
            "IT Department",
            "172.17.6.157",
            "192.168.1.3",
            "GET",
            "200",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "None",
            "URLFilter",
            "API_Allow_2",
            "Other",
            "None",
            "NA",
            "NA",
            "N/A"
        ]
        logs.append(log)
    
    # ANOMALY 5: Response Code Analysis - High 4xx error rate
    for i in range(10):
        timestamp = datetime(2024, 1, 15, 10, 1, i)
        log = [
            timestamp.strftime("%a %b %d %H:%M:%S %Y"),
            "attacker5",
            "HTTP",
            f"broken-site.com/page{i+1}",
            "Blocked",
            "Broken Site",
            "Technology",
            "75",
            "0",
            "0",
            "0",
            "Technology",
            "Security Risk",
            "Broken Page",
            "None",
            "None",
            "0",
            "None",
            "None",
            "attacker5",
            "IT Department",
            "172.17.6.158",
            "192.168.1.4",
            "GET",
            "404",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "None",
            "ThreatProtection",
            f"404_Block_{i+1}",
            "Other",
            "None",
            "NA",
            "NA",
            "N/A"
        ]
        logs.append(log)
    
    # ANOMALY 6: File Access Monitoring - Suspicious file types
    suspicious_files = ["download.exe", "script.bat", "payload.dll", "archive.zip", "script.ps1"]
    for i in range(5):
        timestamp = datetime(2024, 1, 15, 10, 2, i)
        log = [
            timestamp.strftime("%a %b %d %H:%M:%S %Y"),
            "attacker6",
            "HTTP",
            f"malicious-site.com/{suspicious_files[i]}",
            "Blocked",
            "Malicious Download",
            "Malware",
            "95",
            "0",
            "0",
            "0",
            "Security Risk",
            "Malware",
            "Malware Downloads",
            "None",
            "None",
            "0",
            "None",
            "None",
            "attacker6",
            "Security Department",
            "172.17.6.159",
            "192.168.1.5",
            "GET",
            "403",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "None",
            "ThreatProtection",
            f"Malware_Block_{i+1}",
            "Other",
            "None",
            "NA",
            suspicious_files[i],
            suspicious_files[i].split('.')[-1]
        ]
        logs.append(log)
    
    # ANOMALY 7: SSL/TLS Behavior - Old TLS versions
    for i in range(6):
        timestamp = datetime(2024, 1, 15, 10, 3, i)
        log = [
            timestamp.strftime("%a %b %d %H:%M:%S %Y"),
            "attacker7",
            "HTTP",
            "old-site.com",
            "Allowed",
            "Old Site",
            "Technology",
            "45",
            "64",
            "128",
            "192",
            "Technology",
            "Technology",
            "Old Site",
            "None",
            "None",
            "0",
            "None",
            "None",
            "attacker7",
            "IT Department",
            "172.17.6.160",
            "192.168.1.6",
            "GET",
            "200",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "None",
            "URLFilter",
            f"Old_Site_{i+1}",
            "Other",
            "None",
            "NA",
            "NA",
            "N/A"
        ]
        logs.append(log)
    
    # ANOMALY 8: Bandwidth Usage - High bandwidth from single IP
    for i in range(5):
        timestamp = datetime(2024, 1, 15, 10, 4, i)
        log = [
            timestamp.strftime("%a %b %d %H:%M:%S %Y"),
            "attacker8",
            "HTTP",
            f"large-file.com/video{i+1}.mp4",
            "Allowed",
            "Large File",
            "Technology",
            "45",
            "10240",
            "20480",
            "30720",
            "Technology",
            "Technology",
            "Large File",
            "None",
            "None",
            "0",
            "None",
            "None",
            "attacker8",
            "IT Department",
            "172.17.6.161",
            "192.168.1.7",
            "GET",
            "200",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "None",
            "URLFilter",
            f"Large_File_{i+1}",
            "Other",
            "None",
            "NA",
            f"video{i+1}.mp4",
            "mp4"
        ]
        logs.append(log)
    
    # Write to CSV file
    with open('comprehensive_test_logs.csv', 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        
        # Write header
        header = [
            'timestamp', 'login', 'department', 'company', 'cloudName', 'clientIP', 'clientInternalIP',
            'clientPublicIP', 'serverIP', 'location', 'url', 'host', 'requestMethod', 'responseCode',
            'userAgent', 'referer', 'contentType', 'action', 'reason', 'ruleType', 'ruleLabel',
            'threatName', 'threatSeverity', 'riskScore', 'malwareCategory', 'malwareClass',
            'urlCategory', 'urlSuperCategory', 'urlClass', 'appName', 'appClass', 'appRiskScore',
            'fileName', 'fileType'
        ]
        writer.writerow(header)
        
        # Write data
        for log in logs:
            writer.writerow(log)
    
    print(f"Generated comprehensive test log file with {len(logs)} entries")
    print("This file will trigger all 8 anomaly detection scenarios:")
    print("1. URL Pattern Analysis")
    print("2. User Agent Analysis") 
    print("3. Geographic Access")
    print("4. Time Pattern Analysis")
    print("5. Response Code Analysis")
    print("6. File Access Monitoring")
    print("7. SSL/TLS Behavior")
    print("8. Bandwidth Usage")

if __name__ == "__main__":
    generate_comprehensive_test_logs()
