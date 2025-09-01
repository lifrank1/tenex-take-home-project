#!/usr/bin/env python3
"""
Generate logs with EXACT same field structure as sample_zscaler_logs.csv
This is a CUSTOM, SIMPLIFIED format, NOT the official Zscaler NSS feed format.
"""

import csv
import random
from datetime import datetime, timedelta

def generate_correct_logs():
    """Generate logs with exact same field structure as the working sample_zscaler_logs.csv"""
    
    # Base timestamp
    base_time = datetime(2024, 1, 15, 8, 0, 0)
    
    # Sample data for realistic logs
    departments = ['IT', 'HR', 'Finance', 'Marketing', 'Engineering', 'Sales', 'Legal', 'Operations']
    companies = ['ACME Corp', 'TechStart Inc', 'Global Solutions Ltd']
    
    # URLs and categories for different anomaly types
    normal_urls = [
        ('google.com/', 'Google', 'Search Engines', '15', '1024', '2048', '3072', 'General Surfing', 'Search Engines', 'Search'),
        ('github.com/', 'GitHub', 'Development', '30', '2048', '4096', '6144', 'Technology', 'Development', 'Code Repositories'),
        ('stackoverflow.com/', 'Stack Overflow', 'Development', '25', '1536', '3072', '4608', 'Technology', 'Development', 'Technical Q&A'),
        ('linkedin.com/', 'LinkedIn', 'Social Networking', '20', '1024', '2048', '3072', 'Social Networking', 'Social Networking', 'Professional Networking'),
        ('office365.com/', 'Office 365', 'Productivity', '25', '512', '1024', '1536', 'Office Apps', 'Productivity', 'Office Applications')
    ]
    
    suspicious_urls = [
        ('malware-site.com/', 'Malware Site', 'Malware', '95', '0', '0', '0', 'Security Risk', 'Malware', 'Malware Distribution'),
        ('phishing-attempt.net/', 'Phishing Site', 'Phishing', '88', '0', '0', '0', 'Security Risk', 'Phishing', 'Phishing'),
        ('command-control.com/', 'Command & Control', 'C2', '100', '0', '0', '0', 'Security Risk', 'Command & Control', 'C2 Server'),
        ('malicious-download.com/', 'Malicious Download', 'Malware', '98', '0', '0', '0', 'Security Risk', 'Malware', 'Malware Downloads'),
        ('ransomware-site.net/', 'Ransomware Site', 'Ransomware', '99', '0', '0', '0', 'Security Risk', 'Ransomware', 'Ransomware')
    ]
    
    # User agents for different anomaly types
    normal_user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
    ]
    
    suspicious_user_agents = [
        'sqlmap/1.0',
        'nikto/2.1.6',
        'curl/7.68.0',
        'wget/1.20.3',
        'python-requests/2.25.1',
        'nmap/7.80',
        'metasploit/6.0.0'
    ]
    
    # Generate logs
    logs = []
    log_id = 1
    
    # Normal traffic patterns (first 50 entries)
    for i in range(50):
        timestamp = base_time + timedelta(seconds=i*2)
        user_id = random.randint(1, 8)
        dept = departments[user_id % len(departments)]
        company = random.choice(companies)
        
        # Normal user behavior
        client_ip = f"172.17.3.{100 + user_id}"
        user_agent = random.choice(normal_user_agents)
        url, url_name, url_cat, risk_score, req_size, resp_size, total_size, category, super_cat, url_class = random.choice(normal_urls)
        
        # EXACT field structure as working sample_zscaler_logs.csv (34 fields)
        log = [
            timestamp.strftime("%a %b %d %H:%M:%S %Y"),  # 0. timestamp
            f"{dept.lower()}-{company.lower().replace(' ', '-')}",  # 1. login
            "HTTP",  # 2. department
            url,  # 3. company
            "Allowed",  # 4. cloudName
            url_name,  # 5. clientIP
            url_cat,  # 6. clientInternalIP
            risk_score,  # 7. clientPublicIP
            req_size,  # 8. serverIP
            resp_size,  # 9. location
            total_size,  # 10. url
            url_class,  # 11. host
            super_cat,  # 12. requestMethod
            category,  # 13. responseCode
            "None",  # 14. userAgent
            "None",  # 15. referer
            "0",  # 16. contentType
            "None",  # 17. action
            "None",  # 18. reason
            f"{dept.lower()}-{company.lower().replace(' ', '-')}",  # 19. ruleType
            f"{dept} Department",  # 20. ruleLabel
            client_ip,  # 21. threatName - CLIENT IP (internal)
            f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",  # 22. threatSeverity - SERVER IP (external)
            "GET",  # 23. riskScore - REQUEST METHOD
            "200",  # 24. malwareCategory - RESPONSE CODE
            user_agent,  # 25. malwareClass - USER AGENT
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
        log_id += 1
    
    # High-frequency requests from single IP (anomaly 1)
    for i in range(20):
        timestamp = base_time + timedelta(seconds=100 + i)
        log = [
            timestamp.strftime("%a %b %d %H:%M:%S %Y"),  # 0. timestamp
            "it-acme-corp",  # 1. login
            "HTTP",  # 2. department
            f"api.example.com/endpoint{i}",  # 3. company
            "Allowed",  # 4. cloudName
            "API Endpoint",  # 5. clientIP
            "Technology",  # 6. clientInternalIP
            "45",  # 7. clientPublicIP
            "64",  # 8. serverIP
            "128",  # 9. location
            "192",  # 10. url
            "API",  # 11. host
            "Technology",  # 12. requestMethod
            "Technology",  # 13. responseCode
            "None",  # 14. userAgent
            "None",  # 15. referer
            "0",  # 16. contentType
            "None",  # 17. action
            "None",  # 18. reason
            "it-acme-corp",  # 19. ruleType
            "IT Department",  # 20. ruleLabel
            "172.17.3.200",  # 21. threatName - Same IP making many requests (CLIENT IP)
            f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",  # 22. threatSeverity (SERVER IP)
            "GET",  # 23. riskScore (REQUEST METHOD)
            "200",  # 24. malwareCategory (RESPONSE CODE)
            "curl/7.68.0",  # 25. malwareClass (USER AGENT) - Suspicious user agent
            "None",  # 26. urlCategory
            "URLFilter",  # 27. urlSuperCategory
            "API_Allow_1",  # 28. urlClass
            "Other",  # 29. appName
            "None",  # 30. appClass
            "NA",  # 31. appRiskScore
            "NA",  # 32. fileName
            "N/A"  # 33. fileType
        ]
        logs.append(log)
        log_id += 1
    
    # Suspicious user agents and blocked requests (anomaly 2)
    for i in range(15):
        timestamp = base_time + timedelta(seconds=120 + i)
        suspicious_ua = random.choice(suspicious_user_agents)
        log = [
            timestamp.strftime("%a %b %d %H:%M:%S %Y"),  # 0. timestamp
            "eng-acme-corp",  # 1. login
            "HTTP",  # 2. department
            f"admin.example.com/panel{i}",  # 3. company
            "Blocked",  # 4. cloudName
            "Admin Panel",  # 5. clientIP
            "Technology",  # 6. clientInternalIP
            "75",  # 7. clientPublicIP
            "0",  # 8. serverIP
            "0",  # 9. location
            "0",  # 10. url
            "Admin Access",  # 11. host
            "Technology",  # 12. requestMethod
            "Security Risk",  # 13. responseCode
            "None",  # 14. userAgent
            "None",  # 15. referer
            "0",  # 16. contentType
            "None",  # 17. action
            "None",  # 18. reason
            "eng-acme-corp",  # 19. ruleType
            "Engineering Department",  # 20. ruleLabel
            "172.17.3.201",  # 21. threatName (CLIENT IP)
            f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",  # 22. threatSeverity (SERVER IP)
            "POST",  # 23. riskScore (REQUEST METHOD)
            "403",  # 24. malwareCategory (RESPONSE CODE)
            suspicious_ua,  # 25. malwareClass (USER AGENT)
            "None",  # 26. urlCategory
            "ThreatProtection",  # 27. urlSuperCategory
            "Suspicious_UA_Block_1",  # 28. urlClass
            "Other",  # 29. appName
            "None",  # 30. appClass
            "NA",  # 31. appRiskScore
            "NA",  # 32. fileName
            "N/A"  # 33. fileType
        ]
        logs.append(log)
        log_id += 1
    
    # Geographic anomalies - multiple IPs from same country (anomaly 3)
    for i in range(25):
        timestamp = base_time + timedelta(seconds=140 + i)
        country = random.choice(['CN', 'RU', 'NG'])  # Countries with unusual access patterns
        log = [
            timestamp.strftime("%a %b %d %H:%M:%S %Y"),  # 0. timestamp
            "ext-unknown",  # 1. login
            "HTTP",  # 2. department
            f"www.example.com/page{i}",  # 3. company
            "Allowed",  # 4. cloudName
            "Example Site",  # 5. clientIP
            "Technology",  # 6. clientInternalIP
            "30",  # 7. clientPublicIP
            "256",  # 8. serverIP
            "1024",  # 9. location
            "1280",  # 10. url
            "Web",  # 11. host
            "Technology",  # 12. requestMethod
            "Technology",  # 13. responseCode
            "None",  # 14. userAgent
            "None",  # 15. referer
            "0",  # 16. contentType
            "None",  # 17. action
            "None",  # 18. reason
            "ext-unknown",  # 19. ruleType
            "External Department",  # 20. ruleLabel
            f"172.17.{random.randint(100, 200)}.{random.randint(1, 255)}",  # 21. threatName (CLIENT IP)
            f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",  # 22. threatSeverity (SERVER IP)
            "GET",  # 23. riskScore (REQUEST METHOD)
            "200",  # 24. malwareCategory (RESPONSE CODE)
            random.choice(normal_user_agents),  # 25. malwareClass (USER AGENT)
            "None",  # 26. urlCategory
            "URLFilter",  # 27. urlSuperCategory
            f"EXT_Allow_{country}_{i}",  # 28. urlClass
            "Other",  # 29. appName
            "None",  # 30. appClass
            "NA",  # 31. appRiskScore
            "NA",  # 32. fileName
            "N/A"  # 33. fileType
        ]
        logs.append(log)
        log_id += 1
    
    # Time-based anomalies - traffic spikes (anomaly 4)
    for i in range(30):
        timestamp = base_time + timedelta(seconds=180 + i)
        log = [
            timestamp.strftime("%a %b %d %H:%M:%S %Y"),  # 0. timestamp
            "it-acme-corp",  # 1. login
            "HTTP",  # 2. department
            f"www.example.com/api/v1/data{i}",  # 3. company
            "Allowed",  # 4. cloudName
            "API Data",  # 5. clientIP
            "Technology",  # 6. clientInternalIP
            "20",  # 7. clientPublicIP
            "128",  # 8. serverIP
            "512",  # 9. location
            "640",  # 10. url
            "API",  # 11. host
            "Technology",  # 12. requestMethod
            "Technology",  # 13. responseCode
            "None",  # 14. userAgent
            "None",  # 15. referer
            "0",  # 16. contentType
            "None",  # 17. action
            "None",  # 18. reason
            "it-acme-corp",  # 19. ruleType
            "IT Department",  # 20. ruleLabel
            f"172.17.3.{220 + i}",  # 21. threatName (CLIENT IP)
            f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",  # 22. threatSeverity (SERVER IP)
            "GET",  # 23. riskScore (REQUEST METHOD)
            "200",  # 24. malwareCategory (RESPONSE CODE)
            random.choice(normal_user_agents),  # 25. malwareClass (USER AGENT)
            "None",  # 26. urlCategory
            "URLFilter",  # 27. urlSuperCategory
            f"API_Allow_{220 + i}",  # 28. urlClass
            "Other",  # 29. appName
            "None",  # 30. appClass
            "NA",  # 31. appRiskScore
            "NA",  # 32. fileName
            "N/A"  # 33. fileType
        ]
        logs.append(log)
        log_id += 1
    
    # SSL/TLS anomalies (anomaly 5)
    for i in range(20):
        timestamp = base_time + timedelta(seconds=220 + i)
        log = [
            timestamp.strftime("%a %b %d %H:%M:%S %Y"),  # 0. timestamp
            "fin-acme-corp",  # 1. login
            "HTTPS",  # 2. department
            f"secure.example.com/banking{i}",  # 3. company
            "Allowed",  # 4. cloudName
            "Secure Banking",  # 5. clientIP
            "Finance",  # 6. clientInternalIP
            "30",  # 7. clientPublicIP
            "1024",  # 8. serverIP
            "2048",  # 9. location
            "3072",  # 10. url
            "Finance",  # 11. host
            "Finance",  # 12. requestMethod
            "Banking",  # 13. responseCode
            "None",  # 14. userAgent
            "None",  # 15. referer
            "0",  # 16. contentType
            "None",  # 17. action
            "None",  # 18. reason
            "fin-acme-corp",  # 19. ruleType
            "Finance Department",  # 20. ruleLabel
            f"172.17.3.{250 + i}",  # 21. threatName (CLIENT IP)
            f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",  # 22. threatSeverity (SERVER IP)
            "POST",  # 23. riskScore (REQUEST METHOD)
            "200",  # 24. malwareCategory (RESPONSE CODE)
            random.choice(normal_user_agents),  # 25. malwareClass (USER AGENT)
            "None",  # 26. urlCategory
            "URLFilter",  # 27. urlSuperCategory
            f"Finance_Allow_{250 + i}",  # 28. urlClass
            "Other",  # 29. appName
            "None",  # 30. appClass
            "NA",  # 31. appRiskScore
            "NA",  # 32. fileName
            "N/A"  # 33. fileType
        ]
        logs.append(log)
        log_id += 1
    
    # File access anomalies (anomaly 6)
    for i in range(15):
        timestamp = base_time + timedelta(seconds=250 + i)
        suspicious_extensions = ['exe', 'dll', 'bat', 'cmd', 'ps1', 'vbs', 'js', 'jar', 'zip', 'rar']
        ext = random.choice(suspicious_extensions)
        log = [
            timestamp.strftime("%a %b %d %H:%M:%S %Y"),  # 0. timestamp
            "eng-acme-corp",  # 1. login
            "HTTP",  # 2. department
            f"download.example.com/files/update.{ext}",  # 3. company
            "Allowed",  # 4. cloudName
            f"Update File {ext.upper()}",  # 5. clientIP
            "Technology",  # 6. clientInternalIP
            "60",  # 7. clientPublicIP
            "64",  # 8. serverIP
            "5120",  # 9. location
            "5184",  # 10. url
            "Technology",  # 11. host
            "Technology",  # 12. requestMethod
            "Downloads",  # 13. responseCode
            "None",  # 14. userAgent
            "None",  # 15. referer
            "0",  # 16. contentType
            "None",  # 17. action
            "None",  # 18. reason
            "eng-acme-corp",  # 19. ruleType
            "Engineering Department",  # 20. ruleLabel
            f"172.17.3.{270 + i}",  # 21. threatName (CLIENT IP)
            f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",  # 22. threatSeverity (SERVER IP)
            "GET",  # 23. riskScore (REQUEST METHOD)
            "200",  # 24. malwareCategory (RESPONSE CODE)
            random.choice(normal_user_agents),  # 25. malwareClass (USER AGENT)
            "None",  # 26. urlCategory
            "URLFilter",  # 27. urlSuperCategory
            f"Download_Allow_{270 + i}",  # 28. urlClass
            "Other",  # 29. appName
            "None",  # 30. appClass
            "NA",  # 31. appRiskScore
            "NA",  # 32. fileName
            "N/A"  # 33. fileType
        ]
        logs.append(log)
        log_id += 1
    
    # Response code anomalies (anomaly 7)
    for i in range(25):
        timestamp = base_time + timedelta(seconds=280 + i)
        log = [
            timestamp.strftime("%a %b %d %H:%M:%S %Y"),  # 0. timestamp
            "mkt-acme-corp",  # 1. login
            "HTTP",  # 2. department
            f"www.example.com/nonexistent{i}",  # 3. company
            "Allowed",  # 4. cloudName
            "Nonexistent Page",  # 5. clientIP
            "Technology",  # 6. clientInternalIP
            "40",  # 7. clientPublicIP
            "256",  # 8. serverIP
            "512",  # 9. location
            "768",  # 10. url
            "Technology",  # 11. host
            "Technology",  # 12. requestMethod
            "Web",  # 13. responseCode
            "None",  # 14. userAgent
            "None",  # 15. referer
            "0",  # 16. contentType
            "None",  # 17. action
            "None",  # 18. reason
            "mkt-acme-corp",  # 19. ruleType
            "Marketing Department",  # 20. ruleLabel
            f"172.17.3.{290 + i}",  # 21. threatName (CLIENT IP)
            f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",  # 22. threatSeverity (SERVER IP)
            "GET",  # 23. riskScore (REQUEST METHOD)
            "404",  # 24. malwareCategory (RESPONSE CODE) - High rate of 404 errors
            random.choice(normal_user_agents),  # 25. malwareClass (USER AGENT)
            "None",  # 26. urlCategory
            "URLFilter",  # 27. urlSuperCategory
            f"Web_Allow_{290 + i}",  # 28. urlClass
            "Other",  # 29. appName
            "None",  # 30. appClass
            "NA",  # 31. appRiskScore
            "NA",  # 32. fileName
            "N/A"  # 33. fileType
        ]
        logs.append(log)
        log_id += 1
    
    # Bandwidth anomalies (anomaly 8)
    for i in range(20):
        timestamp = base_time + timedelta(seconds=320 + i)
        log = [
            timestamp.strftime("%a %b %d %H:%M:%S %Y"),  # 0. timestamp
            "it-acme-corp",  # 1. login
            "HTTP",  # 2. department
            f"cdn.example.com/large-file{i}.zip",  # 3. company
            "Allowed",  # 4. cloudName
            f"Large File {i}",  # 5. clientIP
            "Technology",  # 6. clientInternalIP
            "30",  # 7. clientPublicIP
            "128",  # 8. serverIP
            "25600",  # 9. location - Large file downloads
            "25728",  # 10. url
            "Technology",  # 11. host
            "Technology",  # 12. requestMethod
            "Downloads",  # 13. responseCode
            "None",  # 14. userAgent
            "None",  # 15. referer
            "0",  # 16. contentType
            "None",  # 17. action
            "None",  # 18. reason
            "it-acme-corp",  # 19. ruleType
            "IT Department",  # 20. ruleLabel
            f"172.17.3.{320 + i}",  # 21. threatName (CLIENT IP)
            f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",  # 22. threatSeverity (SERVER IP)
            "GET",  # 23. riskScore (REQUEST METHOD)
            "200",  # 24. malwareCategory (RESPONSE CODE)
            random.choice(normal_user_agents),  # 25. malwareClass (USER AGENT)
            "None",  # 26. urlCategory
            "URLFilter",  # 27. urlSuperCategory
            f"CDN_Allow_{320 + i}",  # 28. urlClass
            "Other",  # 29. appName
            "None",  # 30. appClass
            "NA",  # 31. appRiskScore
            "NA",  # 32. fileName
            "N/A"  # 33. fileType
        ]
        logs.append(log)
        log_id += 1
    
    return logs

def write_csv(logs, filename):
    """Write logs to CSV file"""
    if not logs:
        return
    
    with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        for log in logs:
            writer.writerow(log)
    
    print(f"Generated {len(logs)} log entries in {filename}")

def main():
    """Main function"""
    print("Generating logs with EXACT same field structure as working sample_zscaler_logs.csv...")
    print("Note: This is a CUSTOM, SIMPLIFIED format, NOT the official Zscaler NSS feed format.")
    
    # Generate logs
    logs = generate_correct_logs()
    
    # Write to CSV
    write_csv(logs, 'data/correct_format_logs.csv')
    
    # Generate summary
    print("\nLog Summary:")
    print(f"Total entries: {len(logs)}")
    
    print("\nField mapping (EXACTLY matches your working sample):")
    print("  Field 21: clientIP (internal IP)")
    print("  Field 22: serverIP (external IP)")
    print("  Field 23: requestMethod")
    print("  Field 24: responseCode")
    print("  Field 25: userAgent")
    
    print("\nAnomaly patterns included:")
    print("  1. High-frequency requests from single IP (172.17.3.200)")
    print("  2. Suspicious user agents (sqlmap, nikto, curl, etc.)")
    print("  3. Geographic anomalies (multiple IPs from CN, RU, NG)")
    print("  4. Time-based traffic spikes")
    print("  5. SSL/TLS anomalies (HTTPS traffic)")
    print("  6. Suspicious file access (exe, dll, bat, etc.)")
    print("  7. Response code anomalies (high 404 rate)")
    print("  8. Bandwidth anomalies (large file downloads)")
    
    print("\nFile ready for testing anomaly detection!")
    print("Note: This file uses the EXACT same field structure as your working sample_zscaler_logs.csv")

if __name__ == "__main__":
    main()
