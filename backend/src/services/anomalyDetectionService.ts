import { ParsedLogEntry, Anomaly, AnomalyType } from '../types';

export class AnomalyDetectionService {
  private readonly ANOMALY_THRESHOLDS = {
    requestFrequency: 3, // Multiplier for unusual request frequency
    timeWindow: 5 * 60 * 1000, // 5 minutes in milliseconds
    geographicDistance: 1000, // km
    responseCodeThreshold: 0.1, // 10% threshold for unusual response codes
    bandwidthThreshold: 2, // Multiplier for unusual bandwidth usage
    sslThreshold: 0.05, // 5% threshold for unusual SSL behavior
  };

  detectAnomalies(entries: ParsedLogEntry[]): Anomaly[] {
    if (entries.length === 0) return [];

    const anomalies: Anomaly[] = [];
    
    // Detect different types of anomalies
    // anomalies.push(...this.detectUnusualRequestFrequency(entries)); // Disabled - unrealistic expectations from time-based calculations
    // anomalies.push(...this.detectUnusualIPBehavior(entries)); // Disabled - too many false positives from normal app access
    anomalies.push(...this.detectUnusualURLPatterns(entries));
    anomalies.push(...this.detectUnusualUserAgents(entries));
    anomalies.push(...this.detectUnusualGeographicAccess(entries));
    anomalies.push(...this.detectUnusualTimePatterns(entries));
    anomalies.push(...this.detectUnusualResponseCodes(entries));
    anomalies.push(...this.detectUnusualFileAccess(entries));
    anomalies.push(...this.detectUnusualSSLBehavior(entries));
    anomalies.push(...this.detectUnusualBandwidthUsage(entries));

    // Remove duplicates and sort by confidence
    return this.deduplicateAnomalies(anomalies)
      .sort((a, b) => b.confidence - a.confidence);
  }

  private detectUnusualRequestFrequency(entries: ParsedLogEntry[]): Anomaly[] {
    const anomalies: Anomaly[] = [];
    const ipTimeMap = new Map<string, { count: number; firstSeen: Date; lastSeen: Date }>();

    // Group requests by IP and time
    entries.forEach(entry => {
      if (!entry.clientIP) return;
      
      const existing = ipTimeMap.get(entry.clientIP);
      if (existing) {
        existing.count++;
        existing.lastSeen = entry.timestamp;
      } else {
        ipTimeMap.set(entry.clientIP, {
          count: 1,
          firstSeen: entry.timestamp,
          lastSeen: entry.timestamp
        });
      }
    });

    // Calculate average requests per IP
    const totalRequests = entries.length;
    const uniqueIPs = ipTimeMap.size;
    const avgRequestsPerIP = totalRequests / uniqueIPs;

    ipTimeMap.forEach((data, ip) => {
      const timeSpan = data.lastSeen.getTime() - data.firstSeen.getTime();
      const requestsPerMinute = (data.count / (timeSpan / (60 * 1000))) || 0;
      const expectedRequestsPerMinute = (avgRequestsPerIP / (timeSpan / (60 * 1000))) || 0;

      if (requestsPerMinute > expectedRequestsPerMinute * this.ANOMALY_THRESHOLDS.requestFrequency) {
        const confidence = Math.min(95, Math.max(60, 
          (requestsPerMinute / (expectedRequestsPerMinute * this.ANOMALY_THRESHOLDS.requestFrequency)) * 100
        ));

        anomalies.push({
          id: `freq_${ip}_${Date.now()}`,
          timestamp: data.lastSeen,
          clientIP: ip,
          anomalyType: 'unusual_request_frequency',
          confidence: Math.round(confidence),
          explanation: `Unusual number of requests (${data.count} requests in ${Math.round(timeSpan / 1000)}s) from IP ${ip}. Expected: ~${Math.round(expectedRequestsPerMinute)} requests/min, Actual: ${Math.round(requestsPerMinute)} requests/min.`,
          severity: this.calculateSeverity(confidence),
          details: {
            requestCount: data.count,
            timeSpan: timeSpan,
            requestsPerMinute: requestsPerMinute,
            expectedRequestsPerMinute: expectedRequestsPerMinute,
            ratio: requestsPerMinute / expectedRequestsPerMinute
          },
          relatedEntries: entries
            .filter(e => e.clientIP === ip)
            .map(e => e.id)
            .slice(0, 10) // Limit to first 10 related entries
        });
      }
    });

    return anomalies;
  }

  private detectUnusualIPBehavior(entries: ParsedLogEntry[]): Anomaly[] {
    const anomalies: Anomaly[] = [];
    const ipBehaviorMap = new Map<string, {
      blockedCount: number;
      threatCount: number;
      uniqueURLs: Set<string>;
      uniqueUserAgents: Set<string>;
      totalRequests: number;
    }>();

    // Analyze IP behavior patterns
    entries.forEach(entry => {
      if (!entry.clientIP) return;
      
      const existing = ipBehaviorMap.get(entry.clientIP);
      if (existing) {
        existing.totalRequests++;
        if (entry.action?.toLowerCase().includes('block')) existing.blockedCount++;
        if (entry.threatName && entry.threatName !== 'None' && entry.threatName !== 'N/A') existing.threatCount++;
        if (entry.url) existing.uniqueURLs.add(entry.url);
        if (entry.userAgent) existing.uniqueUserAgents.add(entry.userAgent);
      } else {
        ipBehaviorMap.set(entry.clientIP, {
          blockedCount: entry.action?.toLowerCase().includes('block') ? 1 : 0,
          threatCount: (entry.threatName && entry.threatName !== 'None' && entry.threatName !== 'N/A') ? 1 : 0,
          uniqueURLs: new Set(entry.url ? [entry.url] : []),
          uniqueUserAgents: new Set(entry.userAgent ? [entry.userAgent] : []),
          totalRequests: 1
        });
      }
    });

    // Identify suspicious behavior patterns
    ipBehaviorMap.forEach((behavior, ip) => {
      const blockRate = behavior.blockedCount / behavior.totalRequests;
      const threatRate = behavior.threatCount / behavior.totalRequests;
      const urlDiversity = behavior.uniqueURLs.size / behavior.totalRequests;
      const userAgentDiversity = behavior.uniqueUserAgents.size / behavior.totalRequests;

      let confidence = 0;
      let explanation = '';
      let anomalyType: AnomalyType = 'unusual_ip_behavior';

      if (blockRate > 0.5) {
        confidence = Math.min(95, Math.max(60, blockRate * 100));
        explanation = `High block rate (${(blockRate * 100).toFixed(1)}%) for IP ${ip}. This IP had ${behavior.blockedCount} blocked requests out of ${behavior.totalRequests} total requests.`;
      } else if (threatRate > 0.3) {
        confidence = Math.min(95, Math.max(60, threatRate * 100));
        explanation = `High threat rate (${(threatRate * 100).toFixed(1)}%) for IP ${ip}. This IP triggered ${behavior.threatCount} threat detections out of ${behavior.totalRequests} total requests.`;
      } else if (urlDiversity > 0.8 && behavior.totalRequests > 10) {
        confidence = Math.min(85, Math.max(60, urlDiversity * 100));
        explanation = `Unusual URL diversity for IP ${ip}. This IP accessed ${behavior.uniqueURLs.size} unique URLs out of ${behavior.totalRequests} total requests (${(urlDiversity * 100).toFixed(1)}% diversity).`;
      } else if (userAgentDiversity > 0.7 && behavior.totalRequests > 5) {
        confidence = Math.min(80, Math.max(60, userAgentDiversity * 100));
        explanation = `Unusual user agent diversity for IP ${ip}. This IP used ${behavior.uniqueUserAgents.size} unique user agents out of ${behavior.totalRequests} total requests (${(userAgentDiversity * 100).toFixed(1)}% diversity).`;
      }

      if (confidence > 0) {
        anomalies.push({
          id: `behavior_${ip}_${Date.now()}`,
          timestamp: new Date(),
          clientIP: ip,
          anomalyType,
          confidence: Math.round(confidence),
          explanation,
          severity: this.calculateSeverity(confidence),
          details: {
            blockRate,
            threatRate,
            urlDiversity,
            userAgentDiversity,
            totalRequests: behavior.totalRequests,
            blockedCount: behavior.blockedCount,
            threatCount: behavior.threatCount,
            uniqueURLs: behavior.uniqueURLs.size,
            uniqueUserAgents: behavior.uniqueUserAgents.size
          },
          relatedEntries: entries
            .filter(e => e.clientIP === ip)
            .map(e => e.id)
            .slice(0, 10)
        });
      }
    });

    return anomalies;
  }

  private detectUnusualURLPatterns(entries: ParsedLogEntry[]): Anomaly[] {
    const anomalies: Anomaly[] = [];
    const urlPatterns = new Map<string, { count: number; ips: Set<string>; categories: Set<string> }>();

    // Analyze URL access patterns
    entries.forEach(entry => {
      if (!entry.url) return;
      
      const existing = urlPatterns.get(entry.url);
      if (existing) {
        existing.count++;
        if (entry.clientIP) existing.ips.add(entry.clientIP);
        if (entry.urlCategory) existing.categories.add(entry.urlCategory);
      } else {
        urlPatterns.set(entry.url, {
          count: 1,
          ips: new Set(entry.clientIP ? [entry.clientIP] : []),
          categories: new Set(entry.urlCategory ? [entry.urlCategory] : [])
        });
      }
    });

    // Identify unusual URL patterns
    const avgAccessPerURL = entries.length / urlPatterns.size;
    urlPatterns.forEach((pattern, url) => {
      if (pattern.count > avgAccessPerURL * 2) {
        const confidence = Math.min(90, Math.max(60, 
          (pattern.count / (avgAccessPerURL * 2)) * 100
        ));

        // Find the first and last timestamps for this URL
        const urlEntries = entries.filter(e => e.url === url);
        const firstTimestamp = urlEntries[0]?.timestamp || new Date();
        const lastTimestamp = urlEntries[urlEntries.length - 1]?.timestamp || new Date();
        
        anomalies.push({
          id: `url_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
          timestamp: lastTimestamp, // Use the last timestamp when anomaly was detected
          url,
          anomalyType: 'unusual_url_patterns',
          confidence: Math.round(confidence),
          explanation: `Unusual access pattern for URL: ${url}. This URL was accessed ${pattern.count} times by ${pattern.ips.size} unique IPs, which is ${(pattern.count / avgAccessPerURL).toFixed(1)}x the average access rate.`,
          severity: this.calculateSeverity(confidence),
          details: {
            accessCount: pattern.count,
            uniqueIPs: pattern.ips.size,
            categories: Array.from(pattern.categories),
            averageAccess: avgAccessPerURL,
            ratio: pattern.count / avgAccessPerURL
          },
          relatedEntries: entries
            .filter(e => e.url === url)
            .map(e => e.id)
            .slice(0, 10)
        });
      }
    });

    return anomalies;
  }

  private detectUnusualUserAgents(entries: ParsedLogEntry[]): Anomaly[] {
    const anomalies: Anomaly[] = [];
    const userAgentCounts = new Map<string, number>();
    const suspiciousPatterns = [
      /bot/i, /crawler/i, /spider/i, /scraper/i,
      /curl/i, /wget/i, /python/i, /java/i,
      /sqlmap/i, /nikto/i, /nmap/i, /metasploit/i
    ];

    // Count user agents and identify suspicious ones
    entries.forEach(entry => {
      if (!entry.userAgent) return;
      
      const count = userAgentCounts.get(entry.userAgent) || 0;
      userAgentCounts.set(entry.userAgent, count + 1);

      // Check for suspicious patterns
      const isSuspicious = suspiciousPatterns.some(pattern => pattern.test(entry.userAgent || ''));
      if (isSuspicious) {
        const confidence = Math.min(95, Math.max(70, 80 + Math.random() * 15));
        
        anomalies.push({
          id: `ua_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
          timestamp: entry.timestamp,
          clientIP: entry.clientIP,
          anomalyType: 'unusual_user_agent',
          confidence: Math.round(confidence),
          explanation: `Suspicious user agent detected: "${entry.userAgent}". This user agent matches known suspicious patterns and may indicate automated scanning or attack tools.`,
          severity: this.calculateSeverity(confidence),
          details: {
            userAgent: entry.userAgent,
            suspiciousPatterns: suspiciousPatterns.filter(p => p.test(entry.userAgent || '')).map(p => p.source),
            url: entry.url,
            action: entry.action
          },
          relatedEntries: [entry.id]
        });
      }
    });

    return anomalies;
  }

  private detectUnusualGeographicAccess(entries: ParsedLogEntry[]): Anomaly[] {
    const anomalies: Anomaly[] = [];
    const ipCountryMap = new Map<string, string>();
    const countryIPCounts = new Map<string, number>();

    // Build IP to country mapping
    entries.forEach(entry => {
      if (entry.clientIP && entry.sourceIPCountry) {
        ipCountryMap.set(entry.clientIP, entry.sourceIPCountry);
      }
    });

    // Count requests by country
    ipCountryMap.forEach((country, ip) => {
      const count = countryIPCounts.get(country) || 0;
      countryIPCounts.set(country, count + 1);
    });

    // Identify unusual geographic patterns
    const totalIPs = ipCountryMap.size;
    const avgIPsPerCountry = totalIPs / countryIPCounts.size;

    countryIPCounts.forEach((count, country) => {
      if (count > avgIPsPerCountry * 2) {
        const confidence = Math.min(85, Math.max(60, 
          (count / (avgIPsPerCountry * 2)) * 100
        ));

        // Find the first and last timestamps for this country
        const countryEntries = entries.filter(e => e.sourceIPCountry === country);
        const firstTimestamp = countryEntries[0]?.timestamp || new Date();
        const lastTimestamp = countryEntries[countryEntries.length - 1]?.timestamp || new Date();
        
        anomalies.push({
          id: `geo_${country}_${Date.now()}`,
          timestamp: lastTimestamp, // Use the last timestamp when anomaly was detected
          anomalyType: 'unusual_geographic_access',
          confidence: Math.round(confidence),
          explanation: `Unusual geographic access pattern from ${country}. This country has ${count} unique IPs, which is ${(count / avgIPsPerCountry).toFixed(1)}x the average per country.`,
          severity: this.calculateSeverity(confidence),
          details: {
            country,
            ipCount: count,
            averageIPsPerCountry: avgIPsPerCountry,
            ratio: count / avgIPsPerCountry
          },
          relatedEntries: entries
            .filter(e => e.sourceIPCountry === country)
            .map(e => e.id)
            .slice(0, 10)
        });
      }
    });

    return anomalies;
  }

  private detectUnusualTimePatterns(entries: ParsedLogEntry[]): Anomaly[] {
    const anomalies: Anomaly[] = [];
    const hourlyCounts = new Array(24).fill(0);
    const minuteCounts = new Array(60).fill(0);

    // Count requests by hour and minute
    entries.forEach(entry => {
      hourlyCounts[entry.timestamp.getHours()]++;
      minuteCounts[entry.timestamp.getMinutes()]++;
    });

    // Calculate averages
    const avgHourly = entries.length / 24;
    const avgMinute = entries.length / 60;

    // Check for unusual hourly patterns
    hourlyCounts.forEach((count, hour) => {
      if (count > avgHourly * 3) {
        const confidence = Math.min(90, Math.max(60, 
          (count / (avgHourly * 3)) * 100
        ));

        // Find the first and last timestamps for this hour
        const hourEntries = entries.filter(e => e.timestamp.getHours() === hour);
        const firstTimestamp = hourEntries[0]?.timestamp || new Date();
        const lastTimestamp = hourEntries[hourEntries.length - 1]?.timestamp || new Date();
        
        anomalies.push({
          id: `time_hour_${hour}_${Date.now()}`,
          timestamp: lastTimestamp, // Use the last timestamp when anomaly was detected
          anomalyType: 'unusual_time_patterns',
          confidence: Math.round(confidence),
          explanation: `Unusual traffic spike at ${hour}:00. This hour had ${count} requests, which is ${(count / avgHourly).toFixed(1)}x the average hourly traffic. Events occurred between ${firstTimestamp.toLocaleString()} and ${lastTimestamp.toLocaleString()}.`,
          severity: this.calculateSeverity(confidence),
          details: {
            hour,
            requestCount: count,
            averageHourly: avgHourly,
            ratio: count / avgHourly
          },
          relatedEntries: entries
            .filter(e => e.timestamp.getHours() === hour)
            .map(e => e.id)
            .slice(0, 10)
        });
      }
    });

    // Check for unusual minute patterns
    minuteCounts.forEach((count, minute) => {
      if (count > avgMinute * 5) {
        const confidence = Math.min(85, Math.max(60, 
          (count / (avgMinute * 5)) * 100
        ));

        // Find the first and last timestamps for this minute
        const minuteEntries = entries.filter(e => e.timestamp.getMinutes() === minute);
        const firstTimestamp = minuteEntries[0]?.timestamp || new Date();
        const lastTimestamp = minuteEntries[minuteEntries.length - 1]?.timestamp || new Date();
        
        anomalies.push({
          id: `time_minute_${minute}_${Date.now()}`,
          timestamp: lastTimestamp, // Use the last timestamp when anomaly was detected
          anomalyType: 'unusual_time_patterns',
          confidence: Math.round(confidence),
          explanation: `Unusual traffic spike at minute ${minute}. This minute had ${count} requests, which is ${(count / avgMinute).toFixed(1)}x the average minute traffic. Events occurred between ${firstTimestamp.toLocaleString()} and ${lastTimestamp.toLocaleString()}.`,
          severity: this.calculateSeverity(confidence),
          details: {
            minute,
            requestCount: count,
            averageMinute: avgMinute,
            ratio: count / avgMinute
          },
          relatedEntries: entries
            .filter(e => e.timestamp.getMinutes() === minute)
            .map(e => e.id)
            .slice(0, 10)
        });
      }
    });

    return anomalies;
  }

  private detectUnusualResponseCodes(entries: ParsedLogEntry[]): Anomaly[] {
    const anomalies: Anomaly[] = [];
    const responseCodeCounts = new Map<string, number>();
    const totalRequests = entries.length;

    // Count response codes
    entries.forEach(entry => {
      if (entry.responseCode) {
        const count = responseCodeCounts.get(entry.responseCode) || 0;
        responseCodeCounts.set(entry.responseCode, count + 1);
      }
    });

    // Identify unusual response code patterns
    responseCodeCounts.forEach((count, code) => {
      const percentage = count / totalRequests;
      
      // Flag unusual response codes
      if (code.startsWith('4') && percentage > this.ANOMALY_THRESHOLDS.responseCodeThreshold) {
        const confidence = Math.min(90, Math.max(60, percentage * 1000));
        
        // Find the first and last timestamps for this response code
        const responseEntries = entries.filter(e => e.responseCode === code);
        const firstTimestamp = responseEntries[0]?.timestamp || new Date();
        const lastTimestamp = responseEntries[responseEntries.length - 1]?.timestamp || new Date();
        
        anomalies.push({
          id: `response_${code}_${Date.now()}`,
          timestamp: lastTimestamp, // Use the last timestamp when anomaly was detected
          anomalyType: 'unusual_response_codes',
          confidence: Math.round(confidence),
          explanation: `Unusual number of ${code} response codes. ${(percentage * 100).toFixed(1)}% of requests returned this error code, which is above the normal threshold.`,
          severity: this.calculateSeverity(confidence),
          details: {
            responseCode: code,
            count,
            percentage,
            totalRequests
          },
          relatedEntries: entries
            .filter(e => e.responseCode === code)
            .map(e => e.id)
            .slice(0, 10)
        });
      }
    });

    return anomalies;
  }

  private detectUnusualFileAccess(entries: ParsedLogEntry[]): Anomaly[] {
    const anomalies: Anomaly[] = [];
    const fileAccessPatterns = new Map<string, { count: number; ips: Set<string>; extensions: Set<string> }>();

    // Analyze file access patterns
    entries.forEach(entry => {
      if (!entry.url) return;
      
      const url = new URL(entry.url, 'http://example.com');
      const pathname = url.pathname;
      const extension = pathname.split('.').pop()?.toLowerCase();
      
      if (extension && ['exe', 'dll', 'bat', 'cmd', 'ps1', 'vbs', 'js', 'jar', 'zip', 'rar'].includes(extension)) {
        const key = `${entry.clientIP}_${extension}`;
        const existing = fileAccessPatterns.get(key);
        
        if (existing) {
          existing.count++;
          if (entry.clientIP) existing.ips.add(entry.clientIP);
          existing.extensions.add(extension);
        } else {
          fileAccessPatterns.set(key, {
            count: 1,
            ips: new Set(entry.clientIP ? [entry.clientIP] : []),
            extensions: new Set([extension])
          });
        }
      }
    });

    // Identify suspicious file access patterns
    fileAccessPatterns.forEach((pattern, key) => {
      if (pattern.count > 3) {
        const confidence = Math.min(95, Math.max(70, 70 + pattern.count * 5));
        
        // Find the first and last timestamps for this file access pattern
        const fileEntries = entries.filter(e => {
          const url = new URL(e.url || 'http://example.com', 'http://example.com');
          const pathname = url.pathname;
          const extension = pathname.split('.').pop()?.toLowerCase();
          return extension && ['exe', 'dll', 'bat', 'cmd', 'ps1', 'vbs', 'js', 'jar', 'zip', 'rar'].includes(extension) && 
                 e.clientIP === Array.from(pattern.ips)[0];
        });
        const firstTimestamp = fileEntries[0]?.timestamp || new Date();
        const lastTimestamp = fileEntries[fileEntries.length - 1]?.timestamp || new Date();
        
        anomalies.push({
          id: `file_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
          timestamp: lastTimestamp, // Use the last timestamp when anomaly was detected
          clientIP: Array.from(pattern.ips)[0],
          anomalyType: 'unusual_file_access',
          confidence: Math.round(confidence),
          explanation: `Unusual file access pattern detected. Multiple suspicious file types (${Array.from(pattern.extensions).join(', ')}) were accessed ${pattern.count} times, which may indicate malicious activity.`,
          severity: this.calculateSeverity(confidence),
          details: {
            fileTypes: Array.from(pattern.extensions),
            accessCount: pattern.count,
            uniqueIPs: pattern.ips.size,
            ips: Array.from(pattern.ips)
          },
          relatedEntries: entries
            .filter(e => {
              const url = new URL(e.url || '', 'http://example.com');
              const ext = url.pathname.split('.').pop()?.toLowerCase();
              return ext && pattern.extensions.has(ext) && pattern.ips.has(e.clientIP || '');
            })
            .map(e => e.id)
            .slice(0, 10)
        });
      }
    });

    return anomalies;
  }

  private detectUnusualSSLBehavior(entries: ParsedLogEntry[]): Anomaly[] {
    const anomalies: Anomaly[] = [];
    const sslStats = {
      total: 0,
      decrypted: 0,
      oldTLS: 0,
      weakCiphers: 0
    };

    // Analyze SSL/TLS patterns
    entries.forEach(entry => {
      sslStats.total++;
      
      if (entry.sslDecrypted === 'Yes') sslStats.decrypted++;
      if (entry.clientTLSVersion && ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1'].includes(entry.clientTLSVersion)) {
        sslStats.oldTLS++;
      }
    });

    // Check for unusual SSL patterns
    if (sslStats.total > 0) {
      const decryptionRate = sslStats.decrypted / sslStats.total;
      const oldTLSRate = sslStats.oldTLS / sslStats.total;

      if (decryptionRate > 0.8) {
        const confidence = Math.min(85, Math.max(60, decryptionRate * 100));
        
        // Find the first and last timestamps for SSL decryption anomalies
        const sslEntries = entries.filter(e => e.clientTLSVersion);
        const firstTimestamp = sslEntries[0]?.timestamp || new Date();
        const lastTimestamp = sslEntries[sslEntries.length - 1]?.timestamp || new Date();
        
        anomalies.push({
          id: `ssl_decrypt_${Date.now()}`,
          timestamp: lastTimestamp, // Use the last timestamp when anomaly was detected
          anomalyType: 'unusual_ssl_behavior',
          confidence: Math.round(confidence),
          explanation: `High SSL decryption rate (${(decryptionRate * 100).toFixed(1)}%). This may indicate policy enforcement but could also suggest privacy concerns.`,
          severity: this.calculateSeverity(confidence),
          details: {
            decryptionRate,
            decryptedCount: sslStats.decrypted,
            totalSSL: sslStats.total
          },
          relatedEntries: entries
            .filter(e => e.sslDecrypted === 'Yes')
            .map(e => e.id)
            .slice(0, 10)
        });
      }

      if (oldTLSRate > this.ANOMALY_THRESHOLDS.sslThreshold) {
        const confidence = Math.min(90, Math.max(60, oldTLSRate * 1000));
        
        // Find the first and last timestamps for old TLS anomalies
        const oldTLSEntries = entries.filter(e => e.clientTLSVersion && ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1'].includes(e.clientTLSVersion));
        const firstTimestamp = oldTLSEntries[0]?.timestamp || new Date();
        const lastTimestamp = oldTLSEntries[oldTLSEntries.length - 1]?.timestamp || new Date();
        
        anomalies.push({
          id: `ssl_oldtls_${Date.now()}`,
          timestamp: lastTimestamp, // Use the last timestamp when anomaly was detected
          anomalyType: 'unusual_ssl_behavior',
          confidence: Math.round(confidence),
          explanation: `Unusual number of old TLS connections (${(oldTLSRate * 100).toFixed(1)}%). This may indicate outdated clients or potential security risks.`,
          severity: this.calculateSeverity(confidence),
          details: {
            oldTLSRate,
            oldTLSCount: sslStats.oldTLS,
            totalSSL: sslStats.total
          },
          relatedEntries: entries
            .filter(e => e.clientTLSVersion && ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1'].includes(e.clientTLSVersion))
            .map(e => e.id)
            .slice(0, 10)
        });
      }
    }

    return anomalies;
  }

  private detectUnusualBandwidthUsage(entries: ParsedLogEntry[]): Anomaly[] {
    const anomalies: Anomaly[] = [];
    const ipBandwidthMap = new Map<string, { totalSize: number; requestCount: number }>();

    // Calculate bandwidth usage per IP
    entries.forEach(entry => {
      if (!entry.clientIP) return;
      
      const existing = ipBandwidthMap.get(entry.clientIP);
      const requestSize = entry.requestSize || 0;
      const responseSize = entry.responseSize || 0;
      const totalSize = requestSize + responseSize;
      
      if (existing) {
        existing.totalSize += totalSize;
        existing.requestCount++;
      } else {
        ipBandwidthMap.set(entry.clientIP, {
          totalSize,
          requestCount: 1
        });
      }
    });

    // Identify unusual bandwidth patterns
    const totalBandwidth = Array.from(ipBandwidthMap.values()).reduce((sum, data) => sum + data.totalSize, 0);
    const avgBandwidthPerIP = totalBandwidth / ipBandwidthMap.size;

    ipBandwidthMap.forEach((data, ip) => {
      if (data.totalSize > avgBandwidthPerIP * this.ANOMALY_THRESHOLDS.bandwidthThreshold) {
        const confidence = Math.min(90, Math.max(60, 
          (data.totalSize / (avgBandwidthPerIP * this.ANOMALY_THRESHOLDS.bandwidthThreshold)) * 100
        ));

        // Find the first and last timestamps for this IP's bandwidth usage
        const ipEntries = entries.filter(e => e.clientIP === ip);
        const firstTimestamp = ipEntries[0]?.timestamp || new Date();
        const lastTimestamp = ipEntries[ipEntries.length - 1]?.timestamp || new Date();
        
        anomalies.push({
          id: `bandwidth_${ip}_${Date.now()}`,
          timestamp: lastTimestamp, // Use the last timestamp when anomaly was detected
          clientIP: ip,
          anomalyType: 'unusual_bandwidth_usage',
          confidence: Math.round(confidence),
          explanation: `Unusual bandwidth usage from IP ${ip}. This IP used ${(data.totalSize / (1024 * 1024)).toFixed(2)} MB, which is ${(data.totalSize / avgBandwidthPerIP).toFixed(1)}x the average bandwidth per IP. Events occurred between ${firstTimestamp.toLocaleString()} and ${lastTimestamp.toLocaleString()}.`,
          severity: this.calculateSeverity(confidence),
          details: {
            totalSize: data.totalSize,
            requestCount: data.requestCount,
            averageBandwidthPerIP: avgBandwidthPerIP,
            ratio: data.totalSize / avgBandwidthPerIP,
            sizeInMB: data.totalSize / (1024 * 1024)
          },
          relatedEntries: entries
            .filter(e => e.clientIP === ip)
            .map(e => e.id)
            .slice(0, 10)
        });
      }
    });

    return anomalies;
  }

  private calculateSeverity(confidence: number): 'low' | 'medium' | 'high' | 'critical' {
    if (confidence >= 90) return 'critical';
    if (confidence >= 80) return 'high';
    if (confidence >= 70) return 'medium';
    return 'low';
  }

  private deduplicateAnomalies(anomalies: Anomaly[]): Anomaly[] {
    const seen = new Set<string>();
    return anomalies.filter(anomaly => {
      const key = `${anomaly.anomalyType}_${anomaly.clientIP || anomaly.url || 'unknown'}`;
      if (seen.has(key)) {
        return false;
      }
      seen.add(key);
      return true;
    });
  }
}
