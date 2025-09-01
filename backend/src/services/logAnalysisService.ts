import { ParsedLogEntry, LogAnalysis, TimelineEvent, TimelineSummary } from '../types';
import { AnomalyDetectionService } from './anomalyDetectionService';

export class LogAnalysisService {
  private anomalyDetectionService: AnomalyDetectionService;

  constructor() {
    this.anomalyDetectionService = new AnomalyDetectionService();
  }

  analyzeLogs(entries: ParsedLogEntry[]): LogAnalysis {
    if (entries.length === 0) {
      return this.getEmptyAnalysis();
    }

    const timelineEvents = this.generateTimelineEvents(entries);
    const timelineSummary = this.generateTimelineSummary(entries);
    const keyInsights = this.generateKeyInsights(entries);
    const anomalies = this.anomalyDetectionService.detectAnomalies(entries);

    return {
      totalRequests: entries.length,
      blockedRequests: this.countBlockedRequests(entries),
      allowedRequests: this.countAllowedRequests(entries),
      uniqueIPs: this.countUniqueIPs(entries),
      uniqueURLs: this.countUniqueURLs(entries),
      topThreats: this.getTopApplications(entries),
      topCategories: this.getTopCategories(entries),
      topSourceIPs: this.getTopSourceIPs(entries),
      hourlyBreakdown: this.getHourlyBreakdown(entries),
      dailyBreakdown: this.getDailyBreakdown(entries),
      suspiciousIPs: this.identifySuspiciousIPs(entries),
      highSeverityEvents: this.countHighSeverityEvents(entries),
      anomalies,
      timelineEvents,
      timelineSummary,
      keyInsights
    };
  }

  private countBlockedRequests(entries: ParsedLogEntry[]): number {
    return entries.filter(entry => 
      entry.action?.toLowerCase().includes('block')
    ).length;
  }

  private countAllowedRequests(entries: ParsedLogEntry[]): number {
    return entries.filter(entry => 
      entry.action?.toLowerCase().includes('allow')
    ).length;
  }

  private countUniqueIPs(entries: ParsedLogEntry[]): number {
    return new Set(entries.map(entry => entry.clientIP).filter(Boolean)).size;
  }

  private countUniqueURLs(entries: ParsedLogEntry[]): number {
    return new Set(entries.map(entry => entry.url).filter(Boolean)).size;
  }

  private getTopApplications(entries: ParsedLogEntry[]): { name: string; count: number }[] {
    const appCounts = new Map<string, number>();
    
    entries.forEach(entry => {
      // Use appName if available, otherwise fall back to threatName (which is actually the app name)
      const appName = entry.appName || entry.threatName;
      if (appName && appName !== 'None' && appName !== 'N/A') {
        const count = appCounts.get(appName) || 0;
        appCounts.set(appName, count + 1);
      }
    });

    return Array.from(appCounts.entries())
      .map(([name, count]) => ({ name, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);
  }

  private getTopCategories(entries: ParsedLogEntry[]): { name: string; count: number }[] {
    const categoryCounts = new Map<string, number>();
    
    entries.forEach(entry => {
      const category = entry.urlCategory || entry.appClass || 'Unknown';
      if (category && category !== 'None' && category !== 'N/A') {
        const count = categoryCounts.get(category) || 0;
        categoryCounts.set(category, count + 1);
      }
    });

    return Array.from(categoryCounts.entries())
      .map(([name, count]) => ({ name, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);
  }

  private getTopSourceIPs(entries: ParsedLogEntry[]): { ip: string; count: number }[] {
    const ipCounts = new Map<string, number>();
    
    entries.forEach(entry => {
      if (entry.clientIP) {
        const count = ipCounts.get(entry.clientIP) || 0;
        ipCounts.set(entry.clientIP, count + 1);
      }
    });

    return Array.from(ipCounts.entries())
      .map(([ip, count]) => ({ ip, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);
  }

  private getHourlyBreakdown(entries: ParsedLogEntry[]): { hour: string; count: number }[] {
    const hourlyCounts: Record<string, number> = {};
    
    entries.forEach(entry => {
      const hour = entry.timestamp.getHours().toString().padStart(2, '0');
      const key = `${hour}:00`;
      hourlyCounts[key] = (hourlyCounts[key] || 0) + 1;
    });

    return Object.entries(hourlyCounts).map(([hour, count]) => ({ hour, count }));
  }

  private getDailyBreakdown(entries: ParsedLogEntry[]): { date: string; count: number }[] {
    const dailyCounts: Record<string, number> = {};
    
    entries.forEach(entry => {
      const date = entry.timestamp.toISOString().split('T')[0];
      dailyCounts[date] = (dailyCounts[date] || 0) + 1;
    });

    return Object.entries(dailyCounts).map(([date, count]) => ({ date, count }));
  }

  private identifySuspiciousIPs(entries: ParsedLogEntry[]): string[] {
    const suspiciousIPs = new Set<string>();
    
    const ipCounts = new Map<string, number>();
    entries.forEach(entry => {
      if (entry.clientIP) {
        const count = ipCounts.get(entry.clientIP) || 0;
        ipCounts.set(entry.clientIP, count + 1);
      }
    });

    const avgRequests = entries.length / ipCounts.size;
    const threshold = avgRequests * 3;

    ipCounts.forEach((count, ip) => {
      if (count > threshold) {
        suspiciousIPs.add(ip);
      }
    });

    entries.forEach(entry => {
      if (entry.action?.toLowerCase().includes('block') && entry.clientIP) {
        suspiciousIPs.add(entry.clientIP);
      }
    });

    entries.forEach(entry => {
      if (entry.threatSeverity?.toLowerCase().includes('high') || 
          entry.threatSeverity?.toLowerCase().includes('critical')) {
        if (entry.clientIP) {
          suspiciousIPs.add(entry.clientIP);
        }
      }
    });

    return Array.from(suspiciousIPs);
  }

  private countHighSeverityEvents(entries: ParsedLogEntry[]): number {
    return entries.filter(entry => 
      entry.threatSeverity?.toLowerCase().includes('high') ||
      entry.threatSeverity?.toLowerCase().includes('critical')
    ).length;
  }

  private generateTimelineEvents(entries: ParsedLogEntry[]): TimelineEvent[] {
    if (!entries || entries.length === 0) {
      return [];
    }
    
    const events: TimelineEvent[] = entries
      .sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime())
      .map((entry, index) => ({
        id: entry.id || `event-${index}`,
        type: this.getEventType(entry),
        timestamp: entry.timestamp.toISOString(),
        title: this.generateEventTitle(entry),
        summary: this.generateEventSummary(entry),
        details: {
          clientIP: entry.clientIP,
          serverIP: entry.serverIP,
          url: entry.url,
          action: entry.action,
          urlCategory: entry.urlCategory,
          threatName: entry.threatName,
          threatSeverity: entry.threatSeverity,
          requestMethod: entry.requestMethod,
          responseCode: entry.responseCode,
          sourceIPCountry: entry.sourceIPCountry,
          destinationIPCountry: entry.destinationIPCountry,
          userAgent: entry.userAgent,
          reason: entry.reason,
          appName: entry.appName,
          appClass: entry.appClass,
          riskScore: entry.riskScore,
          location: entry.location,
          department: entry.department
        },
        severity: this.mapSeverity(entry.threatSeverity),
        isExpandable: true
      }));
    
    return events;
  }

  private generateTimelineSummary(entries: ParsedLogEntry[]): TimelineSummary {
    const blocked = this.countBlockedRequests(entries);
    const allowed = entries.length - blocked; // All non-blocked events are considered allowed
    const anomalies = this.countHighSeverityEvents(entries);

    return {
      totalEvents: entries.length,
      eventBreakdown: {
        blocked,
        allowed,
        anomalies
      }
    };
  }

  private getEventType(entry: ParsedLogEntry): 'log_entry' | 'event_cluster' | 'ip_cluster' | 'daily_summary' | 'hourly_summary' {
    if (entry.action?.toLowerCase().includes('block')) {
      return 'event_cluster'; // Blocked events get special attention
    }
    
    // High-risk applications (HR data, admin access, etc.)
    const appName = entry.appName || entry.threatName;
    if (appName && (appName.includes('HR') || appName.includes('Admin') || appName.includes('Salary'))) {
      return 'ip_cluster'; // Sensitive access gets highlighted
    }
    
    return 'log_entry'; // Regular application access
  }

  private mapSeverity(severity?: string): 'low' | 'medium' | 'high' | 'critical' {
    if (!severity) return 'low';
    
    const severityLower = severity.toLowerCase();
    if (severityLower.includes('critical')) return 'critical';
    if (severityLower.includes('high')) return 'high';
    if (severityLower.includes('medium')) return 'medium';
    return 'low';
  }

  private generateEventTitle(entry: ParsedLogEntry): string {
    if (entry.action?.toLowerCase().includes('block')) {
      return `Blocked ${entry.requestMethod || 'request'} from ${entry.clientIP || 'unknown IP'}`;
    }
    
    // Use appName or threatName (which is actually the application name in your logs)
    const appName = entry.appName || entry.threatName;
    if (appName && appName !== 'None' && appName !== 'N/A') {
      return `${appName} access from ${entry.clientIP || 'unknown IP'}`;
    }
    
    // Fallback to URL-based title
    if (entry.url) {
      const domain = entry.url.split('/')[0];
      return `${entry.requestMethod || 'Request'} to ${domain} from ${entry.clientIP || 'unknown IP'}`;
    }
    
    return `Request from ${entry.clientIP || 'unknown IP'}`;
  }

  private generateEventSummary(entry: ParsedLogEntry): string {
    const parts = [];
    
    // Action (Allowed/Blocked)
    if (entry.action) parts.push(entry.action);
    
    // Application category (Productivity, HR, Cloud Storage, etc.)
    if (entry.appClass && entry.appClass !== 'None' && entry.appClass !== 'N/A') {
      parts.push(entry.appClass);
    }
    
    // Application name (Work Dashboard, HR Salary Data, Cloud Upload, etc.)
    const appName = entry.appName || entry.threatName;
    if (appName && appName !== 'None' && appName !== 'N/A') {
      parts.push(appName);
    }
    
    // HTTP method if available
    if (entry.requestMethod && entry.requestMethod !== 'None') {
      parts.push(entry.requestMethod);
    }
    
    return parts.join(' • ');
  }

  private generateKeyInsights(entries: ParsedLogEntry[]): string[] {
    const insights: string[] = [];
    
    // Most accessed applications
    const appNames = this.getTopApplications(entries);
    if (appNames.length > 0 && appNames[0].count > 0) {
      insights.push(`Most accessed application: ${appNames[0].name} (${appNames[0].count} accesses)`);
    }
    
    const suspiciousIPs = this.identifySuspiciousIPs(entries);
    if (suspiciousIPs.length > 0) {
      insights.push(`${suspiciousIPs.length} suspicious IP addresses identified`);
    }
    
    const blockRate = (this.countBlockedRequests(entries) / entries.length) * 100;
    if (blockRate > 10) {
      insights.push(`High block rate: ${blockRate.toFixed(1)}% of requests were blocked`);
    }
    
    const highRiskEntries = entries.filter(e => e.riskScore && e.riskScore > 70);
    if (highRiskEntries.length > 0) {
      insights.push(`${highRiskEntries.length} high-risk requests detected (risk score > 70)`);
    }
    
    const appCategories = new Set(entries.map(e => e.appClass).filter(Boolean));
    if (appCategories.size > 0) {
      insights.push(`Traffic spans ${appCategories.size} application categories`);
    }

    // Add anomaly insights
    const anomalies = this.anomalyDetectionService.detectAnomalies(entries);
    if (anomalies.length > 0) {
      const criticalAnomalies = anomalies.filter(a => a.severity === 'critical').length;
      const highAnomalies = anomalies.filter(a => a.severity === 'high').length;
      
      if (criticalAnomalies > 0) {
        insights.push(`${criticalAnomalies} critical anomalies detected requiring immediate attention`);
      }
      if (highAnomalies > 0) {
        insights.push(`${highAnomalies} high-severity anomalies identified`);
      }
      insights.push(`${anomalies.length} total anomalies detected with confidence scores ranging from ${Math.min(...anomalies.map(a => a.confidence))}% to ${Math.max(...anomalies.map(a => a.confidence))}%`);
    }
    
    return insights;
  }

  private getEmptyAnalysis(): LogAnalysis {
    return {
      totalRequests: 0,
      blockedRequests: 0,
      allowedRequests: 0,
      uniqueIPs: 0,
      uniqueURLs: 0,
      topThreats: [],
      topCategories: [],
      topSourceIPs: [],
      hourlyBreakdown: [],
      dailyBreakdown: [],
      suspiciousIPs: [],
      highSeverityEvents: 0,
      anomalies: [],
      timelineEvents: [],
      timelineSummary: {
        totalEvents: 0,
        eventBreakdown: {
          blocked: 0,
          allowed: 0,
          anomalies: 0
        }
      },
      keyInsights: []
    };
  }
}
