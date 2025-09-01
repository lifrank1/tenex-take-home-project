import { ParsedLogEntry } from '../types';

export class LogParser {
  static parseLogLine(line: string): ParsedLogEntry | null {
    const fields = this.parseCSVLine(line);
    
    if (fields.length < 20) {
      return null;
    }

    const timestamp = this.parseZscalerTimestamp(fields[0]);
    if (!timestamp) {
      return null;
    }

    const entry: ParsedLogEntry = {
      id: crypto.randomUUID(),
      timestamp,
      
      login: fields[1],
      department: fields[20],
      company: fields[1],
      
      clientIP: fields[21],
      clientInternalIP: fields[21],
      clientPublicIP: fields[21],
      serverIP: fields[22],
      location: fields[1],
      
      url: fields[3],
      host: fields[3],
      requestMethod: fields[23],
      responseCode: fields[24],
      userAgent: fields[25],
      referer: fields[25],
      contentType: fields[32],
      
      action: fields[4],
      reason: fields[11],
      ruleType: fields[27],
      ruleLabel: fields[28],
      
      threatName: fields[5],
      threatSeverity: fields[4],
      riskScore: this.parseNumber(fields[7]),
      malwareCategory: fields[6],
      malwareClass: fields[6],
      
      urlCategory: fields[13],
      urlSuperCategory: fields[12],
      urlClass: fields[11],
      
      appName: fields[5],
      appClass: fields[6],
      appRiskScore: fields[7],
      
      fileName: fields[32],
      fileType: fields[32],
      fileClass: fields[32],
      
      sslDecrypted: fields[32],
      clientTLSVersion: fields[32],
      serverTLSVersion: fields[32],
      
      requestSize: this.parseNumber(fields[8]),
      responseSize: this.parseNumber(fields[9]),
      totalSize: this.parseNumber(fields[10]),
      
      sourceIPCountry: fields[32],
      destinationIPCountry: fields[32],
      
      deviceHostname: fields[32],
      deviceType: fields[32],
      deviceOSType: fields[32],
      
      dlpDictionary: fields[32],
      dlpEngine: fields[32],
      dlpRuleName: fields[32],
    };

    if (!entry.clientIP || !entry.url) {
      return null;
    }

    return entry;
  }

  private static parseZscalerTimestamp(timestamp: string): Date | null {
    const cleanTimestamp = timestamp.replace(/"/g, '');
    const date = new Date(cleanTimestamp);
    
    if (!isNaN(date.getTime())) {
      return date;
    }
    
    return null;
  }

  private static parseCSVLine(line: string): string[] {
    const fields: string[] = [];
    let current = '';
    let inQuotes = false;
    let i = 0;

    while (i < line.length) {
      const char = line[i];
      
      if (char === '"') {
        inQuotes = !inQuotes;
      } else if (char === ',' && !inQuotes) {
        fields.push(current.trim());
        current = '';
      } else {
        current += char;
      }
      
      i++;
    }
    
    fields.push(current.trim());
    return fields;
  }

  private static parseNumber(value: string): number | undefined {
    if (!value || value === '-' || value === 'None' || value === 'N/A' || value === 'NA') return undefined;
    const parsed = parseInt(value, 10);
    return isNaN(parsed) ? undefined : parsed;
  }

  static detectFormat(sampleLines: string[]): 'csv' | 'tsv' {
    if (sampleLines.length === 0) return 'csv';
    
    const firstLine = sampleLines[0];
    const commaCount = (firstLine.match(/,/g) || []).length;
    const tabCount = (firstLine.match(/\t/g) || []).length;
    
    return tabCount > commaCount ? 'tsv' : 'csv';
  }

  static validateLogFormat(content: string): boolean {
    const lines = content.split('\n').filter(line => line.trim());
    
    if (lines.length === 0) {
      return false;
    }
    
    const sampleLines = lines.slice(0, Math.min(5, lines.length));
    const validationResults = sampleLines.map(line => {
      const fields = this.parseCSVLine(line);
      return fields.length >= 20;
    });
    
    return validationResults.every(result => result);
  }
}
