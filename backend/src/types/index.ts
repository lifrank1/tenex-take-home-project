import { Request } from 'express';

// Extend Express Request to include user information
export interface AuthenticatedRequest extends Request {
  user?: {
    id: string;
    username: string;
    email: string;
  };
}

// User types
export interface User {
  id: string;
  username: string;
  email: string;
  createdAt: string;
  updatedAt: string;
}

// File upload types
export interface FileUploadInfo {
  filename: string;
  originalName: string;
  fileSize: number;
  uploadDate: Date;
}

export interface LogFile {
  id: string;
  filename: string;
  originalName: string;
  fileSize: number;
  uploadDate: string;
  status: 'processing' | 'completed' | 'error';
  totalEntries: number;
  userId: string;
}

export interface LogEntry {
  id: string;
  timestamp: string;
  sourceIP: string;
  destinationIP?: string;
  url?: string;
  action?: string;
  userAgent?: string;
  category?: string;
  threatName?: string;
  severity?: string;
  reason?: string;
  method?: string;
  statusCode?: number;
  bytesSent?: number;
  bytesReceived?: number;
  referer?: string;
  country?: string;
  city?: string;
  logFileId: string;
}

// Log parsing types - Updated to match Zscaler web proxy log format
export interface ParsedLogEntry {
  id: string;
  timestamp: Date;
  
  // User Information
  login?: string;
  department?: string;
  company?: string;
  cloudName?: string;
  
  // Network
  clientIP?: string;
  clientInternalIP?: string;
  clientPublicIP?: string;
  serverIP?: string;
  location?: string;
  
  // HTTP Transaction
  url?: string;
  host?: string;
  requestMethod?: string;
  responseCode?: string;
  userAgent?: string;
  referer?: string;
  contentType?: string;
  
  // Policy and Action
  action?: string;
  reason?: string;
  ruleType?: string;
  ruleLabel?: string;
  
  // Threat Protection
  threatName?: string;
  threatSeverity?: string;
  riskScore?: number;
  malwareCategory?: string;
  malwareClass?: string;
  
  // URL Categorization
  urlCategory?: string;
  urlSuperCategory?: string;
  urlClass?: string;
  
  // Cloud Application
  appName?: string;
  appClass?: string;
  appRiskScore?: string;
  
  // File Information
  fileName?: string;
  fileType?: string;
  fileClass?: string;
  
  // SSL Information
  sslDecrypted?: string;
  clientTLSVersion?: string;
  serverTLSVersion?: string;
  
  // Bandwidth and Size
  requestSize?: number;
  responseSize?: number;
  totalSize?: number;
  
  // Geographic Information
  sourceIPCountry?: string;
  destinationIPCountry?: string;
  
  // Device Information
  deviceHostname?: string;
  deviceType?: string;
  deviceOSType?: string;
  
  // DLP Information
  dlpDictionary?: string;
  dlpEngine?: string;
  dlpRuleName?: string;
}

// Timeline-specific types
export interface TimelineEvent {
  id: string;
  type: 'log_entry' | 'event_cluster' | 'ip_cluster' | 'daily_summary' | 'hourly_summary';
  timestamp: string;
  title: string;
  summary: string;
  details: Record<string, any>;
  severity: 'low' | 'medium' | 'high' | 'critical';
  isExpandable: boolean;
}

export interface TimelineSummary {
  totalEvents: number;
  eventBreakdown: {
    blocked: number;
    allowed: number;
    anomalies: number;
  };
}

export interface TimelineAnalysis {
  timelineEvents: TimelineEvent[];
  timelineSummary: TimelineSummary;
  keyInsights: string[];
}

// Anomaly detection types
export interface Anomaly {
  id: string;
  timestamp: Date;
  clientIP?: string;
  url?: string;
  anomalyType: AnomalyType;
  confidence: number;
  explanation: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  details: Record<string, any>;
  relatedEntries: string[]; // IDs of related log entries
}

export type AnomalyType = 
  | 'unusual_request_frequency'
  | 'unusual_ip_behavior'
  | 'unusual_url_patterns'
  | 'unusual_user_agent'
  | 'unusual_geographic_access'
  | 'unusual_time_patterns'
  | 'unusual_response_codes'
  | 'unusual_file_access'
  | 'unusual_ssl_behavior'
  | 'unusual_bandwidth_usage';

// Analysis types
export interface LogAnalysis {
  totalRequests: number;
  blockedRequests: number;
  allowedRequests: number;
  uniqueIPs: number;
  uniqueURLs: number;
  topThreats: { name: string; count: number }[];
  topCategories: { name: string; count: number }[];
  topSourceIPs: { ip: string; count: number }[];
  hourlyBreakdown: { hour: string; count: number }[];
  dailyBreakdown: { date: string; count: number }[];
  suspiciousIPs: string[];
  highSeverityEvents: number;
  anomalies: Anomaly[];
  timelineEvents: TimelineEvent[];
  timelineSummary: TimelineSummary;
  keyInsights: string[];
}

// API Response types
export interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  message?: string;
  error?: string;
}

export interface LoginRequest {
  username: string;
  password: string;
}

export interface LoginResponse {
  user: User;
  token: string;
}

export interface UploadResponse {
  logFile: LogFile;
  message: string;
}

export interface LogFileWithAnalysis {
  logFile: LogFile;
  analysis: TimelineAnalysis;
}

// Error types
export interface AppError {
  message: string;
  statusCode: number;
  error?: any;
}
