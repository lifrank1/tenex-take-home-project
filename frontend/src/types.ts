// Frontend types - imported from backend types

export interface User {
  id: string;
  username: string;
  email: string;
  createdAt: string;
  updatedAt: string;
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
  details: Record<string, string | number | boolean | null | undefined>;
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

export interface TimelineEvent {
  id: string;
  type: 'log_entry' | 'event_cluster' | 'ip_cluster' | 'daily_summary' | 'hourly_summary';
  timestamp: string;
  title: string;
  summary: string;
  details: Record<string, string | number | boolean | null | undefined>;
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
  anomalies?: Anomaly[];
}

export interface ApiResponse<T = unknown> {
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
