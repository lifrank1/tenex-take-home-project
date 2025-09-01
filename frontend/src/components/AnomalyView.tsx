'use client';

import React, { useState } from 'react';
import { AlertTriangle, AlertCircle, AlertOctagon, Info, ChevronDown, ChevronRight, Target, Clock, MapPin, Globe, FileText, Shield, Activity } from 'lucide-react';
import { Anomaly } from '../types';

interface AnomalyViewProps {
  anomalies: Anomaly[];
}

const AnomalyView: React.FC<AnomalyViewProps> = ({ anomalies = [] }) => {
  const [expandedAnomalies, setExpandedAnomalies] = useState<Set<string>>(new Set());

  if (!anomalies || anomalies.length === 0) {
    return (
      <div className="text-center py-12">
        <div className="text-gray-500 dark:text-gray-400">
          <Shield className="w-12 h-12 mx-auto mb-4 text-green-500" />
          <p>No anomalies detected.</p>
          <p className="text-sm mt-2">Your logs appear to show normal traffic patterns.</p>
        </div>
      </div>
    );
  }

  const toggleAnomaly = (anomalyId: string) => {
    const newExpanded = new Set(expandedAnomalies);
    if (newExpanded.has(anomalyId)) {
      newExpanded.delete(anomalyId);
    } else {
      newExpanded.add(anomalyId);
    }
    setExpandedAnomalies(newExpanded);
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'text-red-500 bg-red-50 border-red-200 dark:bg-red-900/20 dark:border-red-800';
      case 'high': return 'text-orange-500 bg-orange-50 border-orange-200 dark:bg-orange-900/20 dark:border-orange-800';
      case 'medium': return 'text-yellow-500 bg-yellow-50 border-yellow-200 dark:bg-yellow-900/20 dark:border-yellow-800';
      case 'low': return 'text-blue-500 bg-blue-50 border-blue-200 dark:bg-blue-900/20 dark:border-blue-800';
      default: return 'text-gray-500 bg-gray-50 border-gray-200 dark:bg-gray-900/20 dark:border-gray-800';
    }
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'critical': return <AlertOctagon className="w-5 h-5" />;
      case 'high': return <AlertTriangle className="w-5 h-5" />;
      case 'medium': return <AlertCircle className="w-5 h-5" />;
      case 'low': return <Info className="w-5 h-5" />;
      default: return <Info className="w-5 h-5" />;
    }
  };

  const getAnomalyTypeIcon = (type: string) => {
    switch (type) {
      case 'unusual_request_frequency': return <Activity className="w-4 h-4" />;
      case 'unusual_ip_behavior': return <Target className="w-4 h-4" />;
      case 'unusual_url_patterns': return <Globe className="w-4 h-4" />;
      case 'unusual_user_agent': return <FileText className="w-4 h-4" />;
      case 'unusual_geographic_access': return <MapPin className="w-4 h-4" />;
      case 'unusual_time_patterns': return <Clock className="w-4 h-4" />;
      case 'unusual_response_codes': return <AlertCircle className="w-4 h-4" />;
      case 'unusual_file_access': return <FileText className="w-4 h-4" />;
      case 'unusual_ssl_behavior': return <Shield className="w-4 h-4" />;
      case 'unusual_bandwidth_usage': return <Activity className="w-4 h-4" />;
      default: return <AlertTriangle className="w-4 h-4" />;
    }
  };

  const getAnomalyTypeLabel = (type: string): string => {
    switch (type) {
      case 'unusual_request_frequency': return 'Unusual Request Frequency';
      case 'unusual_ip_behavior': return 'Unusual IP Behavior';
      case 'unusual_url_patterns': return 'Unusual URL Patterns';
      case 'unusual_user_agent': return 'Suspicious User Agent';
      case 'unusual_geographic_access': return 'Unusual Geographic Access';
      case 'unusual_time_patterns': return 'Unusual Time Patterns';
      case 'unusual_response_codes': return 'Unusual Response Codes';
      case 'unusual_file_access': return 'Suspicious File Access';
      case 'unusual_ssl_behavior': return 'Unusual SSL Behavior';
      case 'unusual_bandwidth_usage': return 'Unusual Bandwidth Usage';
      default: return type.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
    }
  };

  const formatTimestamp = (timestamp: Date | string) => {
    const date = typeof timestamp === 'string' ? new Date(timestamp) : timestamp;
    return date.toLocaleString();
  };

  const getConfidenceColor = (confidence: number) => {
    if (confidence >= 90) return 'text-red-600 dark:text-red-400';
    if (confidence >= 80) return 'text-orange-600 dark:text-orange-400';
    if (confidence >= 70) return 'text-yellow-600 dark:text-yellow-400';
    return 'text-blue-600 dark:text-blue-400';
  };

  const getConfidenceLabel = (confidence: number) => {
    if (confidence >= 90) return 'Very High';
    if (confidence >= 80) return 'High';
    if (confidence >= 70) return 'Medium';
    return 'Low';
  };

  // Group anomalies by severity for better organization
  const groupedAnomalies = anomalies.reduce((groups, anomaly) => {
    const severity = anomaly.severity;
    if (!groups[severity]) {
      groups[severity] = [];
    }
    groups[severity].push(anomaly);
    return groups;
  }, {} as Record<string, Anomaly[]>);

  const severityOrder = ['critical', 'high', 'medium', 'low'];

  return (
    <div className="space-y-6">
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
          Anomaly Detection Summary
        </h3>
        
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
          <div className="bg-red-50 dark:bg-red-900/20 rounded-lg p-4">
            <div className="text-2xl font-bold text-red-600 dark:text-red-400">
              {anomalies.filter(a => a.severity === 'critical').length}
            </div>
            <div className="text-sm text-red-600 dark:text-red-400">Critical</div>
          </div>
          
          <div className="bg-orange-50 dark:bg-orange-900/20 rounded-lg p-4">
            <div className="text-2xl font-bold text-orange-600 dark:text-orange-400">
              {anomalies.filter(a => a.severity === 'high').length}
            </div>
            <div className="text-sm text-orange-600 dark:text-orange-400">High</div>
          </div>
          
          <div className="bg-yellow-50 dark:bg-yellow-900/20 rounded-lg p-4">
            <div className="text-2xl font-bold text-yellow-600 dark:text-yellow-400">
              {anomalies.filter(a => a.severity === 'medium').length}
            </div>
            <div className="text-sm text-yellow-600 dark:text-yellow-400">Medium</div>
          </div>
          
          <div className="bg-blue-50 dark:bg-blue-900/20 rounded-lg p-4">
            <div className="text-2xl font-bold text-blue-600 dark:text-blue-400">
              {anomalies.filter(a => a.severity === 'low').length}
            </div>
            <div className="text-sm text-blue-600 dark:text-blue-400">Low</div>
          </div>
        </div>

        <div className="text-sm text-gray-600 dark:text-gray-300">
          <p>Total anomalies detected: <span className="font-semibold">{anomalies.length}</span></p>
          <p>Average confidence score: <span className="font-semibold">
            {Math.round(anomalies.reduce((sum, a) => sum + a.confidence, 0) / anomalies.length)}%
          </span></p>
        </div>
      </div>

      {severityOrder.map(severity => {
        const severityAnomalies = groupedAnomalies[severity];
        if (!severityAnomalies || severityAnomalies.length === 0) return null;

        return (
          <div key={severity} className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700">
            <div className="p-6 border-b border-gray-200 dark:border-gray-700">
              <h4 className="text-lg font-semibold text-gray-900 dark:text-white flex items-center space-x-2">
                {getSeverityIcon(severity)}
                <span className="capitalize">{severity} Severity Anomalies</span>
                <span className="text-sm font-normal text-gray-500 dark:text-gray-400">
                  ({severityAnomalies.length})
                </span>
              </h4>
            </div>
            
            <div className="divide-y divide-gray-200 dark:divide-gray-700">
              {severityAnomalies.map((anomaly) => (
                <div key={anomaly.id} className="p-6 hover:bg-gray-50 dark:hover:bg-gray-700/50 transition-colors">
                  <div className="flex items-start space-x-4">
                    <div className={`p-2 rounded-lg border ${getSeverityColor(anomaly.severity)}`}>
                      {getAnomalyTypeIcon(anomaly.anomalyType)}
                    </div>
                    
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center space-x-3">
                          <h5 className="text-sm font-medium text-gray-900 dark:text-white">
                            {getAnomalyTypeLabel(anomaly.anomalyType)}
                          </h5>
                          <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getConfidenceColor(anomaly.confidence)} bg-opacity-10`}>
                            {anomaly.confidence}% Confidence
                          </span>
                          <span className="text-xs text-gray-500 dark:text-gray-400">
                            {getConfidenceLabel(anomaly.confidence)}
                          </span>
                        </div>
                        <span className="text-xs text-gray-500 dark:text-gray-400">
                          {formatTimestamp(anomaly.timestamp)}
                        </span>
                      </div>
                      
                      <p className="text-sm text-gray-600 dark:text-gray-300 mb-3">
                        {anomaly.explanation}
                      </p>

                      {anomaly.clientIP && (
                        <div className="text-sm text-gray-500 dark:text-gray-400 mb-2">
                          <span className="font-medium">Source IP:</span> {anomaly.clientIP}
                        </div>
                      )}

                      {anomaly.url && (
                        <div className="text-sm text-gray-500 dark:text-gray-400 mb-2">
                          <span className="font-medium">URL:</span> {anomaly.url}
                        </div>
                      )}
                      
                      <div className="mt-3">
                        <button
                          onClick={() => toggleAnomaly(anomaly.id)}
                          className="flex items-center space-x-1 text-xs text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300"
                        >
                          {expandedAnomalies.has(anomaly.id) ? (
                            <ChevronDown className="w-3 h-3" />
                          ) : (
                            <ChevronRight className="w-3 h-3" />
                          )}
                          <span>Show Details</span>
                        </button>
                        
                        {expandedAnomalies.has(anomaly.id) && (
                          <div className="mt-3 p-4 bg-gray-50 dark:bg-gray-700 rounded-lg">
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                              {Object.entries(anomaly.details).map(([key, value]) => (
                                <div key={key}>
                                  <span className="font-medium text-gray-700 dark:text-gray-300 capitalize">
                                    {key.replace(/([A-Z])/g, ' $1').trim()}:
                                  </span>
                                  <span className="ml-2 text-gray-600 dark:text-gray-400">
                                    {Array.isArray(value) ? value.join(', ') : String(value)}
                                  </span>
                                </div>
                              ))}
                            </div>
                            
                            {anomaly.relatedEntries.length > 0 && (
                              <div className="mt-3 pt-3 border-t border-gray-200 dark:border-gray-600">
                                <span className="text-sm font-medium text-gray-700 dark:text-gray-300">
                                  Related Log Entries: {anomaly.relatedEntries.length}
                                </span>
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        );
      })}
    </div>
  );
};

export default AnomalyView;
