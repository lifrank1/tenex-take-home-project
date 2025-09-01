'use client';

import React, { useState } from 'react';
import { Clock, AlertTriangle, Shield, Eye, ChevronDown, ChevronRight, Activity } from 'lucide-react';
import { TimelineEvent, TimelineSummary, Anomaly } from '../types';
import AnomalyView from './AnomalyView';

interface TimelineViewProps {
  timelineEvents: TimelineEvent[];
  timelineSummary: TimelineSummary;
  keyInsights: string[];
  anomalies?: Anomaly[];
}

const TimelineView: React.FC<TimelineViewProps> = ({ 
  timelineEvents = [], 
  timelineSummary, 
  keyInsights = [],
  anomalies = []
}) => {
  const [expandedEvents, setExpandedEvents] = useState<Set<string>>(new Set());
  const [activeTab, setActiveTab] = useState<'timeline' | 'anomalies'>('timeline');

  const safeTimelineSummary = timelineSummary || {
    totalEvents: 0,
    eventBreakdown: {
      blocked: 0,
      allowed: 0,
      anomalies: 0
    }
  };

  const safeTimelineEvents = Array.isArray(timelineEvents) ? timelineEvents : [];
  const safeKeyInsights = Array.isArray(keyInsights) ? keyInsights : [];
  const safeAnomalies = Array.isArray(anomalies) ? anomalies : [];

  if (!safeTimelineEvents.length && !safeTimelineSummary.totalEvents && !safeAnomalies.length) {
    return (
      <div className="text-center py-12">
        <div className="text-gray-500 dark:text-gray-400">
          <p>No data available.</p>
          <p className="text-sm mt-2">The analysis may still be processing or no events were found.</p>
        </div>
      </div>
    );
  }

  const toggleEvent = (eventId: string) => {
    const newExpanded = new Set(expandedEvents);
    if (newExpanded.has(eventId)) {
      newExpanded.delete(eventId);
    } else {
      newExpanded.add(eventId);
    }
    setExpandedEvents(newExpanded);
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'text-red-500 bg-red-50 border-red-200';
      case 'high': return 'text-orange-500 bg-orange-50 border-orange-200';
      case 'medium': return 'text-yellow-500 bg-yellow-50 border-yellow-200';
      case 'low': return 'text-green-500 bg-green-50 border-green-200';
      default: return 'text-gray-500 bg-gray-50 border-gray-200';
    }
  };

  const getEventIcon = (type: string) => {
    switch (type) {
      case 'daily_summary': return <Clock className="w-4 h-4" />;
      case 'hourly_summary': return <Eye className="w-4 h-4" />;
      case 'event_cluster': return <AlertTriangle className="w-4 h-4" />;
      case 'ip_cluster': return <Shield className="w-4 h-4" />;
      default: return <Clock className="w-4 h-4" />;
    }
  };

  const formatTimestamp = (timestamp: string) => {
    const date = new Date(timestamp);
    return date.toLocaleString();
  };

  return (
    <div className="space-y-6">
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
          Analysis Summary
        </h3>
        
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
          <div className="bg-blue-50 dark:bg-blue-900/20 rounded-lg p-4">
            <div className="text-2xl font-bold text-blue-600 dark:text-blue-400">
              {safeTimelineSummary.totalEvents || 0}
            </div>
            <div className="text-sm text-blue-600 dark:text-blue-400">Total Events</div>
          </div>
          
          <div className="bg-red-50 dark:bg-red-900/20 rounded-lg p-4">
            <div className="text-2xl font-bold text-red-600 dark:text-red-400">
              {safeTimelineSummary.eventBreakdown?.blocked || 0}
            </div>
            <div className="text-sm text-red-600 dark:text-red-400">Blocked</div>
          </div>
          
          <div className="bg-green-50 dark:bg-green-900/20 rounded-lg p-4">
            <div className="text-2xl font-bold text-green-600 dark:text-green-400">
              {safeTimelineSummary.eventBreakdown?.allowed || 0}
            </div>
            <div className="text-sm text-green-600 dark:text-green-400">Allowed</div>
          </div>
        </div>

        {safeKeyInsights && safeKeyInsights.length > 0 && (
          <div className="mt-6">
            <h4 className="text-md font-medium text-gray-900 dark:text-white mb-3">
              Key Insights
            </h4>
            <div className="space-y-2">
              {safeKeyInsights.map((insight, index) => (
                <div key={index} className="flex items-start space-x-2">
                  <div className="w-2 h-2 bg-blue-500 rounded-full mt-2 flex-shrink-0"></div>
                  <p className="text-sm text-gray-600 dark:text-gray-300">{insight}</p>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Tab Navigation */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700">
        <div className="border-b border-gray-200 dark:border-gray-700">
          <nav className="-mb-px flex space-x-8 px-6">
            <button
              onClick={() => setActiveTab('timeline')}
              className={`py-4 px-1 border-b-2 font-medium text-sm transition-colors duration-200 ${
                activeTab === 'timeline'
                  ? 'border-blue-500 text-blue-600 dark:text-blue-400'
                  : 'border-transparent text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300 hover:border-gray-300'
              }`}
            >
              <div className="flex items-center space-x-2">
                <Clock className="w-4 h-4" />
                <span>Event Timeline</span>
                {safeTimelineEvents.length > 0 && (
                  <span className="bg-gray-200 dark:bg-gray-600 text-gray-700 dark:text-gray-300 text-xs rounded-full px-2 py-1">
                    {safeTimelineEvents.length}
                  </span>
                )}
              </div>
            </button>
            <button
              onClick={() => setActiveTab('anomalies')}
              className={`py-4 px-1 border-b-2 font-medium text-sm transition-colors duration-200 ${
                activeTab === 'anomalies'
                  ? 'border-blue-500 text-blue-600 dark:text-blue-400'
                  : 'border-transparent text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300 hover:border-gray-300'
              }`}
            >
              <div className="flex items-center space-x-2">
                <Activity className="w-4 h-4" />
                <span>Anomaly Detection</span>
                {safeAnomalies.length > 0 && (
                  <span className="bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-400 text-xs rounded-full px-2 py-1">
                    {safeAnomalies.length}
                  </span>
                )}
              </div>
            </button>
          </nav>
        </div>
        
        <div className="p-6">
          {activeTab === 'timeline' ? (
            <div>
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
                Event Timeline
              </h3>
              
              {safeTimelineEvents.length === 0 ? (
                <div className="text-center py-8 text-gray-500 dark:text-gray-400">
                  No timeline events available.
                </div>
              ) : (
                <div className="divide-y divide-gray-200 dark:divide-gray-700">
                  {safeTimelineEvents.map((event) => (
                    <div key={event.id} className="py-4 hover:bg-gray-50 dark:hover:bg-gray-700/50 transition-colors">
                      <div className="flex items-start space-x-4">
                        <div className={`p-2 rounded-lg border ${getSeverityColor(event.severity)}`}>
                          {getEventIcon(event.type)}
                        </div>
                        
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center justify-between">
                            <h4 className="text-sm font-medium text-gray-900 dark:text-white">
                              {event.title}
                            </h4>
                            <span className="text-xs text-gray-500 dark:text-gray-400">
                              {formatTimestamp(event.timestamp)}
                            </span>
                          </div>
                          
                          <p className="text-sm text-gray-600 dark:text-gray-300 mt-1">
                            {event.summary}
                          </p>
                          
                          {event.isExpandable && (
                            <div className="mt-3">
                              <button
                                onClick={() => toggleEvent(event.id)}
                                className="flex items-center space-x-1 text-xs text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300"
                              >
                                {expandedEvents.has(event.id) ? (
                                  <ChevronDown className="w-3 h-3" />
                                ) : (
                                  <ChevronRight className="w-3 h-3" />
                                )}
                                <span>Show Details</span>
                              </button>
                              
                              {expandedEvents.has(event.id) && event.details && (
                                <div className="mt-3 p-4 bg-gray-50 dark:bg-gray-700 rounded-lg">
                                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                                    {Object.entries(event.details).map(([key, value]) => (
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
                                </div>
                              )}
                            </div>
                          )}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          ) : (
            <AnomalyView anomalies={safeAnomalies} />
          )}
        </div>
      </div>
    </div>
  );
};

export default TimelineView;
