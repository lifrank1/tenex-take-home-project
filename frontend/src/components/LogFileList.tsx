'use client';

import React, { useState, useEffect } from 'react';
import { FileText, Clock, CheckCircle, AlertCircle, XCircle, Eye } from 'lucide-react';
import TimelineView from './TimelineView';
import { LogFile, TimelineAnalysis } from '../types';

interface LogFileWithAnalysis extends LogFile {
  analysis?: TimelineAnalysis;
}

interface LogFileListProps {
  files: LogFile[];
  onRefresh: () => void;
}

const LogFileList: React.FC<LogFileListProps> = ({ files, onRefresh }) => {
  const [selectedFile, setSelectedFile] = useState<LogFileWithAnalysis | null>(null);
  const [showTimeline, setShowTimeline] = useState(false);
  const [filesWithAnalysis, setFilesWithAnalysis] = useState<LogFileWithAnalysis[]>([]);

  useEffect(() => {
    const fetchAnalysisData = async () => {
      const filesToUpdate = [...files];
      
      for (let i = 0; i < filesToUpdate.length; i++) {
        const file = filesToUpdate[i];
        if (file.status === 'completed') {
          try {
            const token = localStorage.getItem('authToken');
            
            const response = await fetch(`http://localhost:3001/api/logs/files/${file.id}`, {
              headers: {
                'Authorization': `Bearer ${token}`,
              },
            });

            const data = await response.json();
            
            if (data.success && data.data.analysis) {
              const analysis = data.data.analysis;
              
              filesToUpdate[i] = {
                ...file,
                analysis: analysis
              } as LogFileWithAnalysis;
            }
          } catch (error) {
            console.error(`Error fetching analysis for file ${file.id}:`, error);
          }
        }
      }
      
      setFilesWithAnalysis(filesToUpdate);
    };

    if (files.length > 0) {
      fetchAnalysisData();
    }
  }, [files]);

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed':
        return <CheckCircle className="w-5 h-5 text-green-500" />;
      case 'processing':
        return <Clock className="w-5 h-5 text-yellow-500 animate-spin" />;
      case 'error':
        return <XCircle className="w-5 h-5 text-red-500" />;
      default:
        return <AlertCircle className="w-5 h-5 text-gray-500" />;
    }
  };

  const getStatusText = (status: string) => {
    switch (status) {
      case 'completed':
        return 'Completed';
      case 'processing':
        return 'Processing';
      case 'error':
        return 'Error';
      default:
        return 'Unknown';
    }
  };

  const formatFileSize = (bytes: number) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const handleViewTimeline = async (file: LogFile) => {
    const fileWithAnalysis = filesWithAnalysis.find(f => f.id === file.id);
    if (fileWithAnalysis && fileWithAnalysis.analysis) {
      setSelectedFile(fileWithAnalysis);
      setShowTimeline(true);
    } else {
      console.error('Analysis data not available for this file');
    }
  };

  const handleBackToList = () => {
    setShowTimeline(false);
    setSelectedFile(null);
  };

  if (showTimeline && selectedFile && selectedFile.analysis) {
    return (
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <button
            onClick={handleBackToList}
            className="flex items-center space-x-2 text-gray-600 dark:text-gray-300 hover:text-gray-900 dark:hover:text-white"
          >
            <Eye className="w-4 h-4" />
            <span>Back to Files</span>
          </button>
          <h2 className="text-xl font-semibold text-gray-900 dark:text-white">
            Timeline: {selectedFile.originalName}
          </h2>
        </div>
        
        <TimelineView
          timelineEvents={selectedFile.analysis.timelineEvents}
          timelineSummary={selectedFile.analysis.timelineSummary}
          keyInsights={selectedFile.analysis.keyInsights}
          anomalies={selectedFile.analysis.anomalies}
        />
      </div>
    );
  }

  if (files.length === 0) {
    return (
      <div className="text-center py-12">
        <FileText className="w-12 h-12 text-gray-400 mx-auto mb-4" />
        <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">
          No log files uploaded yet
        </h3>
        <p className="text-gray-500 dark:text-gray-400">
          Upload your first log file to start analyzing security events.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-xl font-semibold text-gray-900 dark:text-white">
          Analysis Results
        </h2>
        <button
          onClick={onRefresh}
          className="text-sm text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300"
        >
          Refresh
        </button>
      </div>

      <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
            <thead className="bg-gray-50 dark:bg-gray-700">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                  File
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                  Size
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                  Upload Date
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                  Status
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                  Entries
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
              {filesWithAnalysis.map((file) => (
                <tr key={file.id} className="hover:bg-gray-50 dark:hover:bg-gray-700/50">
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="flex items-center">
                      <FileText className="w-5 h-5 text-gray-400 mr-3" />
                      <div>
                        <div className="text-sm font-medium text-gray-900 dark:text-white">
                          {file.originalName}
                        </div>
                        <div className="text-sm text-gray-500 dark:text-gray-400">
                          {file.filename}
                        </div>
                      </div>
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-white">
                    {formatFileSize(file.fileSize)}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-white">
                    {new Date(file.uploadDate).toLocaleDateString()}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="flex items-center">
                      {getStatusIcon(file.status)}
                      <span className="ml-2 text-sm text-gray-900 dark:text-white">
                        {getStatusText(file.status)}
                      </span>
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-white">
                    {file.totalEntries.toLocaleString()}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                    {file.status === 'completed' && file.analysis && (
                      <button
                        onClick={() => handleViewTimeline(file)}
                        className="text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300"
                      >
                        View Timeline
                      </button>
                    )}
                    {file.status === 'processing' && (
                      <span className="text-gray-500 dark:text-gray-400">Processing...</span>
                    )}
                    {file.status === 'error' && (
                      <span className="text-red-500">Error</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default LogFileList;
