'use client';

import React, { useState, useEffect } from 'react';
import { useAuth } from '../contexts/AuthContext';
import { FileUpload } from './FileUpload';
import LogFileList from './LogFileList';
import { Shield, Upload, BarChart3, LogOut, User } from 'lucide-react';
import { LogFile } from '../types';

export const Dashboard: React.FC = () => {
  const { user, logout } = useAuth();
  const [activeTab, setActiveTab] = useState<'upload' | 'files'>('upload');
  const [logFiles, setLogFiles] = useState<LogFile[]>([]);
  const [isLoading, setIsLoading] = useState(false);

  const fetchLogFiles = async () => {
    if (!user) return;
    
    setIsLoading(true);
    try {
      const token = localStorage.getItem('authToken');
      const response = await fetch('http://localhost:3001/api/logs/files', {
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });

      const data = await response.json();
      if (data.success) {
        setLogFiles(data.data);
      }
    } catch (error) {
      console.error('Error fetching log files:', error);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchLogFiles();
  }, [user]);

  const handleUploadSuccess = () => {
    fetchLogFiles();
    setActiveTab('files');
  };

  const handleLogout = () => {
    logout();
  };

  if (!user) {
    return null;
  }

  return (
    <div className="min-h-screen bg-gray-900">
      <header className="bg-gray-800 border-b border-gray-700">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <div className="flex items-center space-x-4">
              <div className="flex items-center space-x-2">
                <Shield className="h-8 w-8 text-blue-500" />
                <span className="text-xl font-bold text-white">TENEX.AI</span>
              </div>
              <span className="text-gray-400 text-sm">Log Analysis Platform</span>
            </div>
            
            <div className="flex items-center space-x-4">
              <div className="flex items-center space-x-2 text-gray-300">
                <User className="h-4 w-4" />
                <span className="text-sm">{user.username}</span>
              </div>
              <button
                onClick={handleLogout}
                className="flex items-center space-x-2 px-3 py-2 text-gray-300 hover:text-white hover:bg-gray-700 rounded-lg transition-colors duration-200"
              >
                <LogOut className="h-4 w-4" />
                <span>Logout</span>
              </button>
            </div>
          </div>
        </div>
      </header>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 mt-6">
        <div className="border-b border-gray-700">
          <nav className="-mb-px flex space-x-8">
            <button
              onClick={() => setActiveTab('upload')}
              className={`py-2 px-1 border-b-2 font-medium text-sm transition-colors duration-200 ${
                activeTab === 'upload'
                  ? 'border-blue-500 text-blue-400'
                  : 'border-transparent text-gray-400 hover:text-gray-300 hover:border-gray-300'
              }`}
            >
              <div className="flex items-center space-x-2">
                <Upload className="h-4 w-4" />
                <span>Upload Logs</span>
              </div>
            </button>
            <button
              onClick={() => setActiveTab('files')}
              className={`py-2 px-1 border-b-2 font-medium text-sm transition-colors duration-200 ${
                activeTab === 'files'
                  ? 'border-blue-500 text-blue-400'
                  : 'border-transparent text-gray-400 hover:text-gray-300 hover:border-gray-300'
              }`}
            >
              <div className="flex items-center space-x-2">
                <BarChart3 className="h-4 w-4" />
                <span>Analysis Results</span>
                {logFiles.length > 0 && (
                  <span className="bg-blue-500 text-white text-xs rounded-full px-2 py-1">
                    {logFiles.length}
                  </span>
                )}
              </div>
            </button>
          </nav>
        </div>
      </div>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {activeTab === 'upload' ? (
          <div className="space-y-8">
            <div className="text-center">
              <h1 className="text-3xl font-bold text-white mb-4">
                Welcome to TENEX.AI
              </h1>
              <p className="text-gray-400 text-lg max-w-2xl mx-auto">
                Upload your ZScaler web proxy logs for advanced security analysis. 
                Our AI-powered platform will analyze your logs and provide actionable 
                insights for your SOC team.
              </p>
            </div>
            
            <FileUpload onUploadSuccess={handleUploadSuccess} />
            
            <div className="text-center text-gray-500 text-sm">
              <p>Supported formats: .log, .txt, .csv</p>
              <p>Maximum file size: 100MB</p>
            </div>
          </div>
        ) : (
          <LogFileList 
            files={logFiles} 
            onRefresh={fetchLogFiles} 
          />
        )}
      </main>
    </div>
  );
};
