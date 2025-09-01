'use client';

import React, { useState, useCallback } from 'react';
import { useDropzone } from 'react-dropzone';
import { Upload, FileText, AlertCircle, CheckCircle, Loader } from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';

interface FileUploadProps {
  onUploadSuccess: () => void;
}

export const FileUpload: React.FC<FileUploadProps> = ({ onUploadSuccess }) => {
  const [uploadStatus, setUploadStatus] = useState<'idle' | 'uploading' | 'success' | 'error'>('idle');
  const [message, setMessage] = useState('');
  const { token } = useAuth();

  const onDrop = useCallback(async (acceptedFiles: File[]) => {
    if (acceptedFiles.length === 0) return;

    const file = acceptedFiles[0];
    setUploadStatus('uploading');
    setMessage('Uploading and processing log file...');

    try {
      const formData = new FormData();
      formData.append('logFile', file);

      const response = await fetch('http://localhost:3001/api/logs/upload', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
        },
        body: formData,
      });

      const data = await response.json();

      if (response.ok && data.success) {
        setUploadStatus('success');
        setMessage('File uploaded successfully! Processing in background...');
        onUploadSuccess();
        
        setTimeout(() => {
          setUploadStatus('idle');
          setMessage('');
        }, 3000);
      } else {
        throw new Error(data.error || 'Upload failed');
      }
    } catch (error) {
      setUploadStatus('error');
      setMessage(error instanceof Error ? error.message : 'Upload failed');
      
      setTimeout(() => {
        setUploadStatus('idle');
        setMessage('');
      }, 5000);
    }
  }, [token, onUploadSuccess]);

  const { getRootProps, getInputProps, isDragActive, isDragReject } = useDropzone({
    onDrop,
    accept: {
      'text/plain': ['.log', '.txt'],
      'text/csv': ['.csv'],
    },
    maxFiles: 1,
    maxSize: 100 * 1024 * 1024,
  });

  const getStatusIcon = () => {
    switch (uploadStatus) {
      case 'uploading':
        return <Loader className="h-8 w-8 text-blue-500 animate-spin" />;
      case 'success':
        return <CheckCircle className="h-8 w-8 text-green-500" />;
      case 'error':
        return <AlertCircle className="h-8 w-8 text-red-500" />;
      default:
        return <Upload className="h-8 w-8 text-gray-400" />;
    }
  };

  const getStatusColor = () => {
    switch (uploadStatus) {
      case 'uploading':
        return 'border-blue-500 bg-blue-500/10';
      case 'success':
        return 'border-green-500 bg-green-500/10';
      case 'error':
        return 'border-red-500 bg-red-500/10';
      default:
        return 'border-gray-600 bg-gray-800/50';
    }
  };

  return (
    <div className="w-full max-w-2xl mx-auto">
      <div className="text-center mb-6">
        <h3 className="text-xl font-semibold text-white mb-2">
          Upload Log File
        </h3>
        <p className="text-gray-400 text-sm">
          Drag and drop your ZScaler log file (.log, .txt, .csv) or click to browse
        </p>
        <p className="text-gray-500 text-xs mt-1">
          Maximum file size: 100MB
        </p>
      </div>

      <div
        {...getRootProps()}
        className={`
          border-2 border-dashed rounded-lg p-8 text-center cursor-pointer transition-all duration-200
          ${getStatusColor()}
          ${isDragActive && !isDragReject ? 'border-blue-400 bg-blue-500/20' : ''}
          ${isDragReject ? 'border-red-400 bg-red-500/20' : ''}
          hover:border-gray-500 hover:bg-gray-700/50
        `}
      >
        <input {...getInputProps()} />
        
        <div className="flex flex-col items-center space-y-4">
          {getStatusIcon()}
          
          <div className="space-y-2">
            {uploadStatus === 'idle' && (
              <>
                <p className="text-lg font-medium text-white">
                  {isDragActive ? 'Drop the file here' : 'Drag & drop your log file'}
                </p>
                <p className="text-sm text-gray-400">
                  or click to select a file
                </p>
              </>
            )}
            
            {uploadStatus === 'uploading' && (
              <p className="text-lg font-medium text-blue-400">
                Processing your log file...
              </p>
            )}
            
            {uploadStatus === 'success' && (
              <p className="text-lg font-medium text-green-400">
                Upload successful!
              </p>
            )}
            
            {uploadStatus === 'error' && (
              <p className="text-lg font-medium text-red-400">
                Upload failed
              </p>
            )}
          </div>

          {uploadStatus === 'idle' && (
            <div className="flex items-center space-x-2 text-gray-400">
              <FileText className="h-4 w-4" />
              <span className="text-sm">Supports .log, .txt, .csv files</span>
            </div>
          )}
        </div>
      </div>

      {message && (
        <div className={`mt-4 p-4 rounded-lg text-center ${
          uploadStatus === 'success' 
            ? 'bg-green-900/20 border border-green-700 text-green-300'
            : uploadStatus === 'error'
            ? 'bg-red-900/20 border border-red-700 text-red-300'
            : 'bg-blue-900/20 border border-blue-700 text-blue-300'
        }`}>
          {message}
        </div>
      )}

      {isDragReject && (
        <div className="mt-4 p-4 bg-red-900/20 border border-red-700 text-red-300 rounded-lg text-center">
          <AlertCircle className="h-5 w-5 inline mr-2" />
          Invalid file type. Please upload a .log, .txt, or .csv file.
        </div>
      )}
    </div>
  );
};
