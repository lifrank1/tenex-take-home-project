import { Router, Response } from 'express';
import multer from 'multer';
import { PrismaClient } from '@prisma/client';
import { authenticateToken } from '../middleware/auth';
import { LogParser } from '../utils/logParser';
import { LogAnalysisService } from '../services/logAnalysisService';
import { AuthenticatedRequest, ApiResponse, UploadResponse } from '../types';
import * as fs from 'fs';
import * as path from 'path';

const router = Router();
const prisma = new PrismaClient();

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = path.join(__dirname, '../../uploads');
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({
  storage,
  limits: {
    fileSize: 100 * 1024 * 1024,
  },
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['.log', '.txt', '.csv'];
    const ext = path.extname(file.originalname).toLowerCase();
    
    if (allowedTypes.includes(ext)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type. Only .log, .txt, and .csv files are allowed.'));
    }
  }
});

router.post('/upload', authenticateToken, upload.single('logFile'), async (req: AuthenticatedRequest, res: Response) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        success: false,
        error: 'No file uploaded'
      });
    }

    if (!req.user) {
      return res.status(401).json({
        success: false,
        error: 'User not authenticated'
      });
    }

    const { originalname, filename, size, path: filePath } = req.file;
    const userId = req.user.id;

    const logFile = await prisma.logFile.create({
      data: {
        filename,
        originalName: originalname,
        fileSize: size,
        userId,
        status: 'processing',
      }
    });

    processLogFile(logFile.id, req.file.path, userId).catch(error => {
      console.error('Error processing log file:', error);
      prisma.logFile.update({
        where: { id: logFile.id },
        data: { status: 'error' }
      }).catch(console.error);
    });

    const response: ApiResponse<UploadResponse> = {
      success: true,
      data: {
        logFile: {
          id: logFile.id,
          filename: logFile.filename,
          originalName: logFile.originalName,
          fileSize: logFile.fileSize,
          uploadDate: logFile.uploadDate.toISOString(),
          status: logFile.status as 'processing' | 'completed' | 'error',
          totalEntries: logFile.totalEntries,
          userId: logFile.userId,
        },
        message: 'File uploaded successfully and processing started'
      }
    };

    res.json(response);

  } catch (error) {
    console.error('Upload error:', error);
    res.status(500).json({
      success: false,
      error: 'Upload failed',
      details: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

router.get('/files', authenticateToken, async (req: AuthenticatedRequest, res: Response) => {
  try {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        error: 'User not authenticated'
      });
    }

    const logFiles = await prisma.logFile.findMany({
      where: { userId: req.user.id },
      orderBy: { uploadDate: 'desc' },
      select: {
        id: true,
        filename: true,
        originalName: true,
        fileSize: true,
        uploadDate: true,
        status: true,
        totalEntries: true,
        userId: true,
      }
    });

    res.json({
      success: true,
      data: logFiles
    });
  } catch (error) {
    console.error('Error fetching log files:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error'
    });
  }
});

router.get('/files/:id', authenticateToken, async (req: AuthenticatedRequest, res: Response) => {
  try {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        error: 'User not authenticated'
      });
    }

    const { id } = req.params;

    const logFile = await prisma.logFile.findFirst({
      where: { 
        id,
        userId: req.user.id 
      }
    });

    if (!logFile) {
      return res.status(404).json({
        success: false,
        error: 'Log file not found'
      });
    }

    const logEntries = await prisma.logEntry.findMany({
      where: { logFileId: id },
      orderBy: { timestamp: 'asc' }
    });

    let timelineAnalysis: {
      timelineEvents: any[];
      timelineSummary: {
        totalEvents: number;
        eventBreakdown: {
          blocked: number;
          allowed: number;
          anomalies: number;
        };
      };
      keyInsights: string[];
      anomalies: any[];
    } = {
      timelineEvents: [],
      timelineSummary: {
        totalEvents: 0,
        eventBreakdown: {
          blocked: 0,
          allowed: 0,
          anomalies: 0
        }
      },
      keyInsights: [],
      anomalies: []
    };

    if (logEntries.length > 0) {
      try {
        const analysisService = new LogAnalysisService();
        
        const parsedEntries = logEntries.map(entry => ({
          id: entry.id,
          timestamp: entry.timestamp,
          clientIP: entry.clientIP || '',
          serverIP: entry.serverIP || undefined,
          url: entry.url || '',
          action: entry.action || '',
          userAgent: entry.userAgent || '',
          urlCategory: entry.urlCategory || '',
          threatName: entry.threatName || undefined,
          threatSeverity: entry.threatSeverity || undefined,
          reason: entry.reason || undefined,
          requestMethod: entry.requestMethod || '',
          responseCode: entry.responseCode || undefined,
          requestSize: entry.requestSize || undefined,
          responseSize: entry.responseSize || undefined,
          referer: entry.referer || undefined,
          sourceIPCountry: entry.sourceIPCountry || undefined,
          destinationIPCountry: entry.destinationIPCountry || undefined,
        }));

        const analysis = analysisService.analyzeLogs(parsedEntries);
        
        timelineAnalysis = {
          timelineEvents: analysis.timelineEvents,
          timelineSummary: analysis.timelineSummary,
          keyInsights: analysis.keyInsights,
          anomalies: analysis.anomalies
        };
        
      } catch (error) {
        console.error('Error generating timeline analysis:', error);
      }
    }

    const finalAnalysis = {
      ...timelineAnalysis,
      id: 'generated',
      logFileId: id,
      analysisDate: new Date().toISOString(),
      totalRequests: timelineAnalysis.timelineSummary.totalEvents,
      blockedRequests: timelineAnalysis.timelineSummary.eventBreakdown.blocked,
      allowedRequests: timelineAnalysis.timelineSummary.eventBreakdown.allowed,
      uniqueIPs: 0,
      uniqueURLs: 0,
      topThreats: [],
      topCategories: [],
      topSourceIPs: [],
      hourlyBreakdown: '[]',
      dailyBreakdown: '[]',
      suspiciousIPs: [],
      highSeverityEvents: timelineAnalysis.timelineSummary.eventBreakdown.anomalies
    };

    const response = {
      success: true,
      data: {
        logFile,
        analysis: finalAnalysis
      }
    };

    res.json(response);
    
  } catch (error) {
    console.error('Error in GET /files/:id:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error'
    });
  }
});

router.get('/files/:id/entries', authenticateToken, async (req: AuthenticatedRequest, res: Response) => {
  try {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        error: 'User not authenticated'
      });
    }

    const { id } = req.params;
    const page = parseInt(req.query.page as string) || 1;
    const limit = parseInt(req.query.limit as string) || 50;
    const offset = (page - 1) * limit;

    const logFile = await prisma.logFile.findFirst({
      where: { 
        id,
        userId: req.user.id 
      }
    });

    if (!logFile) {
      return res.status(404).json({
        success: false,
        error: 'Log file not found'
      });
    }

    const [entries, total] = await Promise.all([
      prisma.logEntry.findMany({
        where: { logFileId: id },
        orderBy: { timestamp: 'desc' },
        skip: offset,
        take: limit,
      }),
      prisma.logEntry.count({
        where: { logFileId: id }
      })
    ]);

    res.json({
      success: true,
      data: {
        entries,
        pagination: {
          page,
          limit,
          total,
          pages: Math.ceil(total / limit)
        }
      }
    });
  } catch (error) {
    console.error('Error fetching log entries:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error'
    });
  }
});

async function processLogFile(logFileId: string, filePath: string, userId: string) {
  try {
    if (!fs.existsSync(filePath)) {
      throw new Error('File not found');
    }
    
    const fileContent = fs.readFileSync(filePath, 'utf-8');
    const lines = fileContent.split('\n').filter(line => line.trim());

    if (lines.length === 0) {
      throw new Error('Empty log file');
    }

    const isValidFormat = LogParser.validateLogFormat(fileContent);
    
    if (!isValidFormat) {
      throw new Error('Invalid log format');
    }

    const parsedEntries = [];
    let parseErrors = 0;
    
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      try {
        const entry = LogParser.parseLogLine(line);
        if (entry) {
          parsedEntries.push(entry);
        } else {
          parseErrors++;
        }
      } catch (parseError) {
        parseErrors++;
      }
    }

    if (parsedEntries.length === 0) {
      throw new Error('No valid log entries found');
    }

    const logEntries = await prisma.logEntry.createMany({
      data: parsedEntries.map(entry => ({
        ...entry,
        logFileId,
        timestamp: entry.timestamp,
      }))
    });

    const analysisService = new LogAnalysisService();
    const analysis = analysisService.analyzeLogs(parsedEntries);

    await prisma.analysisResult.create({
      data: {
        logFileId,
        totalRequests: analysis.totalRequests,
        blockedRequests: analysis.blockedRequests,
        allowedRequests: analysis.allowedRequests,
        uniqueIPs: analysis.uniqueIPs,
        uniqueURLs: analysis.uniqueURLs,
        topThreats: analysis.topThreats.map(t => t.name),
        topCategories: analysis.topCategories.map(c => c.name),
        topSourceIPs: analysis.topSourceIPs.map(ip => ip.ip),
        hourlyBreakdown: JSON.stringify(analysis.hourlyBreakdown),
        dailyBreakdown: JSON.stringify(analysis.dailyBreakdown),
        suspiciousIPs: analysis.suspiciousIPs,
        highSeverityEvents: analysis.highSeverityEvents,
      }
    });

    await prisma.logFile.update({
      where: { id: logFileId },
      data: {
        status: 'completed',
        totalEntries: parsedEntries.length
      }
    });
    
    fs.unlinkSync(filePath);
    
  } catch (error) {
    console.error(`Error processing log file ${logFileId}:`, error);
    
    try {
      await prisma.logFile.update({
        where: { id: logFileId },
        data: { status: 'error' }
      });
    } catch (updateError) {
      console.error(`Failed to update log file status:`, updateError);
    }

    try {
      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
      }
    } catch (cleanupError) {
      console.error(`Error cleaning up file:`, cleanupError);
    }
  }
}

export default router;
