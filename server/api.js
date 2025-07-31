/**
 * TrojanHorse.js Enterprise REST API Server
 * Comprehensive API server with authentication, rate limiting, and security
 */

import express from 'express';
import helmet from 'helmet';
import compression from 'compression';
import rateLimit from 'express-rate-limit';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import winston from 'winston';
import { body, param, query, validationResult } from 'express-validator';
import swaggerJSDoc from 'swagger-jsdoc';
import swaggerUi from 'swagger-ui-express';
import multer from 'multer';
import { TrojanHorse, createVault } from '../dist/trojanhorse.js';
import { StreamingProcessor } from '../dist/core/StreamingProcessor.js';
import { CircuitBreakerManager } from '../dist/core/CircuitBreaker.js';
import { createRequire } from 'module';
import { promises as fs } from 'fs';
import path from 'path';

// ES module compatibility for package.json
const require = createRequire(import.meta.url);
const packageJson = require('../package.json');

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 3000;

// Configure logger
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console({
      format: winston.format.simple()
    }),
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/combined.log' })
  ]
});

// Circuit breaker for external services
const circuitBreaker = new CircuitBreakerManager({
  failureThreshold: 5,
  timeout: 60000,
  volumeThreshold: 10
});

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
}));

// CORS configuration
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000', 'http://localhost:8080'],
  credentials: true,
  optionsSuccessStatus: 200
}));

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Compression
app.use(compression());

// Rate limiting
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: process.env.NODE_ENV === 'production' ? 100 : 1000, // limit each IP
  message: {
    error: 'Too many requests from this IP, please try again later.',
    retryAfter: '15 minutes'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 auth requests per windowMs
  message: {
    error: 'Too many authentication attempts, please try again later.'
  },
  skipSuccessfulRequests: true,
});

app.use('/api/', apiLimiter);
app.use('/api/auth/', authLimiter);

// Request logging middleware
app.use((req, res, next) => {
  const startTime = Date.now();
  
  res.on('finish', () => {
    const duration = Date.now() - startTime;
    logger.info('Request completed', {
      method: req.method,
      url: req.url,
      statusCode: res.statusCode,
      duration,
      userAgent: req.get('User-Agent'),
      ip: req.ip
    });
  });
  
  next();
});

// File upload configuration
const upload = multer({
  dest: 'uploads/',
  limits: {
    fileSize: 50 * 1024 * 1024, // 50MB limit
    files: 5
  },
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['text/csv', 'application/json', 'text/xml', 'text/plain'];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type. Only CSV, JSON, XML, and TXT files are allowed.'));
    }
  }
});

// Swagger documentation setup
const swaggerOptions = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'TrojanHorse.js API',
      version: '1.0.0',
      description: 'Comprehensive threat intelligence API',
      contact: {
        name: 'TrojanHorse.js Team',
        url: 'https://github.com/sc4rfurry/TrojanHorse.js'
      }
    },
    servers: [
      {
        url: `http://localhost:${PORT}`,
        description: 'Development server'
      }
    ],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT'
        }
      }
    },
    security: [
      {
        bearerAuth: []
      }
    ]
  },
  apis: ['./server/api.js'],
};

const swaggerSpec = swaggerJSDoc(swaggerOptions);

// Swagger UI
app.use('/api/docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec, {
  explorer: true,
  customCss: '.swagger-ui .topbar { display: none }',
  customSiteTitle: "TrojanHorse.js API Documentation"
}));

// Validation middleware
const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      error: 'Validation failed',
      details: errors.array()
    });
  }
  next();
};

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({
      success: false,
      error: 'Access token required'
    });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'fallback-secret', (err, user) => {
    if (err) {
      return res.status(403).json({
        success: false,
        error: 'Invalid or expired token'
      });
    }
    req.user = user;
    next();
  });
};

// Initialize TrojanHorse instance
let trojanInstance = null;

async function initializeTrojanHorse() {
  try {
    const config = {
      apiKeys: {
        alienVault: process.env.ALIENVAULT_API_KEY,
        abuseipdb: process.env.ABUSEIPDB_API_KEY,
        virustotal: process.env.VIRUSTOTAL_API_KEY,
        crowdsec: process.env.CROWDSEC_API_KEY
      },
      sources: ['urlhaus', 'alienvault', 'abuseipdb', 'virustotal', 'crowdsec'].filter(source => {
        const keyMap = {
          'urlhaus': true, // No key required
          'alienvault': process.env.ALIENVAULT_API_KEY,
          'abuseipdb': process.env.ABUSEIPDB_API_KEY,
          'virustotal': process.env.VIRUSTOTAL_API_KEY,
          'crowdsec': process.env.CROWDSEC_API_KEY
        };
        return keyMap[source];
      }),
      strategy: 'balanced'
    };

    trojanInstance = new TrojanHorse(config);
    logger.info('TrojanHorse instance initialized successfully');
  } catch (error) {
    logger.error('Failed to initialize TrojanHorse:', error);
    throw error;
  }
}

/**
 * @swagger
 * /api/health:
 *   get:
 *     summary: Health check endpoint
 *     tags: [System]
 *     responses:
 *       200:
 *         description: System health status
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                 timestamp:
 *                   type: string
 *                 uptime:
 *                   type: number
 *                 version:
 *                   type: string
 */
app.get('/api/health', (req, res) => {
  const health = {
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    version: packageJson.version,
    memory: process.memoryUsage(),
    feeds: trojanInstance ? Object.keys(trojanInstance.feeds || {}) : []
  };

  res.json(health);
});

/**
 * @swagger
 * /api/auth/login:
 *   post:
 *     summary: Authenticate user
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - username
 *               - password
 *             properties:
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       200:
 *         description: Authentication successful
 *       401:
 *         description: Invalid credentials
 */
app.post('/api/auth/login',
  [
    body('username').isLength({ min: 3 }).withMessage('Username must be at least 3 characters'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters')
  ],
  handleValidationErrors,
  async (req, res) => {
    try {
      const { username, password } = req.body;
      
      // Validate required environment variables
      const validUsername = process.env.API_USERNAME;
      const validPasswordHash = process.env.API_PASSWORD_HASH;
      
      if (!validUsername || !validPasswordHash) {
        logger.error('Missing required environment variables: API_USERNAME and API_PASSWORD_HASH');
        return res.status(500).json({
          success: false,
          error: 'Authentication service unavailable'
        });
      }
      
      if (username !== validUsername || !await bcrypt.compare(password, validPasswordHash)) {
        logger.warn('Failed login attempt', { username, ip: req.ip });
        return res.status(401).json({
          success: false,
          error: 'Invalid credentials'
        });
      }

      const token = jwt.sign(
        { username, role: 'admin' },
        process.env.JWT_SECRET || 'fallback-secret',
        { expiresIn: '24h' }
      );

      res.json({
        success: true,
        token,
        expiresIn: '24h'
      });

    } catch (error) {
      logger.error('Login error:', error);
      res.status(500).json({
        success: false,
        error: 'Authentication failed'
      });
    }
  }
);

/**
 * @swagger
 * /api/threat/check:
 *   post:
 *     summary: Check a target for threats
 *     tags: [Threat Intelligence]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - target
 *             properties:
 *               target:
 *                 type: string
 *                 description: Domain, IP, URL, or hash to check
 *               sources:
 *                 type: array
 *                 items:
 *                   type: string
 *               minimumConfidence:
 *                 type: number
 *                 minimum: 0
 *                 maximum: 1
 *     responses:
 *       200:
 *         description: Threat analysis result
 *       400:
 *         description: Invalid request
 *       500:
 *         description: Analysis failed
 */
app.post('/api/threat/check',
  authenticateToken,
  [
    body('target').notEmpty().withMessage('Target is required'),
    body('sources').optional().isArray().withMessage('Sources must be an array'),
    body('minimumConfidence').optional().isFloat({ min: 0, max: 1 }).withMessage('Confidence must be between 0 and 1')
  ],
  handleValidationErrors,
  async (req, res) => {
    try {
      const { target, sources, minimumConfidence = 0.5 } = req.body;

      if (!trojanInstance) {
        return res.status(503).json({
          success: false,
          error: 'Threat intelligence service not available'
        });
      }

      const result = await circuitBreaker.execute('threat-check', async () => {
        return await trojanInstance.scout(target, {
          sources,
          minimumConfidence
        });
      });

      logger.info('Threat check completed', {
        target,
        correlationScore: result.correlationScore,
        sources: result.sources.join(','),
        user: req.user.username
      });

      res.json({
        success: true,
        data: result
      });

    } catch (error) {
      logger.error('Threat check failed:', error);
      res.status(500).json({
        success: false,
        error: 'Threat analysis failed',
        message: error.message
      });
    }
  }
);

/**
 * @swagger
 * /api/threat/batch:
 *   post:
 *     summary: Check multiple targets for threats
 *     tags: [Threat Intelligence]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - targets
 *             properties:
 *               targets:
 *                 type: array
 *                 items:
 *                   type: string
 *               concurrency:
 *                 type: number
 *                 minimum: 1
 *                 maximum: 10
 *     responses:
 *       200:
 *         description: Batch analysis results
 */
app.post('/api/threat/batch',
  authenticateToken,
  [
    body('targets').isArray({ min: 1, max: 100 }).withMessage('Targets must be an array (1-100 items)'),
    body('concurrency').optional().isInt({ min: 1, max: 10 }).withMessage('Concurrency must be between 1 and 10')
  ],
  handleValidationErrors,
  async (req, res) => {
    try {
      const { targets, concurrency = 5 } = req.body;

      if (!trojanInstance) {
        return res.status(503).json({
          success: false,
          error: 'Threat intelligence service not available'
        });
      }

      const results = [];
      const startTime = Date.now();

      // Process in batches to avoid overwhelming the system
      for (let i = 0; i < targets.length; i += concurrency) {
        const batch = targets.slice(i, i + concurrency);
        
        const batchPromises = batch.map(async (target) => {
          try {
            const result = await trojanInstance.scout(target);
            return { target, result, error: null };
          } catch (error) {
            return { target, result: null, error: error.message };
          }
        });

        const batchResults = await Promise.all(batchPromises);
        results.push(...batchResults);

        // Small delay between batches to be respectful to APIs
        if (i + concurrency < targets.length) {
          await new Promise(resolve => setTimeout(resolve, 1000));
        }
      }

      const processingTime = Date.now() - startTime;

      logger.info('Batch threat check completed', {
        targetCount: targets.length,
        processingTime,
        user: req.user.username
      });

      res.json({
        success: true,
        data: {
          results,
          summary: {
            total: targets.length,
            successful: results.filter(r => r.result !== null).length,
            failed: results.filter(r => r.error !== null).length,
            processingTime
          }
        }
      });

    } catch (error) {
      logger.error('Batch threat check failed:', error);
      res.status(500).json({
        success: false,
        error: 'Batch analysis failed',
        message: error.message
      });
    }
  }
);

/**
 * @swagger
 * /api/threat/upload:
 *   post:
 *     summary: Upload and process threat data file
 *     tags: [Threat Intelligence]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         multipart/form-data:
 *           schema:
 *             type: object
 *             properties:
 *               file:
 *                 type: string
 *                 format: binary
 *               type:
 *                 type: string
 *                 enum: [csv, json, xml]
 *     responses:
 *       200:
 *         description: File processed successfully
 */
app.post('/api/threat/upload',
  authenticateToken,
  upload.single('file'),
  [
    body('type').isIn(['csv', 'json', 'xml']).withMessage('Type must be csv, json, or xml')
  ],
  handleValidationErrors,
  async (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({
          success: false,
          error: 'No file uploaded'
        });
      }

      const { type = 'csv' } = req.body;
      const processor = new StreamingProcessor({
        chunkSize: 1024 * 1024, // 1MB chunks
        maxConcurrency: 4
      });

      const inputStream = processor.createLargeDataStream(req.file.path);
      
      const result = await processor.processStream(inputStream, null, {
        processorType: type
      });

      // Clean up uploaded file
      await fs.unlink(req.file.path);

      logger.info('File processing completed', {
        filename: req.file.originalname,
        size: req.file.size,
        indicatorsFound: result.indicators.length,
        user: req.user.username
      });

      res.json({
        success: true,
        data: {
          filename: req.file.originalname,
          size: req.file.size,
          indicators: result.indicators.length,
          processingStats: result.metadata.processingStats
        }
      });

    } catch (error) {
      logger.error('File processing failed:', error);
      
      // Clean up uploaded file on error
      if (req.file) {
        try {
          await fs.unlink(req.file.path);
        } catch (cleanupError) {
          logger.error('Failed to clean up uploaded file:', cleanupError);
        }
      }

      res.status(500).json({
        success: false,
        error: 'File processing failed',
        message: error.message
      });
    }
  }
);

/**
 * @swagger
 * /api/export:
 *   get:
 *     summary: Export threat intelligence data
 *     tags: [Data Export]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: format
 *         schema:
 *           type: string
 *           enum: [json, csv, stix]
 *         description: Export format
 *       - in: query
 *         name: timeRange
 *         schema:
 *           type: string
 *         description: Time range (e.g., 24h, 7d, 30d)
 *     responses:
 *       200:
 *         description: Exported data
 */
app.get('/api/export',
  authenticateToken,
  [
    query('format').isIn(['json', 'csv', 'stix']).withMessage('Format must be json, csv, or stix'),
    query('timeRange').optional().matches(/^\d+[hdwm]$/).withMessage('Invalid time range format')
  ],
  handleValidationErrors,
  async (req, res) => {
    try {
      const { format = 'json', timeRange = '24h' } = req.query;

      if (!trojanInstance) {
        return res.status(503).json({
          success: false,
          error: 'Threat intelligence service not available'
        });
      }

      const exportData = await trojanInstance.plunder(format, {
        timeRange,
        includeMetadata: true
      });

      const contentTypes = {
        json: 'application/json',
        csv: 'text/csv',
        stix: 'application/stix+json'
      };

      res.setHeader('Content-Type', contentTypes[format]);
      res.setHeader('Content-Disposition', `attachment; filename="threats-${Date.now()}.${format}"`);
      res.send(exportData);

      logger.info('Data export completed', {
        format,
        timeRange,
        user: req.user.username
      });

    } catch (error) {
      logger.error('Data export failed:', error);
      res.status(500).json({
        success: false,
        error: 'Export failed',
        message: error.message
      });
    }
  }
);

/**
 * @swagger
 * /api/stats:
 *   get:
 *     summary: Get system statistics
 *     tags: [System]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: System statistics
 */
app.get('/api/stats',
  authenticateToken,
  async (req, res) => {
    try {
      const circuitBreakerStats = circuitBreaker.getAllStats();
      const memoryUsage = process.memoryUsage();

      const stats = {
        uptime: process.uptime(),
        memory: {
          heapUsed: Math.round(memoryUsage.heapUsed / 1024 / 1024), // MB
          heapTotal: Math.round(memoryUsage.heapTotal / 1024 / 1024), // MB
          rss: Math.round(memoryUsage.rss / 1024 / 1024) // MB
        },
        circuitBreakers: circuitBreakerStats,
        feeds: trojanInstance ? (trojanInstance.getStats ? trojanInstance.getStats() : {}) : {},
        version: packageJson.version
      };

      res.json({
        success: true,
        data: stats
      });

    } catch (error) {
      logger.error('Failed to get stats:', error);
      res.status(500).json({
        success: false,
        error: 'Failed to get statistics'
      });
    }
  }
);

// Error handling middleware
app.use((error, req, res, next) => {
  if (error instanceof multer.MulterError) {
    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({
        success: false,
        error: 'File too large. Maximum size is 50MB.'
      });
    }
  }

  logger.error('Unhandled error:', error);
  res.status(500).json({
    success: false,
    error: 'Internal server error'
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    error: 'Endpoint not found'
  });
});

// Graceful shutdown
process.on('SIGTERM', async () => {
  logger.info('SIGTERM received. Starting graceful shutdown...');
  
  // Close server
  server.close(() => {
    logger.info('HTTP server closed.');
    
    // Cleanup TrojanHorse instance
    if (trojanInstance && trojanInstance.destroy) {
      trojanInstance.destroy().then(() => {
        logger.info('TrojanHorse instance cleaned up.');
        process.exit(0);
      });
    } else {
      process.exit(0);
    }
  });
});

// Start server
async function startServer() {
  try {
    await initializeTrojanHorse();
    
    const server = app.listen(PORT, () => {
      logger.info(`🏰 TrojanHorse.js API Server running on port ${PORT}`);
      logger.info(`📚 API Documentation: http://localhost:${PORT}/api/docs`);
      logger.info(`🔍 Health Check: http://localhost:${PORT}/api/health`);
    });

    return server;
  } catch (error) {
    logger.error('Failed to start server:', error);
    process.exit(1);
  }
}

// Start the server if this file is run directly
if (import.meta.url === path.toFileURL(process.argv[1]).href) {
  startServer();
}

export { app, startServer }; 