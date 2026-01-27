/**
 * ===========================================
 * SECURE INTERNSHIP PORTAL - SERVER
 * ===========================================
 * 
 * Main entry point for the backend API
 * 
 * SECURITY FEATURES IMPLEMENTED:
 * 
 * 1. CORS Configuration
 *    - Restricts API access to authorized origins
 *    - Prevents unauthorized cross-origin requests
 * 
 * 2. Rate Limiting
 *    - Global rate limit to prevent DoS attacks
 *    - Additional limits on authentication routes
 * 
 * 3. Security Headers (via CORS)
 *    - Prevents common web vulnerabilities
 * 
 * 4. Request Size Limits
 *    - Prevents large payload attacks
 * 
 * 5. Environment Variables
 *    - All sensitive config stored in .env
 *    - Never hardcoded credentials
 * 
 * API ROUTES:
 * /api/auth   - Authentication (register, login, OTP)
 * /api/offers - Offer management (CRUD, encryption, signing)
 * /api/admin  - Admin dashboard (audit logs, stats)
 * 
 * SECURITY LEVELS & RISK MITIGATION:
 * ┌─────────────────────┬────────────┬─────────────────────────────────┐
 * │ Feature             │ Level      │ Mitigates                       │
 * ├─────────────────────┼────────────┼─────────────────────────────────┤
 * │ MFA (OTP)           │ HIGH       │ Credential theft, phishing      │
 * │ JWT Authentication  │ HIGH       │ Session hijacking               │
 * │ AES-256 Encryption  │ HIGH       │ Data theft, MITM                │
 * │ RSA Hybrid          │ HIGH       │ Key exchange attacks            │
 * │ Digital Signatures  │ HIGH       │ Tampering, repudiation          │
 * │ bcrypt Hashing      │ HIGH       │ Password theft, rainbow tables  │
 * │ Rate Limiting       │ MEDIUM     │ Brute force, DoS                │
 * │ Role-Based Access   │ HIGH       │ Privilege escalation            │
 * │ Audit Logging       │ HIGH       │ Non-repudiation, forensics      │
 * └─────────────────────┴────────────┴─────────────────────────────────┘
 */

import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import rateLimit from 'express-rate-limit';

// Database connection
import connectDB from './dbconfig/db.js';

// Routes
import authRoutes from './routers/auth.js';
import offerRoutes from './routers/offer.js';
import adminRoutes from './routers/admin.js';

// Models for initialization
import AuditLog from './models/AuditLog.js';

// Load environment variables
dotenv.config();

// Initialize Express app
const app = express();

// ==================================
// SECURITY: CORS Configuration
// ==================================
/**
 * CORS (Cross-Origin Resource Sharing)
 * 
 * Restricts which domains can access the API
 * Prevents unauthorized websites from making API requests
 */
const corsOptions = {
    origin: function (origin, callback) {
        // Allow requests with no origin (mobile apps, Postman)
        if (!origin) return callback(null, true);
        
        // List of allowed origins
        const allowedOrigins = [
            'http://localhost:3000',
            'http://localhost:5173',
            'http://127.0.0.1:3000',
            'http://127.0.0.1:5173',
            process.env.FRONTEND_URL
        ].filter(Boolean);
        
        if (allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true, // Allow cookies
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
};

app.use(cors(corsOptions));

// ==================================
// SECURITY: Request Parsing with Size Limits
// ==================================
/**
 * Limit request body size to prevent large payload attacks
 * PDF uploads handled separately with multer (10MB limit)
 */
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// ==================================
// SECURITY: Global Rate Limiting
// ==================================
/**
 * Rate Limiting
 * 
 * Prevents:
 * - Brute force attacks
 * - DoS attacks
 * - API abuse
 * 
 * Settings:
 * - 100 requests per 15 minutes per IP
 */
const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Requests per window
    message: {
        success: false,
        message: 'Too many requests. Please try again later.',
        error: 'RATE_LIMIT_EXCEEDED'
    },
    standardHeaders: true,
    legacyHeaders: false,
    // Skip rate limiting for certain paths if needed
    skip: (req) => {
        // Don't rate limit health checks
        return req.path === '/api/health';
    }
});

app.use(globalLimiter);

// ==================================
// LOGGING: Request Logger
// ==================================
/**
 * Simple request logger for development
 * In production, use a proper logging solution
 */
app.use((req, res, next) => {
    const timestamp = new Date().toISOString();
    console.log(`[${timestamp}] ${req.method} ${req.path}`);
    next();
});

// ==================================
// API ROUTES
// ==================================

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.status(200).json({
        success: true,
        message: 'Secure Internship Portal API is running',
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV || 'development'
    });
});

// Authentication routes
app.use('/api/auth', authRoutes);

// Offer routes (requires authentication)
app.use('/api/offers', offerRoutes);

// Admin routes (requires admin role)
app.use('/api/admin', adminRoutes);

// ==================================
// ERROR HANDLING
// ==================================

// 404 Handler
app.use((req, res, next) => {
    res.status(404).json({
        success: false,
        message: 'Route not found',
        error: 'NOT_FOUND'
    });
});

// Global Error Handler
app.use((err, req, res, next) => {
    console.error('❌ Error:', err);
    
    // Handle specific error types
    if (err.name === 'ValidationError') {
        return res.status(400).json({
            success: false,
            message: 'Validation error',
            error: err.message
        });
    }
    
    if (err.name === 'UnauthorizedError') {
        return res.status(401).json({
            success: false,
            message: 'Unauthorized',
            error: 'UNAUTHORIZED'
        });
    }
    
    if (err.message === 'Not allowed by CORS') {
        return res.status(403).json({
            success: false,
            message: 'CORS policy violation',
            error: 'CORS_ERROR'
        });
    }
    
    // Multer file size error
    if (err.code === 'LIMIT_FILE_SIZE') {
        return res.status(400).json({
            success: false,
            message: 'File too large. Maximum size is 10MB.',
            error: 'FILE_TOO_LARGE'
        });
    }
    
    // Default error response
    res.status(500).json({
        success: false,
        message: 'Internal server error',
        error: process.env.NODE_ENV === 'development' ? err.message : 'SERVER_ERROR'
    });
});

// ==================================
// SERVER STARTUP
// ==================================
const PORT = process.env.PORT || 5000;

const startServer = async () => {
    try {
        // Connect to MongoDB
        await connectDB();
        
        // Start the server
        app.listen(PORT, () => {
            console.log('');
            console.log('===========================================');
            console.log('🔐 SECURE INTERNSHIP PORTAL - API SERVER');
            console.log('===========================================');
            console.log(`🚀 Server running on port ${PORT}`);
            console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
            console.log(`📍 API URL: http://localhost:${PORT}/api`);
            console.log('');
            console.log('📋 Available Routes:');
            console.log('   POST /api/auth/register     - Register new user');
            console.log('   POST /api/auth/login        - Login (sends OTP)');
            console.log('   POST /api/auth/verify-otp   - Verify OTP');
            console.log('   GET  /api/auth/me           - Get current user');
            console.log('   POST /api/offers/upload     - Upload encrypted offer (Recruiter)');
            console.log('   GET  /api/offers            - List offers');
            console.log('   POST /api/offers/:id/decrypt - Decrypt offer (Student)');
            console.log('   POST /api/offers/:id/verify  - Verify signature (Student)');
            console.log('   POST /api/offers/:id/accept  - Accept offer (Student)');
            console.log('   GET  /api/admin/audit-logs   - View audit logs (Admin)');
            console.log('');
            console.log('🔒 Security Features Active:');
            console.log('   ✅ JWT Authentication');
            console.log('   ✅ MFA (OTP via Email)');
            console.log('   ✅ AES-256 Encryption');
            console.log('   ✅ RSA Hybrid Encryption');
            console.log('   ✅ Digital Signatures (RSA-SHA256)');
            console.log('   ✅ bcrypt Password Hashing');
            console.log('   ✅ Role-Based Access Control');
            console.log('   ✅ Rate Limiting');
            console.log('   ✅ Audit Logging');
            console.log('===========================================');
            console.log('');
        });
        
        // Log server startup
        await AuditLog.log({
            action: 'SYSTEM_STARTUP',
            resourceType: 'system',
            description: `Server started on port ${PORT}`,
            userRole: 'system',
            status: 'success',
            severity: 'low'
        });
        
    } catch (error) {
        console.error('❌ Failed to start server:', error);
        process.exit(1);
    }
};

// Handle unhandled promise rejections
process.on('unhandledRejection', (err) => {
    console.error('❌ Unhandled Promise Rejection:', err);
    // Don't exit in development, exit in production
    if (process.env.NODE_ENV === 'production') {
        process.exit(1);
    }
});

// Handle uncaught exceptions
process.on('uncaughtException', (err) => {
    console.error('❌ Uncaught Exception:', err);
    process.exit(1);
});

// Graceful shutdown
process.on('SIGTERM', async () => {
    console.log('📴 SIGTERM received. Shutting down gracefully...');
    
    await AuditLog.log({
        action: 'SYSTEM_SHUTDOWN',
        resourceType: 'system',
        description: 'Server shutdown (SIGTERM)',
        userRole: 'system',
        status: 'success',
        severity: 'low'
    });
    
    process.exit(0);
});

// Start the server
startServer();
