/**
 * ===========================================
 * AUTHENTICATION MIDDLEWARE
 * ===========================================
 * 
 * SECURITY CONCEPTS IMPLEMENTED:
 * 
 * 1. JWT (JSON Web Token) AUTHENTICATION
 *    - Stateless authentication mechanism
 *    - Token contains encoded user information
 *    - Signed with secret key (HMAC-SHA256)
 *    - Verified on each request
 * 
 * 2. TOKEN STRUCTURE
 *    JWT = Header.Payload.Signature
 *    
 *    Header: Algorithm & token type
 *    Payload: User data (id, email, role)
 *    Signature: HMAC-SHA256(header + payload, secret)
 * 
 * 3. SECURITY FEATURES
 *    - Token expiration (1 hour default)
 *    - Signature verification
 *    - User validation against database
 * 
 * SECURITY LEVEL: HIGH
 * - JWT_SECRET stored in environment variable
 * - Token verification on every protected route
 * - Automatic expiration handling
 * 
 * POSSIBLE ATTACKS & MITIGATIONS:
 * - Token Theft → Short expiration time (1 hour)
 * - Token Tampering → Signature verification
 * - Replay Attacks → Token expiration + OTP for sensitive actions
 */

import jwt from 'jsonwebtoken';
import User from '../models/User.js';
import AuditLog from '../models/AuditLog.js';
import dotenv from 'dotenv';

dotenv.config();

/**
 * JWT Authentication Middleware
 * 
 * SECURITY FLOW:
 * 1. Extract token from Authorization header
 * 2. Verify token signature using JWT_SECRET
 * 3. Check if token has expired
 * 4. Validate user exists and is active
 * 5. Attach user to request object
 * 
 * If any step fails, return 401 Unauthorized
 * 
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware
 */
export const authenticateToken = async (req, res, next) => {
    try {
        // Step 1: Extract token from Authorization header
        // Expected format: "Bearer <token>"
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1]; // Get token part after "Bearer"
        
        if (!token) {
            // No token provided - unauthorized
            await logUnauthorizedAccess(req, 'No token provided');
            return res.status(401).json({
                success: false,
                message: 'Access denied. No authentication token provided.',
                error: 'MISSING_TOKEN'
            });
        }
        
        // Step 2 & 3: Verify token signature and check expiration
        // jwt.verify throws error if token is invalid or expired
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        
        // Step 4: Validate user exists and is active
        const user = await User.findById(decoded.id);
        
        if (!user) {
            await logUnauthorizedAccess(req, 'User not found for token');
            return res.status(401).json({
                success: false,
                message: 'User not found. Token may be invalid.',
                error: 'USER_NOT_FOUND'
            });
        }
        
        if (!user.isActive) {
            await logUnauthorizedAccess(req, 'Inactive user attempted access', user._id);
            return res.status(401).json({
                success: false,
                message: 'Account is deactivated. Please contact administrator.',
                error: 'ACCOUNT_INACTIVE'
            });
        }
        
        // Check if OTP was verified for this session
        if (!user.isOtpVerified) {
            return res.status(401).json({
                success: false,
                message: 'OTP verification required. Please complete MFA.',
                error: 'OTP_NOT_VERIFIED'
            });
        }
        
        // Step 5: Attach user to request
        // This user object is available in subsequent middleware/routes
        req.user = user;
        req.userId = user._id;
        req.userRole = user.role;
        
        // Continue to next middleware/route
        next();
        
    } catch (error) {
        // Handle specific JWT errors
        if (error.name === 'TokenExpiredError') {
            await logUnauthorizedAccess(req, 'Expired token used');
            return res.status(401).json({
                success: false,
                message: 'Token has expired. Please login again.',
                error: 'TOKEN_EXPIRED'
            });
        }
        
        if (error.name === 'JsonWebTokenError') {
            await logUnauthorizedAccess(req, 'Invalid token signature');
            return res.status(401).json({
                success: false,
                message: 'Invalid token. Authentication failed.',
                error: 'INVALID_TOKEN'
            });
        }
        
        // Generic error
        console.error('Authentication error:', error);
        return res.status(500).json({
            success: false,
            message: 'Authentication error. Please try again.',
            error: 'AUTH_ERROR'
        });
    }
};

/**
 * Generate JWT Token
 * 
 * SECURITY: Token payload contains minimal information
 * - User ID for lookup
 * - Email for logging
 * - Role for quick authorization checks
 * 
 * Token is signed with JWT_SECRET using HMAC-SHA256
 * 
 * @param {Object} user - User object from database
 * @returns {string} JWT token
 */
export const generateToken = (user) => {
    const payload = {
        id: user._id,
        email: user.email,
        role: user.role
    };
    
    // Sign token with secret, expires in 1 hour (configurable)
    return jwt.sign(
        payload,
        process.env.JWT_SECRET,
        { expiresIn: process.env.JWT_EXPIRES_IN || '1h' }
    );
};

/**
 * Optional Authentication Middleware
 * 
 * Similar to authenticateToken but doesn't block if no token
 * Useful for routes that work for both authenticated and anonymous users
 */
export const optionalAuth = async (req, res, next) => {
    try {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];
        
        if (token) {
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            const user = await User.findById(decoded.id);
            
            if (user && user.isActive) {
                req.user = user;
                req.userId = user._id;
                req.userRole = user.role;
            }
        }
        
        next();
    } catch (error) {
        // Token invalid but continue anyway (anonymous access)
        next();
    }
};

/**
 * Helper: Log unauthorized access attempts
 * 
 * SECURITY: Track failed authentication for monitoring
 * Helps detect brute-force or credential stuffing attacks
 */
const logUnauthorizedAccess = async (req, reason, userId = null) => {
    await AuditLog.log({
        userId,
        action: 'ACCESS_UNAUTHORIZED',
        resourceType: 'auth',
        description: `Unauthorized access attempt: ${reason}`,
        metadata: {
            path: req.path,
            method: req.method
        },
        ipAddress: req.ip || req.connection.remoteAddress,
        userAgent: req.headers['user-agent'],
        status: 'failure',
        severity: 'medium'
    });
};

export default {
    authenticateToken,
    generateToken,
    optionalAuth
};
