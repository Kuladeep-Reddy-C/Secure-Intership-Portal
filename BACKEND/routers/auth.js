// /**
//  * ===========================================
//  * AUTHENTICATION ROUTES
//  * ===========================================
//  * 
//  * SECURITY CONCEPTS IMPLEMENTED:
//  * 
//  * 1. SINGLE-FACTOR AUTHENTICATION
//  *    - Email/Roll No + Password login
//  *    - Password hashed with bcrypt + salt
//  * 
//  * 2. MULTI-FACTOR AUTHENTICATION (MFA)
//  *    - After password verification, OTP sent via email
//  *    - OTP is time-bound (5 minutes)
//  *    - OTP is hashed before storage
//  * 
//  * 3. RATE LIMITING
//  *    - Prevents brute-force attacks
//  *    - Limits login attempts per IP
//  * 
//  * 4. ACCOUNT LOCKOUT
//  *    - 5 failed attempts = 30 minute lockout
//  *    - Mitigates credential stuffing
//  * 
//  * AUTHENTICATION FLOW:
//  * 1. User submits email/rollNo + password
//  * 2. Server verifies credentials (bcrypt compare)
//  * 3. Server generates OTP and sends via email
//  * 4. User submits OTP
//  * 5. Server verifies OTP (hash comparison)
//  * 6. Server issues JWT token
//  * 
//  * ROUTES:
//  * POST /api/auth/register - Create new user
//  * POST /api/auth/login    - Login (returns temp token, sends OTP)
//  * POST /api/auth/verify-otp - Verify OTP (returns full access token)
//  * POST /api/auth/resend-otp - Resend OTP
//  * GET  /api/auth/me        - Get current user info
//  */

// import express from 'express';
// import rateLimit from 'express-rate-limit';
// import User from '../models/User.js';
// import AuditLog from '../models/AuditLog.js';
// import { generateToken, authenticateToken } from '../middleware/auth.js';
// import { sendOTPEmail } from '../utils/email.js';
// import { generateRSAKeyPair } from '../utils/encryption.js';

// const router = express.Router();

// /**
//  * RATE LIMITER for authentication routes
//  * 
//  * SECURITY: Prevents brute-force attacks
//  * - Max 5 requests per 15 minutes per IP
//  * - Slows down automated attacks
//  */
// const authLimiter = rateLimit({
//     windowMs: 15 * 60 * 1000, // 15 minutes
//     max: 10, // 10 requests per window
//     message: {
//         success: false,
//         message: 'Too many authentication attempts. Please try again after 15 minutes.',
//         error: 'RATE_LIMIT_EXCEEDED'
//     },
//     standardHeaders: true,
//     legacyHeaders: false
// });

// /**
//  * POST /api/auth/register
//  * 
//  * Register a new user
//  * 
//  * SECURITY:
//  * - Password is automatically hashed by User model pre-save hook
//  * - Email uniqueness enforced by database
//  * - RSA key pair generated for each user (for hybrid encryption)
//  */
// router.post('/register', authLimiter, async (req, res) => {
//     try {
//         const { name, email, password, role, rollNo } = req.body;

//         // Validate required fields
//         if (!name || !email || !password) {
//             return res.status(400).json({
//                 success: false,
//                 message: 'Name, email, and password are required',
//                 error: 'MISSING_FIELDS'
//             });
//         }

//         // Validate email format
//         const emailRegex = /^\S+@\S+\.\S+$/;
//         if (!emailRegex.test(email)) {
//             return res.status(400).json({
//                 success: false,
//                 message: 'Please provide a valid email address',
//                 error: 'INVALID_EMAIL'
//             });
//         }

//         // Validate password strength
//         if (password.length < 8) {
//             return res.status(400).json({
//                 success: false,
//                 message: 'Password must be at least 8 characters long',
//                 error: 'WEAK_PASSWORD'
//             });
//         }

//         // Check if user already exists
//         const existingUser = await User.findOne({ email: email.toLowerCase() });
//         if (existingUser) {
//             return res.status(409).json({
//                 success: false,
//                 message: 'Email is already registered',
//                 error: 'EMAIL_EXISTS'
//             });
//         }

//         // Validate role (only allow specific roles)
//         const validRoles = ['student', 'recruiter'];
//         const userRole = validRoles.includes(role) ? role : 'student';

//         // Generate RSA key pair for the user (for hybrid encryption)
//         const { publicKey, privateKey } = generateRSAKeyPair();

//         // Create new user
//         // Password will be automatically hashed by pre-save middleware
//         const user = new User({
//             name,
//             email: email.toLowerCase(),
//             password,
//             role: userRole,
//             rollNo: rollNo || null,
//             publicKey,
//             isOtpVerified: false
//         });

//         await user.save();

//         // Log registration event
//         await AuditLog.log({
//             userId: user._id,
//             userEmail: user.email,
//             userRole: user.role,
//             action: 'AUTH_REGISTER',
//             resourceType: 'user',
//             resourceId: user._id,
//             description: `New user registered: ${user.email}`,
//             ipAddress: req.ip,
//             userAgent: req.headers['user-agent'],
//             status: 'success',
//             severity: 'low'
//         });

//         // Return success (don't return password or private key!)
//         res.status(201).json({
//             success: true,
//             message: 'Registration successful. Please login to continue.',
//             data: {
//                 id: user._id,
//                 name: user.name,
//                 email: user.email,
//                 role: user.role,
//                 // Return private key ONLY at registration (user must store it securely)
//                 // This is needed for decrypting offers later
//                 privateKey: privateKey
//             }
//         });

//     } catch (error) {
//         console.error('Registration error:', error);

//         // Handle mongoose validation errors
//         if (error.name === 'ValidationError') {
//             const messages = Object.values(error.errors).map(e => e.message);
//             return res.status(400).json({
//                 success: false,
//                 message: messages.join('. '),
//                 error: 'VALIDATION_ERROR'
//             });
//         }

//         // Handle duplicate key error
//         if (error.code === 11000) {
//             return res.status(409).json({
//                 success: false,
//                 message: 'Email or Roll Number already exists',
//                 error: 'DUPLICATE_KEY'
//             });
//         }

//         res.status(500).json({
//             success: false,
//             message: 'Registration failed. Please try again.',
//             error: 'SERVER_ERROR'
//         });
//     }
// });

// /**
//  * POST /api/auth/login
//  * 
//  * Step 1 of authentication: Verify credentials and send OTP
//  * 
//  * SECURITY FLOW:
//  * 1. Find user by email
//  * 2. Check if account is locked
//  * 3. Verify password using bcrypt
//  * 4. Generate and send OTP via email
//  * 5. Return temporary token for OTP verification
//  */
// router.post('/login', authLimiter, async (req, res) => {
//     try {
//         const { email, password } = req.body;

//         // Validate input
//         if (!email || !password) {
//             return res.status(400).json({
//                 success: false,
//                 message: 'Email and password are required',
//                 error: 'MISSING_CREDENTIALS'
//             });
//         }

//         // Find user (include password field for comparison)
//         const user = await User.findOne({ email: email.toLowerCase() }).select('+password');

//         if (!user) {
//             // Don't reveal whether email exists (security best practice)
//             await AuditLog.log({
//                 userEmail: email,
//                 action: 'AUTH_LOGIN_FAILED',
//                 resourceType: 'auth',
//                 description: `Login attempt with non-existent email: ${email}`,
//                 ipAddress: req.ip,
//                 userAgent: req.headers['user-agent'],
//                 status: 'failure',
//                 severity: 'medium'
//             });

//             return res.status(401).json({
//                 success: false,
//                 message: 'Invalid email or password',
//                 error: 'INVALID_CREDENTIALS'
//             });
//         }

//         // Check if account is locked
//         if (user.isLocked()) {
//             await AuditLog.log({
//                 userId: user._id,
//                 userEmail: user.email,
//                 userRole: user.role,
//                 action: 'AUTH_ACCOUNT_LOCKED',
//                 resourceType: 'auth',
//                 description: `Login attempt on locked account`,
//                 ipAddress: req.ip,
//                 userAgent: req.headers['user-agent'],
//                 status: 'failure',
//                 severity: 'high'
//             });

//             return res.status(423).json({
//                 success: false,
//                 message: 'Account is temporarily locked due to multiple failed login attempts. Please try again later.',
//                 error: 'ACCOUNT_LOCKED'
//             });
//         }

//         // Verify password using bcrypt
//         const isPasswordValid = await user.comparePassword(password);

//         if (!isPasswordValid) {
//             // Increment failed login attempts
//             await user.incrementLoginAttempts();

//             await AuditLog.log({
//                 userId: user._id,
//                 userEmail: user.email,
//                 userRole: user.role,
//                 action: 'AUTH_LOGIN_FAILED',
//                 resourceType: 'auth',
//                 description: `Failed login attempt (wrong password). Attempts: ${user.loginAttempts}`,
//                 ipAddress: req.ip,
//                 userAgent: req.headers['user-agent'],
//                 status: 'failure',
//                 severity: 'medium'
//             });

//             return res.status(401).json({
//                 success: false,
//                 message: 'Invalid email or password',
//                 error: 'INVALID_CREDENTIALS'
//             });
//         }

//         // Password correct - Generate OTP for MFA
//         console.log(`[DEBUG] Token correct, generating OTP for ${user.email}`);
//         const otp = user.generateOTP();
//         user.isOtpVerified = false;
//         await user.save();
//         console.log(`[DEBUG] OTP saved to database for ${user.email}`);

//         // Send OTP via email
//         const emailResult = await sendOTPEmail(user.email, otp, user.name);
//         console.log(`[DEBUG] Email result: ${JSON.stringify(emailResult)}`);

//         // Log OTP sent
//         await AuditLog.log({
//             userId: user._id,
//             userEmail: user.email,
//             userRole: user.role,
//             action: 'AUTH_OTP_SENT',
//             resourceType: 'auth',
//             description: `OTP sent for MFA verification`,
//             ipAddress: req.ip,
//             userAgent: req.headers['user-agent'],
//             status: emailResult.success ? 'success' : 'warning',
//             severity: 'low'
//         });

//         // Generate temporary token (valid only for OTP verification)
//         const tempToken = generateToken(user);

//         res.status(200).json({
//             success: true,
//             message: 'Password verified. OTP has been sent to your email.',
//             requiresOTP: true,
//             data: {
//                 tempToken, // Use this to verify OTP
//                 email: user.email,
//                 otpSent: emailResult.success
//             }
//         });

//     } catch (error) {
//         console.error('Login error:', error);
//         res.status(500).json({
//             success: false,
//             message: 'Login failed. Please try again.',
//             error: 'SERVER_ERROR'
//         });
//     }
// });

// /**
//  * POST /api/auth/verify-otp
//  * 
//  * Step 2 of authentication: Verify OTP and issue full access token
//  * 
//  * SECURITY:
//  * - OTP is hashed and compared
//  * - OTP has time-bound expiry
//  * - OTP is cleared after use (one-time use)
//  */
// router.post('/verify-otp', authLimiter, async (req, res) => {
//     try {
//         const { tempToken, otp } = req.body;

//         if (!tempToken || !otp) {
//             return res.status(400).json({
//                 success: false,
//                 message: 'Token and OTP are required',
//                 error: 'MISSING_FIELDS'
//             });
//         }

//         // Verify temp token and get user
//         let decoded;
//         try {
//             decoded = require('jsonwebtoken').verify(tempToken, process.env.JWT_SECRET);
//         } catch (error) {
//             return res.status(401).json({
//                 success: false,
//                 message: 'Invalid or expired token. Please login again.',
//                 error: 'INVALID_TOKEN'
//             });
//         }

//         // Get user with OTP fields
//         const user = await User.findById(decoded.id).select('+otp +otpExpiry');

//         if (!user) {
//             return res.status(401).json({
//                 success: false,
//                 message: 'User not found',
//                 error: 'USER_NOT_FOUND'
//             });
//         }

//         // Verify OTP
//         console.log(`[DEBUG] Verifying OTP for user ${user.email}`);
//         const isOtpValid = user.verifyOTP(otp);

//         if (!isOtpValid) {
//             console.log(`[DEBUG] OTP invalid for user ${user.email}`);
//             await AuditLog.log({
//                 userId: user._id,
//                 userEmail: user.email,
//                 userRole: user.role,
//                 action: 'AUTH_OTP_FAILED',
//                 resourceType: 'auth',
//                 description: `Invalid or expired OTP provided`,
//                 ipAddress: req.ip,
//                 userAgent: req.headers['user-agent'],
//                 status: 'failure',
//                 severity: 'high'
//             });

//             return res.status(401).json({
//                 success: false,
//                 message: 'Invalid or expired OTP. Please try again or request a new OTP.',
//                 error: 'INVALID_OTP'
//             });
//         }

//         // OTP valid - Clear OTP and mark as verified
//         user.clearOTP();
//         await user.resetLoginAttempts();
//         await user.save();

//         // Log successful authentication
//         await AuditLog.log({
//             userId: user._id,
//             userEmail: user.email,
//             userRole: user.role,
//             action: 'AUTH_OTP_VERIFIED',
//             resourceType: 'auth',
//             description: `MFA completed successfully. User logged in.`,
//             ipAddress: req.ip,
//             userAgent: req.headers['user-agent'],
//             status: 'success',
//             severity: 'low'
//         });

//         await AuditLog.log({
//             userId: user._id,
//             userEmail: user.email,
//             userRole: user.role,
//             action: 'AUTH_LOGIN_SUCCESS',
//             resourceType: 'auth',
//             description: `User successfully logged in with MFA`,
//             ipAddress: req.ip,
//             userAgent: req.headers['user-agent'],
//             status: 'success',
//             severity: 'low'
//         });

//         // Generate full access token
//         const accessToken = generateToken(user);

//         res.status(200).json({
//             success: true,
//             message: 'Authentication successful!',
//             data: {
//                 token: accessToken,
//                 user: {
//                     id: user._id,
//                     name: user.name,
//                     email: user.email,
//                     role: user.role,
//                     publicKey: user.publicKey
//                 }
//             }
//         });

//     } catch (error) {
//         console.error('OTP verification error:', error);
//         res.status(500).json({
//             success: false,
//             message: 'OTP verification failed. Please try again.',
//             error: 'SERVER_ERROR'
//         });
//     }
// });

// /**
//  * POST /api/auth/resend-otp
//  * 
//  * Resend OTP to user's email
//  */
// router.post('/resend-otp', authLimiter, async (req, res) => {
//     try {
//         const { tempToken } = req.body;

//         if (!tempToken) {
//             return res.status(400).json({
//                 success: false,
//                 message: 'Token is required',
//                 error: 'MISSING_TOKEN'
//             });
//         }

//         // Verify temp token
//         let decoded;
//         try {
//             decoded = require('jsonwebtoken').verify(tempToken, process.env.JWT_SECRET);
//         } catch (error) {
//             return res.status(401).json({
//                 success: false,
//                 message: 'Invalid or expired token. Please login again.',
//                 error: 'INVALID_TOKEN'
//             });
//         }

//         const user = await User.findById(decoded.id);

//         if (!user) {
//             return res.status(401).json({
//                 success: false,
//                 message: 'User not found',
//                 error: 'USER_NOT_FOUND'
//             });
//         }

//         // Generate new OTP
//         const otp = user.generateOTP();
//         await user.save();

//         // Send OTP
//         const emailResult = await sendOTPEmail(user.email, otp, user.name);

//         await AuditLog.log({
//             userId: user._id,
//             userEmail: user.email,
//             userRole: user.role,
//             action: 'AUTH_OTP_SENT',
//             resourceType: 'auth',
//             description: `OTP resent for MFA verification`,
//             ipAddress: req.ip,
//             userAgent: req.headers['user-agent'],
//             status: emailResult.success ? 'success' : 'warning',
//             severity: 'low'
//         });

//         res.status(200).json({
//             success: true,
//             message: 'New OTP has been sent to your email.',
//             data: {
//                 email: user.email,
//                 otpSent: emailResult.success
//             }
//         });

//     } catch (error) {
//         console.error('Resend OTP error:', error);
//         res.status(500).json({
//             success: false,
//             message: 'Failed to resend OTP. Please try again.',
//             error: 'SERVER_ERROR'
//         });
//     }
// });

// /**
//  * GET /api/auth/me
//  * 
//  * Get current authenticated user's information
//  */
// router.get('/me', authenticateToken, async (req, res) => {
//     try {
//         const user = await User.findById(req.userId);

//         if (!user) {
//             return res.status(404).json({
//                 success: false,
//                 message: 'User not found',
//                 error: 'USER_NOT_FOUND'
//             });
//         }

//         res.status(200).json({
//             success: true,
//             data: {
//                 id: user._id,
//                 name: user.name,
//                 email: user.email,
//                 role: user.role,
//                 rollNo: user.rollNo,
//                 publicKey: user.publicKey,
//                 isActive: user.isActive,
//                 createdAt: user.createdAt,
//                 lastLogin: user.lastLogin
//             }
//         });

//     } catch (error) {
//         console.error('Get user error:', error);
//         res.status(500).json({
//             success: false,
//             message: 'Failed to get user information',
//             error: 'SERVER_ERROR'
//         });
//     }
// });

// /**
//  * POST /api/auth/logout
//  * 
//  * Logout user (mark OTP as not verified)
//  */
// router.post('/logout', authenticateToken, async (req, res) => {
//     try {
//         const user = await User.findById(req.userId);

//         if (user) {
//             user.isOtpVerified = false;
//             await user.save();

//             await AuditLog.log({
//                 userId: user._id,
//                 userEmail: user.email,
//                 userRole: user.role,
//                 action: 'AUTH_LOGOUT',
//                 resourceType: 'auth',
//                 description: 'User logged out',
//                 ipAddress: req.ip,
//                 userAgent: req.headers['user-agent'],
//                 status: 'success',
//                 severity: 'low'
//             });
//         }

//         res.status(200).json({
//             success: true,
//             message: 'Logged out successfully'
//         });

//     } catch (error) {
//         console.error('Logout error:', error);
//         res.status(500).json({
//             success: false,
//             message: 'Logout failed',
//             error: 'SERVER_ERROR'
//         });
//     }
// });

// export default router;


/**
 * ===========================================
 * AUTH ROUTES (UPDATED DEBUG)
 * ===========================================
 */

import express from 'express';
import jwt from 'jsonwebtoken';
import rateLimit from 'express-rate-limit';
import User from '../models/User.js';
import AuditLog from '../models/AuditLog.js';
import { generateToken } from '../middleware/auth.js';
import { sendOTPEmail } from '../utils/email.js';
import { generateRSAKeyPair } from '../utils/encryption.js';

const router = express.Router();

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10
});

/**
 * ===========================================
 * LOGIN (STEP 1)
 * ===========================================
 */
router.post('/login', authLimiter, async (req, res) => {
    const { email, password } = req.body;

    const user = await User
        .findOne({ email: email.toLowerCase() })
        .select('+password');

    if (!user) {
        return res.status(401).json({ success: false });
    }

    const isValid = await user.comparePassword(password);
    if (!isValid) {
        await user.incrementLoginAttempts();
        return res.status(401).json({ success: false });
    }

    const otp = user.generateOTP();
    await user.save();

    await sendOTPEmail(user.email, otp, user.name);

    const tempToken = generateToken(user);

    res.json({
        success: true,
        requiresOTP: true,
        data: { tempToken, email: user.email }
    });
});

/**
 * ===========================================
 * VERIFY OTP (STEP 2)
 * ===========================================
 */
router.post('/verify-otp', authLimiter, async (req, res) => {
    console.log('================ VERIFY OTP API =================');
    console.log('[REQ BODY]', req.body);

    const { tempToken, otp } = req.body;

    if (!tempToken || !otp) {
        console.log('[ERROR] Missing fields');
        return res.status(400).json({ success: false });
    }

    let decoded;
    try {
        decoded = jwt.verify(tempToken, process.env.JWT_SECRET);
        console.log('[JWT DECODED]', decoded);
    } catch (err) {
        console.log('[JWT ERROR]', err.message);
        return res.status(401).json({ success: false });
    }

    const user = await User
        .findById(decoded.id)
        .select('+otp +otpExpiry');

    if (!user) {
        console.log('[ERROR] User not found');
        return res.status(401).json({ success: false });
    }

    console.log('[USER FOUND]', user.email);

    const isOtpValid = user.verifyOTP(otp);

    if (!isOtpValid) {
        console.log('[FINAL RESULT] ❌ OTP INVALID');
        return res.status(401).json({
            success: false,
            message: 'Invalid or expired OTP'
        });
    }

    user.clearOTP();
    await user.resetLoginAttempts();
    await user.save();

    const accessToken = generateToken(user);

    console.log('[FINAL RESULT] ✅ OTP VERIFIED');

    res.json({
        success: true,
        data: {
            token: accessToken,
            user: {
                id: user._id,
                email: user.email,
                role: user.role
            }
        }
    });
});

/**
 * ===========================================
 * REGISTER (CREATE USER)
 * ===========================================
 */
router.post('/register', authLimiter, async (req, res) => {
    try {
        console.log('================ REGISTER API =================');
        console.log('[REQ BODY]', req.body);

        const { name, email, password, role, rollNo } = req.body;

        // ---------------------------
        // BASIC VALIDATION
        // ---------------------------
        if (!name || !email || !password) {
            return res.status(400).json({
                success: false,
                message: 'Name, email, and password are required'
            });
        }

        if (password.length < 8) {
            return res.status(400).json({
                success: false,
                message: 'Password must be at least 8 characters'
            });
        }

        // ---------------------------
        // ROLE VALIDATION
        // ---------------------------
        const allowedRoles = ['student', 'recruiter'];
        const finalRole = allowedRoles.includes(role) ? role : 'student';

        // ---------------------------
        // CHECK EXISTING USER
        // ---------------------------
        const existingUser = await User.findOne({
            email: email.toLowerCase()
        });

        if (existingUser) {
            return res.status(409).json({
                success: false,
                message: 'Email already registered'
            });
        }

        // ---------------------------
        // GENERATE RSA KEY PAIR
        // ---------------------------
        // NOTE: this function already exists in your project
        const { publicKey, privateKey } = generateRSAKeyPair();

        // ---------------------------
        // CREATE USER
        // ---------------------------
        const user = new User({
            name,
            email: email.toLowerCase(),
            password, // hashed by pre-save hook
            role: finalRole,
            rollNo: rollNo || undefined,
            publicKey,
            isOtpVerified: false
        });

        await user.save();

        console.log('[REGISTER SUCCESS]', user.email, user.role);

        // ---------------------------
        // AUDIT LOG
        // ---------------------------
        await AuditLog.log({
            userId: user._id,
            userEmail: user.email,
            userRole: user.role,
            action: 'AUTH_REGISTER',
            resourceType: 'user',
            resourceId: user._id,
            description: `User registered: ${user.email}`,
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
            status: 'success',
            severity: 'low'
        });

        // ---------------------------
        // RESPONSE (PRIVATE KEY ONLY ONCE)
        // ---------------------------
        res.status(201).json({
            success: true,
            message: 'Registration successful',
            data: {
                id: user._id,
                name: user.name,
                email: user.email,
                role: user.role,
                privateKey // ⚠️ shown ONLY now
            }
        });

    } catch (error) {
        console.error('[REGISTER ERROR]', error);

        res.status(500).json({
            success: false,
            message: 'Registration failed'
        });
    }
});

import { authenticateToken } from '../middleware/auth.js';

router.get('/me', authenticateToken, (req, res) => {
    res.status(200).json({
        success: true,
        data: {
            id: req.user._id,
            email: req.user.email,
            role: req.user.role
        }
    });
});


export default router;
