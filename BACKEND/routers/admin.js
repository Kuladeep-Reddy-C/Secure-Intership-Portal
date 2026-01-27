/**
 * ===========================================
 * ADMIN ROUTES
 * ===========================================
 * 
 * SECURITY CONCEPTS IMPLEMENTED:
 * 
 * 1. ROLE-BASED ACCESS CONTROL
 *    - Only admin users can access these routes
 *    - HTTP 403 Forbidden for unauthorized access
 * 
 * 2. AUDIT LOG ACCESS
 *    - Admin can view all security audit logs
 *    - Logs provide non-repudiation evidence
 * 
 * 3. SECURITY MONITORING
 *    - View failed login attempts
 *    - Track unauthorized access
 *    - Monitor cryptographic operations
 * 
 * ACCESS CONTROL MATRIX for Admin:
 * ┌──────────────┬─────────┐
 * │ Resource     │ Access  │
 * ├──────────────┼─────────┤
 * │ Audit Logs   │ READ    │
 * │ All Offers   │ READ    │
 * │ All Users    │ READ    │
 * └──────────────┴─────────┘
 * 
 * ROUTES:
 * GET /api/admin/audit-logs       - Get all audit logs
 * GET /api/admin/audit-logs/user/:userId - Get logs for specific user
 * GET /api/admin/security-alerts  - Get high-severity security events
 * GET /api/admin/statistics       - Get system statistics
 * GET /api/admin/users            - Get all users
 */

import express from 'express';
import AuditLog from '../models/AuditLog.js';
import User from '../models/User.js';
import Offer from '../models/Offer.js';
import { authenticateToken } from '../middleware/auth.js';
import { restrictTo, ROLES } from '../middleware/roleAuth.js';

const router = express.Router();

// All admin routes require authentication and admin role
router.use(authenticateToken);
router.use(restrictTo(ROLES.ADMIN));

/**
 * GET /api/admin/audit-logs
 * 
 * Get all audit logs with pagination and filtering
 * 
 * SECURITY: Admin-only access
 * This provides complete audit trail for security monitoring
 * 
 * Query Parameters:
 * - page: Page number (default: 1)
 * - limit: Items per page (default: 50)
 * - action: Filter by action type
 * - severity: Filter by severity level
 * - userId: Filter by user ID
 * - startDate: Filter from date
 * - endDate: Filter to date
 */
router.get('/audit-logs', async (req, res) => {
    try {
        const {
            page = 1,
            limit = 50,
            action,
            severity,
            userId,
            startDate,
            endDate,
            resourceType
        } = req.query;
        
        // Build filter query
        const filter = {};
        
        if (action) filter.action = action;
        if (severity) filter.severity = severity;
        if (userId) filter.userId = userId;
        if (resourceType) filter.resourceType = resourceType;
        
        // Date range filter
        if (startDate || endDate) {
            filter.timestamp = {};
            if (startDate) filter.timestamp.$gte = new Date(startDate);
            if (endDate) filter.timestamp.$lte = new Date(endDate);
        }
        
        // Calculate pagination
        const skip = (parseInt(page) - 1) * parseInt(limit);
        
        // Fetch logs
        const logs = await AuditLog.find(filter)
            .sort({ timestamp: -1 })
            .skip(skip)
            .limit(parseInt(limit))
            .populate('userId', 'name email role');
        
        // Get total count for pagination
        const total = await AuditLog.countDocuments(filter);
        
        // Log this access
        await AuditLog.log({
            userId: req.userId,
            userEmail: req.user.email,
            userRole: 'admin',
            action: 'ADMIN_LOGS_VIEWED',
            resourceType: 'system',
            description: `Admin viewed audit logs (page ${page}, ${logs.length} records)`,
            metadata: { filter, page, limit },
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
            status: 'success',
            severity: 'low'
        });
        
        res.status(200).json({
            success: true,
            data: {
                logs,
                pagination: {
                    page: parseInt(page),
                    limit: parseInt(limit),
                    total,
                    pages: Math.ceil(total / parseInt(limit))
                }
            }
        });
        
    } catch (error) {
        console.error('Get audit logs error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch audit logs',
            error: 'SERVER_ERROR'
        });
    }
});

/**
 * GET /api/admin/audit-logs/user/:userId
 * 
 * Get audit logs for a specific user
 * Useful for investigating user activity
 */
router.get('/audit-logs/user/:userId', async (req, res) => {
    try {
        const { userId } = req.params;
        const { limit = 100 } = req.query;
        
        const logs = await AuditLog.getUserActivity(userId, parseInt(limit));
        
        const user = await User.findById(userId).select('name email role');
        
        res.status(200).json({
            success: true,
            data: {
                user,
                logs,
                count: logs.length
            }
        });
        
    } catch (error) {
        console.error('Get user audit logs error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch user audit logs',
            error: 'SERVER_ERROR'
        });
    }
});

/**
 * GET /api/admin/security-alerts
 * 
 * Get recent high-severity security events
 * 
 * These include:
 * - Failed login attempts
 * - Invalid signatures detected
 * - Unauthorized access attempts
 * - Account lockouts
 * 
 * SECURITY: Critical for monitoring security incidents
 */
router.get('/security-alerts', async (req, res) => {
    try {
        const { hours = 24 } = req.query;
        
        const alerts = await AuditLog.getSecurityAlerts(parseInt(hours));
        
        // Group alerts by type for easier analysis
        const alertSummary = alerts.reduce((acc, alert) => {
            acc[alert.action] = (acc[alert.action] || 0) + 1;
            return acc;
        }, {});
        
        res.status(200).json({
            success: true,
            data: {
                timeframe: `Last ${hours} hours`,
                totalAlerts: alerts.length,
                summary: alertSummary,
                alerts
            }
        });
        
    } catch (error) {
        console.error('Get security alerts error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch security alerts',
            error: 'SERVER_ERROR'
        });
    }
});

/**
 * GET /api/admin/statistics
 * 
 * Get system statistics and metrics
 * 
 * Includes:
 * - User counts by role
 * - Offer counts by status
 * - Recent activity summary
 * - Security event counts
 */
router.get('/statistics', async (req, res) => {
    try {
        // User statistics
        const userStats = await User.aggregate([
            {
                $group: {
                    _id: '$role',
                    count: { $sum: 1 }
                }
            }
        ]);
        
        // Offer statistics
        const offerStats = await Offer.aggregate([
            {
                $group: {
                    _id: '$status',
                    count: { $sum: 1 }
                }
            }
        ]);
        
        // Recent activity (last 24 hours)
        const last24Hours = new Date(Date.now() - 24 * 60 * 60 * 1000);
        const recentActivity = await AuditLog.aggregate([
            {
                $match: {
                    timestamp: { $gte: last24Hours }
                }
            },
            {
                $group: {
                    _id: '$action',
                    count: { $sum: 1 }
                }
            },
            {
                $sort: { count: -1 }
            },
            {
                $limit: 10
            }
        ]);
        
        // Security events (last 24 hours)
        const securityEvents = await AuditLog.countDocuments({
            timestamp: { $gte: last24Hours },
            severity: { $in: ['high', 'critical'] }
        });
        
        // Failed logins
        const failedLogins = await AuditLog.countDocuments({
            timestamp: { $gte: last24Hours },
            action: 'AUTH_LOGIN_FAILED'
        });
        
        res.status(200).json({
            success: true,
            data: {
                users: {
                    byRole: userStats.reduce((acc, item) => {
                        acc[item._id] = item.count;
                        return acc;
                    }, {}),
                    total: userStats.reduce((sum, item) => sum + item.count, 0)
                },
                offers: {
                    byStatus: offerStats.reduce((acc, item) => {
                        acc[item._id] = item.count;
                        return acc;
                    }, {}),
                    total: offerStats.reduce((sum, item) => sum + item.count, 0)
                },
                activity: {
                    last24Hours: recentActivity
                },
                security: {
                    alertsLast24Hours: securityEvents,
                    failedLoginsLast24Hours: failedLogins
                }
            }
        });
        
    } catch (error) {
        console.error('Get statistics error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch statistics',
            error: 'SERVER_ERROR'
        });
    }
});

/**
 * GET /api/admin/users
 * 
 * Get all users in the system
 * 
 * SECURITY: Admin-only - sensitive user data
 */
router.get('/users', async (req, res) => {
    try {
        const { role, isActive, page = 1, limit = 50 } = req.query;
        
        const filter = {};
        if (role) filter.role = role;
        if (isActive !== undefined) filter.isActive = isActive === 'true';
        
        const skip = (parseInt(page) - 1) * parseInt(limit);
        
        const users = await User.find(filter)
            .select('-password -otp -otpExpiry')
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(parseInt(limit));
        
        const total = await User.countDocuments(filter);
        
        res.status(200).json({
            success: true,
            data: {
                users,
                pagination: {
                    page: parseInt(page),
                    limit: parseInt(limit),
                    total,
                    pages: Math.ceil(total / parseInt(limit))
                }
            }
        });
        
    } catch (error) {
        console.error('Get users error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch users',
            error: 'SERVER_ERROR'
        });
    }
});

/**
 * GET /api/admin/offers
 * 
 * Get all offers in the system
 */
router.get('/offers', async (req, res) => {
    try {
        const { status, page = 1, limit = 50 } = req.query;
        
        const filter = {};
        if (status) filter.status = status;
        
        const skip = (parseInt(page) - 1) * parseInt(limit);
        
        const offers = await Offer.find(filter)
            .select('-encryptedPdfData -encryptedAesKey -aesIv')
            .populate('recruiterId', 'name email')
            .populate('studentId', 'name email rollNo')
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(parseInt(limit));
        
        const total = await Offer.countDocuments(filter);
        
        res.status(200).json({
            success: true,
            data: {
                offers,
                pagination: {
                    page: parseInt(page),
                    limit: parseInt(limit),
                    total,
                    pages: Math.ceil(total / parseInt(limit))
                }
            }
        });
        
    } catch (error) {
        console.error('Get offers error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch offers',
            error: 'SERVER_ERROR'
        });
    }
});

export default router;
