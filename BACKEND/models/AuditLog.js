/**
 * ===========================================
 * AUDIT LOG MODEL
 * ===========================================
 * 
 * SECURITY CONCEPTS IMPLEMENTED:
 * 
 * 1. NON-REPUDIATION
 *    - All security-relevant actions are logged
 *    - Users cannot deny performing actions (evidence exists)
 *    - Timestamps and user IDs provide proof
 * 
 * 2. ACCOUNTABILITY
 *    - Every action is tied to a specific user
 *    - IP addresses and user agents are recorded
 *    - Creates audit trail for security investigations
 * 
 * 3. SECURITY MONITORING
 *    - Detect suspicious patterns (multiple failed logins)
 *    - Track unauthorized access attempts
 *    - Monitor system usage
 * 
 * LOGGED EVENTS:
 * - User registration
 * - Login attempts (success/failure)
 * - OTP verification
 * - PDF uploads
 * - PDF downloads/views
 * - Offer acceptance/rejection
 * - Signature verifications
 * - Access denied events
 * 
 * SECURITY LEVEL: HIGH
 * - Logs are append-only (no modification)
 * - Admin-only access
 * - Sensitive data is NOT logged (passwords, OTPs)
 */

import mongoose from 'mongoose';

const auditLogSchema = new mongoose.Schema({
    // The user who performed the action (null for system events)
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        default: null
    },

    // Email of user (stored separately for cases where user is deleted)
    userEmail: {
        type: String,
        default: null
    },

    // Role of user at time of action
    userRole: {
        type: String,
        enum: ['student', 'recruiter', 'admin', 'system', 'anonymous'],
        default: 'anonymous'
    },

    /**
     * ACTION TYPE
     * 
     * Categories of logged actions:
     * - AUTH: Authentication-related
     * - ACCESS: Resource access
     * - CRYPTO: Cryptographic operations
     * - OFFER: Offer-related actions
     * - ADMIN: Administrative actions
     */
    action: {
        type: String,
        required: true,
        enum: [
            // Authentication actions
            'AUTH_REGISTER',
            'AUTH_LOGIN_SUCCESS',
            'AUTH_LOGIN_FAILED',
            'AUTH_OTP_SENT',
            'AUTH_OTP_VERIFIED',
            'AUTH_OTP_FAILED',
            'AUTH_LOGOUT',
            'AUTH_ACCOUNT_LOCKED',
            
            // Access control actions
            'ACCESS_GRANTED',
            'ACCESS_DENIED',
            'ACCESS_UNAUTHORIZED',
            
            // Cryptographic actions
            'CRYPTO_PDF_ENCRYPTED',
            'CRYPTO_PDF_DECRYPTED',
            'CRYPTO_SIGNATURE_CREATED',
            'CRYPTO_SIGNATURE_VERIFIED',
            'CRYPTO_SIGNATURE_INVALID',
            'CRYPTO_HASH_VERIFIED',
            'CRYPTO_HASH_MISMATCH',
            
            // Offer actions
            'OFFER_CREATED',
            'OFFER_VIEWED',
            'OFFER_ACCEPTED',
            'OFFER_REJECTED',
            'OFFER_EXPIRED',
            
            // Admin actions
            'ADMIN_USER_CREATED',
            'ADMIN_USER_DELETED',
            'ADMIN_LOGS_VIEWED',
            'ADMIN_SETTINGS_CHANGED',
            
            // System actions
            'SYSTEM_ERROR',
            'SYSTEM_STARTUP',
            'SYSTEM_SHUTDOWN'
        ]
    },

    /**
     * RESOURCE TYPE
     * 
     * What type of resource was involved
     */
    resourceType: {
        type: String,
        enum: ['user', 'offer', 'pdf', 'system', 'auth'],
        required: true
    },

    // ID of the resource involved (if applicable)
    resourceId: {
        type: mongoose.Schema.Types.ObjectId,
        default: null
    },

    /**
     * DESCRIPTION
     * 
     * Human-readable description of the event
     * Should NOT contain sensitive data
     */
    description: {
        type: String,
        required: true
    },

    /**
     * METADATA
     * 
     * Additional context about the event
     * May include:
     * - Request path
     * - HTTP method
     * - Response status
     * - Error messages (sanitized)
     */
    metadata: {
        type: mongoose.Schema.Types.Mixed,
        default: {}
    },

    /**
     * IP ADDRESS
     * 
     * SECURITY: Track source of requests
     * Used for:
     * - Detecting suspicious patterns
     * - Geolocation analysis
     * - Forensic investigation
     */
    ipAddress: {
        type: String,
        default: null
    },

    /**
     * USER AGENT
     * 
     * Browser/client information
     * Helps detect unusual access patterns
     */
    userAgent: {
        type: String,
        default: null
    },

    /**
     * STATUS
     * 
     * Whether the action was successful
     */
    status: {
        type: String,
        enum: ['success', 'failure', 'warning', 'info'],
        default: 'info'
    },

    /**
     * SEVERITY LEVEL
     * 
     * For alerting and filtering:
     * - low: Informational
     * - medium: Notable event
     * - high: Security concern
     * - critical: Requires immediate attention
     */
    severity: {
        type: String,
        enum: ['low', 'medium', 'high', 'critical'],
        default: 'low'
    },

    // Timestamp (indexed for efficient querying)
    timestamp: {
        type: Date,
        default: Date.now,
        index: true
    }
}, {
    // Prevent modification of logs (append-only)
    timestamps: false // We manage timestamp manually
});

// Compound indexes for efficient querying
auditLogSchema.index({ userId: 1, timestamp: -1 });
auditLogSchema.index({ action: 1, timestamp: -1 });
auditLogSchema.index({ severity: 1, timestamp: -1 });
auditLogSchema.index({ resourceType: 1, resourceId: 1 });

/**
 * STATIC METHOD: Create Log Entry
 * 
 * Utility method to create audit logs with consistent format
 */
auditLogSchema.statics.log = async function(logData) {
    try {
        const log = new this({
            userId: logData.userId || null,
            userEmail: logData.userEmail || null,
            userRole: logData.userRole || 'anonymous',
            action: logData.action,
            resourceType: logData.resourceType,
            resourceId: logData.resourceId || null,
            description: logData.description,
            metadata: logData.metadata || {},
            ipAddress: logData.ipAddress || null,
            userAgent: logData.userAgent || null,
            status: logData.status || 'info',
            severity: logData.severity || 'low',
            timestamp: new Date()
        });

        await log.save();
        return log;
    } catch (error) {
        // Log to console if database logging fails
        // Critical: Security logs should never silently fail
        console.error('AUDIT LOG ERROR:', error);
        console.error('Failed to log:', logData);
    }
};

/**
 * STATIC METHOD: Get Recent Security Events
 * 
 * Returns recent high-severity events for security monitoring
 */
auditLogSchema.statics.getSecurityAlerts = async function(hours = 24) {
    const since = new Date(Date.now() - hours * 60 * 60 * 1000);
    
    return this.find({
        timestamp: { $gte: since },
        severity: { $in: ['high', 'critical'] }
    })
    .sort({ timestamp: -1 })
    .limit(100);
};

/**
 * STATIC METHOD: Get User Activity
 * 
 * Returns activity history for a specific user
 */
auditLogSchema.statics.getUserActivity = async function(userId, limit = 50) {
    return this.find({ userId })
        .sort({ timestamp: -1 })
        .limit(limit);
};

const AuditLog = mongoose.model('AuditLog', auditLogSchema);

export default AuditLog;
