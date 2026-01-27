/**
 * ===========================================
 * ROLE-BASED ACCESS CONTROL (RBAC) MIDDLEWARE
 * ===========================================
 * 
 * SECURITY CONCEPTS IMPLEMENTED:
 * 
 * 1. ACCESS CONTROL MATRIX
 *    Defines which roles (subjects) can perform which actions on resources (objects)
 * 
 *    ┌──────────────┬─────────────┬───────────────┬────────────┬─────────────┐
 *    │ Role/Action  │ View Offers │ Accept/Reject │ Upload PDF │ Audit Logs  │
 *    ├──────────────┼─────────────┼───────────────┼────────────┼─────────────┤
 *    │ Student      │     ✅       │      ✅        │     ❌      │     ❌       │
 *    │ Recruiter    │     ✅       │      ❌        │     ✅      │     ❌       │
 *    │ Admin        │     ✅       │      ❌        │     ❌      │     ✅       │
 *    └──────────────┴─────────────┴───────────────┴────────────┴─────────────┘
 * 
 * 2. PRINCIPLE OF LEAST PRIVILEGE
 *    - Users only have permissions necessary for their role
 *    - Minimizes damage if account is compromised
 * 
 * 3. SEPARATION OF DUTIES
 *    - Different roles for different functions
 *    - No single role has all permissions
 * 
 * SECURITY LEVEL: HIGH
 * - Role checked on every protected route
 * - Unauthorized access returns HTTP 403 Forbidden
 * - All access attempts are logged
 * 
 * POSSIBLE ATTACKS & MITIGATIONS:
 * - Privilege Escalation → Strict role validation on every request
 * - Unauthorized Access → Role-specific middleware on routes
 * - Insider Threats → Audit logging of all access
 */

import AuditLog from '../models/AuditLog.js';

/**
 * SUBJECTS (Roles) in our system
 */
export const ROLES = {
    STUDENT: 'student',
    RECRUITER: 'recruiter',
    ADMIN: 'admin'
};

/**
 * OBJECTS (Resources) in our system
 */
export const RESOURCES = {
    OFFER: 'offer',
    PDF: 'pdf',
    AUDIT_LOG: 'audit_log',
    USER: 'user'
};

/**
 * ACTIONS that can be performed
 */
export const ACTIONS = {
    CREATE: 'create',
    READ: 'read',
    UPDATE: 'update',
    DELETE: 'delete',
    ACCEPT: 'accept',
    REJECT: 'reject',
    UPLOAD: 'upload',
    DOWNLOAD: 'download',
    VERIFY: 'verify'
};

/**
 * ACCESS CONTROL MATRIX
 * 
 * Defines permissions for each role on each resource
 * Format: role -> resource -> [allowed actions]
 * 
 * This is the single source of truth for authorization
 */
const ACCESS_CONTROL_MATRIX = {
    [ROLES.STUDENT]: {
        [RESOURCES.OFFER]: [ACTIONS.READ, ACTIONS.ACCEPT, ACTIONS.REJECT],
        [RESOURCES.PDF]: [ACTIONS.READ, ACTIONS.DOWNLOAD, ACTIONS.VERIFY],
        [RESOURCES.AUDIT_LOG]: [],  // No access
        [RESOURCES.USER]: [ACTIONS.READ, ACTIONS.UPDATE]  // Own profile only
    },
    [ROLES.RECRUITER]: {
        [RESOURCES.OFFER]: [ACTIONS.CREATE, ACTIONS.READ],
        [RESOURCES.PDF]: [ACTIONS.UPLOAD, ACTIONS.READ],
        [RESOURCES.AUDIT_LOG]: [],  // No access
        [RESOURCES.USER]: [ACTIONS.READ, ACTIONS.UPDATE]  // Own profile only
    },
    [ROLES.ADMIN]: {
        [RESOURCES.OFFER]: [ACTIONS.READ],
        [RESOURCES.PDF]: [ACTIONS.READ],
        [RESOURCES.AUDIT_LOG]: [ACTIONS.READ],  // Full access
        [RESOURCES.USER]: [ACTIONS.READ, ACTIONS.UPDATE, ACTIONS.DELETE, ACTIONS.CREATE]
    }
};

/**
 * Check if a role has permission to perform an action on a resource
 * 
 * @param {string} role - User's role
 * @param {string} resource - Resource being accessed
 * @param {string} action - Action being performed
 * @returns {boolean} Whether access is allowed
 */
export const hasPermission = (role, resource, action) => {
    const rolePermissions = ACCESS_CONTROL_MATRIX[role];
    
    if (!rolePermissions) {
        return false;  // Unknown role - deny access
    }
    
    const resourcePermissions = rolePermissions[resource];
    
    if (!resourcePermissions) {
        return false;  // Unknown resource - deny access
    }
    
    return resourcePermissions.includes(action);
};

/**
 * Authorization Middleware Factory
 * 
 * Creates middleware that checks if user has required permission
 * 
 * USAGE:
 * router.get('/offers', authorize(RESOURCES.OFFER, ACTIONS.READ), getOffers);
 * router.post('/offers', authorize(RESOURCES.OFFER, ACTIONS.CREATE), createOffer);
 * 
 * @param {string} resource - Resource being accessed
 * @param {string} action - Action being performed
 * @returns {Function} Express middleware function
 */
export const authorize = (resource, action) => {
    return async (req, res, next) => {
        try {
            // User must be authenticated (req.user set by authenticateToken middleware)
            if (!req.user) {
                return res.status(401).json({
                    success: false,
                    message: 'Authentication required',
                    error: 'NOT_AUTHENTICATED'
                });
            }
            
            const userRole = req.user.role;
            
            // Check permission using Access Control Matrix
            if (!hasPermission(userRole, resource, action)) {
                // Log access denied event
                await logAccessDenied(req, resource, action);
                
                // Return 403 Forbidden
                return res.status(403).json({
                    success: false,
                    message: `Access denied. ${userRole} role cannot ${action} ${resource}.`,
                    error: 'FORBIDDEN',
                    requiredPermission: {
                        resource,
                        action
                    }
                });
            }
            
            // Log access granted (for audit trail)
            await logAccessGranted(req, resource, action);
            
            // Permission granted - continue to route handler
            next();
            
        } catch (error) {
            console.error('Authorization error:', error);
            return res.status(500).json({
                success: false,
                message: 'Authorization error',
                error: 'AUTH_ERROR'
            });
        }
    };
};

/**
 * Role Restriction Middleware Factory
 * 
 * Simpler alternative - just check if user has one of the allowed roles
 * 
 * USAGE:
 * router.get('/admin', restrictTo(ROLES.ADMIN), adminDashboard);
 * router.post('/upload', restrictTo(ROLES.RECRUITER), uploadPDF);
 * 
 * @param {...string} allowedRoles - Roles that are allowed access
 * @returns {Function} Express middleware function
 */
export const restrictTo = (...allowedRoles) => {
    return async (req, res, next) => {
        try {
            // User must be authenticated
            if (!req.user) {
                return res.status(401).json({
                    success: false,
                    message: 'Authentication required',
                    error: 'NOT_AUTHENTICATED'
                });
            }
            
            const userRole = req.user.role;
            
            // Check if user's role is in allowed roles
            if (!allowedRoles.includes(userRole)) {
                // Log access denied
                await AuditLog.log({
                    userId: req.user._id,
                    userEmail: req.user.email,
                    userRole: userRole,
                    action: 'ACCESS_DENIED',
                    resourceType: 'system',
                    description: `Role-based access denied. Required: [${allowedRoles.join(', ')}], Has: ${userRole}`,
                    metadata: {
                        path: req.path,
                        method: req.method,
                        allowedRoles,
                        userRole
                    },
                    ipAddress: req.ip || req.connection.remoteAddress,
                    userAgent: req.headers['user-agent'],
                    status: 'failure',
                    severity: 'high'
                });
                
                return res.status(403).json({
                    success: false,
                    message: `Access denied. This resource requires ${allowedRoles.join(' or ')} role.`,
                    error: 'FORBIDDEN'
                });
            }
            
            next();
            
        } catch (error) {
            console.error('Role restriction error:', error);
            return res.status(500).json({
                success: false,
                message: 'Authorization error',
                error: 'AUTH_ERROR'
            });
        }
    };
};

/**
 * Resource Ownership Check Middleware
 * 
 * Ensures user can only access their own resources
 * Example: Student can only view their own offers
 * 
 * @param {string} paramName - Name of the URL parameter containing resource owner ID
 * @returns {Function} Express middleware function
 */
export const checkOwnership = (paramName = 'userId') => {
    return async (req, res, next) => {
        try {
            const resourceOwnerId = req.params[paramName];
            const requestingUserId = req.user._id.toString();
            
            // Admins can access any resource
            if (req.user.role === ROLES.ADMIN) {
                return next();
            }
            
            // Check if user is accessing their own resource
            if (resourceOwnerId !== requestingUserId) {
                await AuditLog.log({
                    userId: req.user._id,
                    userEmail: req.user.email,
                    userRole: req.user.role,
                    action: 'ACCESS_DENIED',
                    resourceType: 'user',
                    resourceId: resourceOwnerId,
                    description: `Attempted to access another user's resource`,
                    metadata: {
                        path: req.path,
                        method: req.method,
                        targetUserId: resourceOwnerId
                    },
                    ipAddress: req.ip,
                    userAgent: req.headers['user-agent'],
                    status: 'failure',
                    severity: 'high'
                });
                
                return res.status(403).json({
                    success: false,
                    message: 'Access denied. You can only access your own resources.',
                    error: 'FORBIDDEN'
                });
            }
            
            next();
            
        } catch (error) {
            console.error('Ownership check error:', error);
            return res.status(500).json({
                success: false,
                message: 'Authorization error',
                error: 'AUTH_ERROR'
            });
        }
    };
};

/**
 * Helper: Log access denied event
 */
const logAccessDenied = async (req, resource, action) => {
    await AuditLog.log({
        userId: req.user._id,
        userEmail: req.user.email,
        userRole: req.user.role,
        action: 'ACCESS_DENIED',
        resourceType: resource,
        description: `Access denied for ${action} on ${resource}`,
        metadata: {
            path: req.path,
            method: req.method,
            attemptedAction: action,
            attemptedResource: resource
        },
        ipAddress: req.ip || req.connection.remoteAddress,
        userAgent: req.headers['user-agent'],
        status: 'failure',
        severity: 'high'
    });
};

/**
 * Helper: Log access granted event
 */
const logAccessGranted = async (req, resource, action) => {
    await AuditLog.log({
        userId: req.user._id,
        userEmail: req.user.email,
        userRole: req.user.role,
        action: 'ACCESS_GRANTED',
        resourceType: resource,
        description: `Access granted for ${action} on ${resource}`,
        metadata: {
            path: req.path,
            method: req.method,
            grantedAction: action,
            grantedResource: resource
        },
        ipAddress: req.ip || req.connection.remoteAddress,
        userAgent: req.headers['user-agent'],
        status: 'success',
        severity: 'low'
    });
};

export default {
    ROLES,
    RESOURCES,
    ACTIONS,
    hasPermission,
    authorize,
    restrictTo,
    checkOwnership
};
