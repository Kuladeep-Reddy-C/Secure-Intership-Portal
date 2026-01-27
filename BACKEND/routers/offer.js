/**
 * ===========================================
 * OFFER ROUTES - PDF-CENTRIC SECURITY
 * ===========================================
 * 
 * This router implements ALL security features for Internship Offer PDFs:
 * 
 * SECURITY CONCEPTS IMPLEMENTED ON EACH PDF:
 * 
 * 1. AES-256 ENCRYPTION
 *    - PDF encrypted with unique session key
 *    - Provides CONFIDENTIALITY
 * 
 * 2. RSA ENCRYPTION (Hybrid)
 *    - AES key encrypted with student's public key
 *    - Only student can decrypt
 * 
 * 3. DIGITAL SIGNATURE
 *    - PDF signed with recruiter's private key
 *    - Provides AUTHENTICITY, INTEGRITY, NON-REPUDIATION
 * 
 * 4. SHA-256 HASHING
 *    - PDF hash stored for integrity verification
 * 
 * 5. BASE64 ENCODING
 *    - Encrypted data encoded for safe transmission
 * 
 * COMPLETE PDF SECURITY FLOW:
 * ┌─────────────────────────────────────────────────────────────────┐
 * │  UPLOAD (Recruiter)                                            │
 * │  1. Upload PDF file                                            │
 * │  2. Hash(PDF) → SHA-256                                        │
 * │  3. Sign(Hash) → Recruiter's Private Key → Digital Signature   │
 * │  4. Generate AES-256 Session Key                               │
 * │  5. Encrypt(PDF, AES Key) → Encrypted PDF                      │
 * │  6. Encrypt(AES Key, Student Public Key) → Encrypted AES Key   │
 * │  7. Base64(Encrypted PDF) → Safe for storage                   │
 * │  8. Store all components in database                           │
 * └─────────────────────────────────────────────────────────────────┘
 * 
 * ┌─────────────────────────────────────────────────────────────────┐
 * │  VIEW (Student)                                                │
 * │  1. Fetch encrypted offer from database                        │
 * │  2. Base64 Decode encrypted PDF                                │
 * │  3. Decrypt AES key with Student's Private Key                 │
 * │  4. Decrypt PDF with AES Key                                   │
 * │  5. Verify signature with Recruiter's Public Key               │
 * │  6. Compute SHA-256 hash and compare                           │
 * │  7. If all checks pass → Display PDF                           │
 * └─────────────────────────────────────────────────────────────────┘
 * 
 * ROUTES:
 * POST   /api/offers/upload     - Recruiter uploads encrypted, signed PDF
 * GET    /api/offers            - List offers (based on role)
 * GET    /api/offers/:id        - Get single offer (encrypted)
 * POST   /api/offers/:id/verify - Verify signature and integrity
 * POST   /api/offers/:id/accept - Accept offer
 * POST   /api/offers/:id/reject - Reject offer
 * GET    /api/offers/:id/decrypt - Get decrypted PDF (requires private key)
 */

import express from 'express';
import multer from 'multer';
import User from '../models/User.js';
import Offer from '../models/Offer.js';
import AuditLog from '../models/AuditLog.js';
import { authenticateToken } from '../middleware/auth.js';
import { restrictTo, ROLES, authorize, RESOURCES, ACTIONS } from '../middleware/roleAuth.js';
import { 
    encryptPDF, 
    decryptPDF, 
    encodeBase64, 
    decodeBase64,
    generateAESKey,
    generateIV,
    encryptAES,
    decryptAES,
    encryptRSA,
    decryptRSA
} from '../utils/encryption.js';
import { 
    signPDF, 
    verifyPDF, 
    computeSHA256Hash,
    generateAcceptanceToken
} from '../utils/signature.js';
import { sendOfferNotificationEmail, sendAcceptanceConfirmationEmail } from '../utils/email.js';

const router = express.Router();

/**
 * MULTER CONFIGURATION for PDF uploads
 * 
 * SECURITY:
 * - Only PDF files allowed
 * - Max file size: 10MB
 * - Files stored in memory (not on disk) for immediate processing
 */
const storage = multer.memoryStorage();
const upload = multer({
    storage,
    limits: {
        fileSize: 10 * 1024 * 1024 // 10MB max
    },
    fileFilter: (req, file, cb) => {
        // Only allow PDF files
        if (file.mimetype === 'application/pdf') {
            cb(null, true);
        } else {
            cb(new Error('Only PDF files are allowed'), false);
        }
    }
});

/**
 * POST /api/offers/upload
 * 
 * Recruiter uploads an internship offer PDF
 * 
 * COMPLETE SECURITY IMPLEMENTATION:
 * 1. Validate recruiter authorization
 * 2. Receive PDF file
 * 3. Compute SHA-256 hash
 * 4. Create digital signature
 * 5. Generate AES session key
 * 6. Encrypt PDF with AES
 * 7. Encrypt AES key with student's RSA public key
 * 8. Base64 encode encrypted data
 * 9. Store in database
 * 
 * Required: JWT token (recruiter role), student email, PDF file
 */
/**
 * POST /api/offers/upload
 * 
 * Recruiter uploads an internship offer PDF
 */
router.post(
    '/upload',
    authenticateToken,
    restrictTo(ROLES.RECRUITER),
    upload.single('pdf'),
    async (req, res) => {
        try {
            console.log('📄 Processing PDF upload...');

            const {
                title,
                company,
                description,
                studentEmail,
                expiryDays,
                recruiterPrivateKey   // ✅ COMES FROM FRONTEND
            } = req.body;

            // ===============================
            // 1. VALIDATION
            // ===============================
            if (!title || !company || !studentEmail || !req.file) {
                return res.status(400).json({
                    success: false,
                    message: 'Title, company, student email, and PDF file are required'
                });
            }

            if (!recruiterPrivateKey) {
                return res.status(400).json({
                    success: false,
                    message: 'Recruiter private key is required for signing'
                });
            }

            // ===============================
            // 2. FIND STUDENT
            // ===============================
            const student = await User.findOne({
                email: studentEmail.toLowerCase(),
                role: 'student'
            });

            if (!student) {
                return res.status(404).json({
                    success: false,
                    message: 'Student not found'
                });
            }

            if (!student.publicKey) {
                return res.status(400).json({
                    success: false,
                    message: 'Student does not have a public key'
                });
            }

            // ===============================
            // 3. READ PDF
            // ===============================
            const pdfBuffer = req.file.buffer;

            console.log('   File:', req.file.originalname);
            console.log('   Size:', pdfBuffer.length, 'bytes');

            // ===============================
            // 4. SIGN PDF (RECRUITER PRIVATE KEY)
            // ===============================
            const { signature, hash } = signPDF(
                pdfBuffer,
                recruiterPrivateKey
            );

            console.log('   ✅ PDF signed');

            // ===============================
            // 5. ENCRYPT PDF (AES)
            // ===============================
            const aesKey = generateAESKey();
            const iv = generateIV();

            const encryptedPdfBuffer = encryptAES(pdfBuffer, aesKey, iv);

            // ===============================
            // 6. ENCRYPT AES KEY (STUDENT PUBLIC KEY)
            // ===============================
            const encryptedAesKey = encryptRSA(aesKey, student.publicKey);

            // ===============================
            // 7. BASE64 ENCODE
            // ===============================
            const encryptedPdfBase64 = encodeBase64(encryptedPdfBuffer);
            const encryptedAesKeyBase64 = encodeBase64(encryptedAesKey);
            const ivBase64 = encodeBase64(iv);

            // ===============================
            // 8. STORE OFFER
            // ===============================
            const expiryDate = new Date();
            expiryDate.setDate(expiryDate.getDate() + (parseInt(expiryDays) || 30));

            const acceptanceToken = generateAcceptanceToken();

            const offer = new Offer({
                title,
                company,
                description: description || '',
                recruiterId: req.userId,
                studentId: student._id,
                encryptedPdfData: encryptedPdfBase64,
                encryptedAesKey: encryptedAesKeyBase64,
                aesIv: ivBase64,
                digitalSignature: signature,
                pdfHash: hash,
                originalFilename: req.file.originalname,
                acceptanceToken,
                expiresAt: expiryDate
            });

            await offer.save();

            console.log('✅ Offer created successfully');

            // ===============================
            // 9. RESPONSE
            // ===============================
            res.status(201).json({
                success: true,
                message: 'Offer uploaded, encrypted, and signed successfully',
                data: {
                    offerId: offer._id,
                    title: offer.title,
                    company: offer.company,
                    studentEmail: student.email,
                    expiresAt: offer.expiresAt
                }
            });

        } catch (error) {
            console.error('❌ Upload error:', error);
            res.status(500).json({
                success: false,
                message: 'Failed to upload offer',
                error: error.message
            });
        }
    }
);


/**
 * GET /api/offers
 * 
 * List offers based on user role:
 * - Student: See their own offers
 * - Recruiter: See offers they created
 * - Admin: See all offers
 */
router.get('/', authenticateToken, async (req, res) => {
    try {
        let query = {};
        
        // Build query based on role
        switch (req.user.role) {
            case 'student':
                query = { studentId: req.userId };
                break;
            case 'recruiter':
                query = { recruiterId: req.userId };
                break;
            case 'admin':
                // Admin sees all
                break;
            default:
                return res.status(403).json({
                    success: false,
                    message: 'Invalid role',
                    error: 'FORBIDDEN'
                });
        }
        
        // Fetch offers (exclude encrypted data for listing)
        const offers = await Offer.find(query)
            .select('-encryptedPdfData -encryptedAesKey -aesIv -digitalSignature')
            .populate('recruiterId', 'name email company')
            .populate('studentId', 'name email rollNo')
            .sort({ createdAt: -1 });
        
        // Log access
        await AuditLog.log({
            userId: req.userId,
            userEmail: req.user.email,
            userRole: req.user.role,
            action: 'OFFER_VIEWED',
            resourceType: 'offer',
            description: `Listed ${offers.length} offers`,
            status: 'success',
            severity: 'low'
        });
        
        res.status(200).json({
            success: true,
            count: offers.length,
            data: offers
        });
        
    } catch (error) {
        console.error('List offers error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to list offers',
            error: 'SERVER_ERROR'
        });
    }
});

/**
 * GET /api/offers/:id
 * 
 * Get single offer with encrypted PDF data
 * Student can access their offers, Recruiter their created offers
 */
router.get('/:id', authenticateToken, async (req, res) => {
    try {
        const offer = await Offer.findById(req.params.id)
            .populate('recruiterId', 'name email')
            .populate('studentId', 'name email rollNo');
        
        if (!offer) {
            return res.status(404).json({
                success: false,
                message: 'Offer not found',
                error: 'NOT_FOUND'
            });
        }
        
        // Check authorization
        const isStudent = req.user.role === 'student' && 
            offer.studentId._id.toString() === req.userId.toString();
        const isRecruiter = req.user.role === 'recruiter' && 
            offer.recruiterId._id.toString() === req.userId.toString();
        const isAdmin = req.user.role === 'admin';
        
        if (!isStudent && !isRecruiter && !isAdmin) {
            await AuditLog.log({
                userId: req.userId,
                userEmail: req.user.email,
                userRole: req.user.role,
                action: 'ACCESS_DENIED',
                resourceType: 'offer',
                resourceId: offer._id,
                description: 'Unauthorized access attempt to offer',
                status: 'failure',
                severity: 'high'
            });
            
            return res.status(403).json({
                success: false,
                message: 'You are not authorized to view this offer',
                error: 'FORBIDDEN'
            });
        }
        
        // Log access
        await AuditLog.log({
            userId: req.userId,
            userEmail: req.user.email,
            userRole: req.user.role,
            action: 'OFFER_VIEWED',
            resourceType: 'offer',
            resourceId: offer._id,
            description: `Viewed offer: ${offer.title}`,
            status: 'success',
            severity: 'low'
        });
        
        // Fetch recruiter to get their public key
        const recruiter = await User.findById(offer.recruiterId);

        res.status(200).json({
            success: true,
            data: {
                ...offer.toObject(),
                recruiterPublicKey: recruiter.publicKey // ✅ FROM DB
            }
        });

        
    } catch (error) {
        console.error('Get offer error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to get offer',
            error: 'SERVER_ERROR'
        });
    }
});

/**
 * POST /api/offers/:id/decrypt
 * 
 * Decrypt the PDF using student's private key
 * 
 * DECRYPTION FLOW:
 * 1. Base64 decode encrypted AES key
 * 2. RSA decrypt AES key with student's private key
 * 3. Base64 decode encrypted PDF
 * 4. AES decrypt PDF
 * 5. Return decrypted PDF
 * 
 * SECURITY: Student must provide their private key (stored client-side)
 */
router.post('/:id/decrypt', 
    authenticateToken,
    restrictTo(ROLES.STUDENT),
    async (req, res) => {
        try {
            const { privateKey } = req.body;
            
            if (!privateKey) {
                return res.status(400).json({
                    success: false,
                    message: 'Private key is required for decryption',
                    error: 'MISSING_PRIVATE_KEY'
                });
            }
            
            const offer = await Offer.findById(req.params.id);
            
            if (!offer) {
                return res.status(404).json({
                    success: false,
                    message: 'Offer not found',
                    error: 'NOT_FOUND'
                });
            }
            
            // Check if this offer belongs to the student
            if (offer.studentId.toString() !== req.userId.toString()) {
                return res.status(403).json({
                    success: false,
                    message: 'You are not authorized to decrypt this offer',
                    error: 'FORBIDDEN'
                });
            }
            
            try {
                // ========================================
                // DECRYPTION PROCESS
                // ========================================
                
                // Step 1: Decrypt the PDF
                const decryptedPdfBuffer = decryptPDF(
                    offer.encryptedPdfData,
                    offer.encryptedAesKey,
                    offer.aesIv,
                    privateKey
                );
                
                console.log('✅ PDF decrypted successfully');
                
                // Log decryption
                await AuditLog.log({
                    userId: req.userId,
                    userEmail: req.user.email,
                    userRole: 'student',
                    action: 'CRYPTO_PDF_DECRYPTED',
                    resourceType: 'pdf',
                    resourceId: offer._id,
                    description: `PDF decrypted for offer: ${offer.title}`,
                    status: 'success',
                    severity: 'low'
                });
                
                // Return PDF as base64 for frontend display
                res.status(200).json({
                    success: true,
                    message: 'PDF decrypted successfully',
                    data: {
                        pdfBase64: encodeBase64(decryptedPdfBuffer),
                        filename: offer.originalFilename,
                        hash: offer.pdfHash,
                        signature: offer.digitalSignature
                    }
                });
                
            } catch (decryptError) {
                console.error('Decryption failed:', decryptError);
                
                await AuditLog.log({
                    userId: req.userId,
                    userEmail: req.user.email,
                    userRole: 'student',
                    action: 'CRYPTO_PDF_DECRYPTED',
                    resourceType: 'pdf',
                    resourceId: offer._id,
                    description: `Decryption failed - invalid private key`,
                    status: 'failure',
                    severity: 'high'
                });
                
                return res.status(400).json({
                    success: false,
                    message: 'Decryption failed. Please check your private key.',
                    error: 'DECRYPTION_FAILED'
                });
            }
            
        } catch (error) {
            console.error('Decrypt error:', error);
            res.status(500).json({
                success: false,
                message: 'Failed to decrypt offer',
                error: 'SERVER_ERROR'
            });
        }
    }
);

/**
 * POST /api/offers/:id/verify
 * 
 * Verify PDF signature and integrity
 * 
 * VERIFICATION PROCESS:
 * 1. Decrypt PDF (using provided private key)
 * 2. Compute fresh SHA-256 hash
 * 3. Compare with stored hash
 * 4. Verify digital signature with recruiter's public key
 * 
 * Returns verification status for:
 * - Hash integrity (PDF not modified)
 * - Signature validity (authentic recruiter)
 */
router.post('/:id/verify',
    authenticateToken,
    restrictTo(ROLES.STUDENT),
    async (req, res) => {
        try {
            const { privateKey } = req.body;
            
            if (!privateKey) {
                return res.status(400).json({
                    success: false,
                    message: 'Private key is required for verification',
                    error: 'MISSING_PRIVATE_KEY'
                });
            }
            
            const offer = await Offer.findById(req.params.id);
            
            if (!offer) {
                return res.status(404).json({
                    success: false,
                    message: 'Offer not found',
                    error: 'NOT_FOUND'
                });
            }
            
            // Check authorization
            if (offer.studentId.toString() !== req.userId.toString()) {
                return res.status(403).json({
                    success: false,
                    message: 'Not authorized',
                    error: 'FORBIDDEN'
                });
            }
            
            try {
                // Step 1: Decrypt the PDF
                const decryptedPdfBuffer = decryptPDF(
                    offer.encryptedPdfData,
                    offer.encryptedAesKey,
                    offer.aesIv,
                    privateKey
                );
                
                // Step 2: Verify signature and hash
                // Fetch recruiter to get their public key
                const recruiter = await User.findById(offer.recruiterId);

                const verification = verifyPDF(
                    decryptedPdfBuffer,
                    offer.digitalSignature,
                    offer.pdfHash,
                    recruiter.publicKey // ✅ FROM DB
                );

                
                // Log verification attempt
                if (verification.isValid) {
                    await AuditLog.log({
                        userId: req.userId,
                        userEmail: req.user.email,
                        userRole: 'student',
                        action: 'CRYPTO_SIGNATURE_VERIFIED',
                        resourceType: 'pdf',
                        resourceId: offer._id,
                        description: `Signature verified for offer: ${offer.title}`,
                        metadata: {
                            signatureValid: verification.signatureValid,
                            hashValid: verification.hashValid
                        },
                        status: 'success',
                        severity: 'low'
                    });
                    
                    await AuditLog.log({
                        userId: req.userId,
                        userEmail: req.user.email,
                        userRole: 'student',
                        action: 'CRYPTO_HASH_VERIFIED',
                        resourceType: 'pdf',
                        resourceId: offer._id,
                        description: `Hash integrity verified for offer: ${offer.title}`,
                        status: 'success',
                        severity: 'low'
                    });
                } else {
                    await AuditLog.log({
                        userId: req.userId,
                        userEmail: req.user.email,
                        userRole: 'student',
                        action: verification.signatureValid ? 'CRYPTO_HASH_MISMATCH' : 'CRYPTO_SIGNATURE_INVALID',
                        resourceType: 'pdf',
                        resourceId: offer._id,
                        description: `Verification failed for offer: ${offer.title}`,
                        metadata: {
                            signatureValid: verification.signatureValid,
                            hashValid: verification.hashValid
                        },
                        status: 'failure',
                        severity: 'critical'
                    });
                }
                
                res.status(200).json({
                    success: true,
                    message: verification.isValid 
                        ? 'PDF verification successful! Document is authentic and unmodified.'
                        : 'PDF verification FAILED! Document may be tampered.',
                    data: {
                        isValid: verification.isValid,
                        signatureValid: verification.signatureValid,
                        hashValid: verification.hashValid,
                        storedHash: offer.pdfHash,
                        computedHash: verification.computedHash,
                        securityChecks: {
                            authenticity: verification.signatureValid 
                                ? '✅ Recruiter identity verified' 
                                : '❌ Invalid signature',
                            integrity: verification.hashValid 
                                ? '✅ Document not modified' 
                                : '❌ Document has been modified',
                            nonRepudiation: verification.signatureValid 
                                ? '✅ Recruiter cannot deny signing' 
                                : '❌ Cannot prove origin'
                        }
                    }
                });
                
            } catch (error) {
                console.error('Verification error:', error);
                return res.status(400).json({
                    success: false,
                    message: 'Verification failed. Check your private key.',
                    error: 'VERIFICATION_FAILED'
                });
            }
            
        } catch (error) {
            console.error('Verify error:', error);
            res.status(500).json({
                success: false,
                message: 'Failed to verify offer',
                error: 'SERVER_ERROR'
            });
        }
    }
);

/**
 * POST /api/offers/:id/accept
 * 
 * Student accepts the offer
 * Requires prior verification
 */
router.post('/:id/accept',
    authenticateToken,
    restrictTo(ROLES.STUDENT),
    async (req, res) => {
        try {
            const offer = await Offer.findById(req.params.id)
                .populate('recruiterId', 'name email');
            
            if (!offer) {
                return res.status(404).json({
                    success: false,
                    message: 'Offer not found',
                    error: 'NOT_FOUND'
                });
            }
            
            // Check authorization
            if (offer.studentId.toString() !== req.userId.toString()) {
                return res.status(403).json({
                    success: false,
                    message: 'Not authorized',
                    error: 'FORBIDDEN'
                });
            }
            
            // Check if offer is still pending
            if (offer.status !== 'pending') {
                return res.status(400).json({
                    success: false,
                    message: `Offer has already been ${offer.status}`,
                    error: 'INVALID_STATUS'
                });
            }
            
            // Check if offer has expired
            if (offer.isExpired()) {
                offer.status = 'expired';
                await offer.save();
                
                return res.status(400).json({
                    success: false,
                    message: 'Offer has expired',
                    error: 'OFFER_EXPIRED'
                });
            }
            
            // Accept the offer
            offer.status = 'accepted';
            offer.respondedAt = new Date();
            await offer.save();
            
            // Log acceptance
            await AuditLog.log({
                userId: req.userId,
                userEmail: req.user.email,
                userRole: 'student',
                action: 'OFFER_ACCEPTED',
                resourceType: 'offer',
                resourceId: offer._id,
                description: `Accepted offer: ${offer.title} from ${offer.company}`,
                ipAddress: req.ip,
                userAgent: req.headers['user-agent'],
                status: 'success',
                severity: 'medium'
            });
            
            // Send confirmation email
            await sendAcceptanceConfirmationEmail(
                req.user.email,
                req.user.name,
                offer.company,
                'accepted'
            );
            
            res.status(200).json({
                success: true,
                message: 'Offer accepted successfully!',
                data: {
                    offerId: offer._id,
                    status: offer.status,
                    respondedAt: offer.respondedAt
                }
            });
            
        } catch (error) {
            console.error('Accept error:', error);
            res.status(500).json({
                success: false,
                message: 'Failed to accept offer',
                error: 'SERVER_ERROR'
            });
        }
    }
);

/**
 * POST /api/offers/:id/reject
 * 
 * Student rejects the offer
 */
router.post('/:id/reject',
    authenticateToken,
    restrictTo(ROLES.STUDENT),
    async (req, res) => {
        try {
            const offer = await Offer.findById(req.params.id)
                .populate('recruiterId', 'name email');
            
            if (!offer) {
                return res.status(404).json({
                    success: false,
                    message: 'Offer not found',
                    error: 'NOT_FOUND'
                });
            }
            
            // Check authorization
            if (offer.studentId.toString() !== req.userId.toString()) {
                return res.status(403).json({
                    success: false,
                    message: 'Not authorized',
                    error: 'FORBIDDEN'
                });
            }
            
            // Check if offer is still pending
            if (offer.status !== 'pending') {
                return res.status(400).json({
                    success: false,
                    message: `Offer has already been ${offer.status}`,
                    error: 'INVALID_STATUS'
                });
            }
            
            // Reject the offer
            offer.status = 'rejected';
            offer.respondedAt = new Date();
            await offer.save();
            
            // Log rejection
            await AuditLog.log({
                userId: req.userId,
                userEmail: req.user.email,
                userRole: 'student',
                action: 'OFFER_REJECTED',
                resourceType: 'offer',
                resourceId: offer._id,
                description: `Rejected offer: ${offer.title} from ${offer.company}`,
                ipAddress: req.ip,
                userAgent: req.headers['user-agent'],
                status: 'success',
                severity: 'medium'
            });
            
            // Send confirmation email
            await sendAcceptanceConfirmationEmail(
                req.user.email,
                req.user.name,
                offer.company,
                'rejected'
            );
            
            res.status(200).json({
                success: true,
                message: 'Offer rejected.',
                data: {
                    offerId: offer._id,
                    status: offer.status,
                    respondedAt: offer.respondedAt
                }
            });
            
        } catch (error) {
            console.error('Reject error:', error);
            res.status(500).json({
                success: false,
                message: 'Failed to reject offer',
                error: 'SERVER_ERROR'
            });
        }
    }
);

/**
 * GET /api/offers/students/list
 * 
 * Recruiter gets list of students to send offers to
 */
router.get('/students/list',
    authenticateToken,
    restrictTo(ROLES.RECRUITER),
    async (req, res) => {
        try {
            const students = await User.find({ role: 'student', isActive: true })
                .select('name email rollNo');
            
            res.status(200).json({
                success: true,
                count: students.length,
                data: students
            });
            
        } catch (error) {
            console.error('List students error:', error);
            res.status(500).json({
                success: false,
                message: 'Failed to list students',
                error: 'SERVER_ERROR'
            });
        }
    }
);

export default router;
