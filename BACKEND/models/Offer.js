/**
 * ===========================================
 * OFFER MODEL
 * ===========================================
 * 
 * This model represents an Internship Offer PDF with ALL security features:
 * 
 * SECURITY CONCEPTS IMPLEMENTED ON EACH OFFER:
 * 
 * 1. AES-256 ENCRYPTION
 *    - PDF content is encrypted using AES-256 symmetric encryption
 *    - Unique session key generated for each offer
 *    - Provides CONFIDENTIALITY - only authorized users can read
 * 
 * 2. RSA ENCRYPTION (Hybrid Encryption)
 *    - AES session key is encrypted with student's RSA public key
 *    - Only student's private key can decrypt the AES key
 *    - Ensures only intended recipient can access the offer
 * 
 * 3. DIGITAL SIGNATURE (RSA + SHA-256)
 *    - PDF hash is encrypted with recruiter's private key
 *    - Provides:
 *      a) AUTHENTICITY - proves recruiter created the offer
 *      b) INTEGRITY - detects any tampering with PDF
 *      c) NON-REPUDIATION - recruiter cannot deny creating offer
 * 
 * 4. SHA-256 HASHING
 *    - Hash of original PDF stored for integrity verification
 *    - Before acceptance, student verifies hash matches
 * 
 * 5. BASE64 ENCODING
 *    - Encrypted binary data is Base64 encoded
 *    - Safe transmission over HTTP/JSON
 *    - Prevents data corruption
 * 
 * PDF-CENTRIC SECURITY FLOW:
 * ┌─────────────────────────────────────────────────────────────────┐
 * │  UPLOAD (Recruiter)                                            │
 * │  1. Receive PDF file                                           │
 * │  2. Generate SHA-256 hash of PDF                               │
 * │  3. Sign hash with Recruiter's RSA private key (signature)     │
 * │  4. Generate random AES-256 session key                        │
 * │  5. Encrypt PDF with AES-256                                   │
 * │  6. Encrypt AES key with Student's RSA public key              │
 * │  7. Base64 encode encrypted PDF                                │
 * │  8. Store: encryptedPDF, encryptedAESKey, signature, hash      │
 * └─────────────────────────────────────────────────────────────────┘
 * 
 * ┌─────────────────────────────────────────────────────────────────┐
 * │  DOWNLOAD (Student)                                            │
 * │  1. Decrypt AES key using Student's RSA private key            │
 * │  2. Base64 decode encrypted PDF                                │
 * │  3. Decrypt PDF using AES-256                                  │
 * │  4. Verify signature using Recruiter's RSA public key          │
 * │  5. Compute SHA-256 hash of decrypted PDF                      │
 * │  6. Compare with stored hash (integrity check)                 │
 * │  7. If all checks pass, display PDF                            │
 * └─────────────────────────────────────────────────────────────────┘
 */

import mongoose from 'mongoose';

const offerSchema = new mongoose.Schema({
    // Title/Position of the internship
    title: {
        type: String,
        required: [true, 'Offer title is required'],
        trim: true
    },

    // Company name
    company: {
        type: String,
        required: [true, 'Company name is required'],
        trim: true
    },

    // Description of the internship
    description: {
        type: String,
        trim: true
    },

    // Reference to the recruiter who created this offer
    recruiterId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },

    // Reference to the student this offer is for
    studentId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },

    /**
     * ENCRYPTED PDF DATA
     * 
     * SECURITY: Original PDF is NEVER stored
     * Only the AES-256 encrypted version is stored
     * 
     * Format: Base64 encoded string of encrypted bytes
     * Encryption: AES-256-CBC
     */
    encryptedPdfData: {
        type: String,
        required: true
    },

    /**
     * AES INITIALIZATION VECTOR (IV)
     * 
     * SECURITY: Required for AES-CBC decryption
     * - 16 bytes (128 bits) for AES
     * - Unique per encryption operation
     * - Can be stored alongside ciphertext (not secret)
     */
    aesIv: {
        type: String,
        required: true
    },

    /**
     * ENCRYPTED AES SESSION KEY
     * 
     * SECURITY: Hybrid Encryption Implementation
     * 
     * The AES key is encrypted with the student's RSA public key
     * Only the student's RSA private key can decrypt this
     * 
     * Why hybrid encryption?
     * - RSA is slow for large data (PDF can be megabytes)
     * - AES is fast for large data
     * - RSA is good for encrypting small data (256-bit key)
     * 
     * Flow:
     * 1. Generate random AES-256 key
     * 2. Encrypt PDF with AES key (fast)
     * 3. Encrypt AES key with RSA public key (secure)
     */
    encryptedAesKey: {
        type: String,
        required: true
    },

    /**
     * DIGITAL SIGNATURE
     * 
     * SECURITY: Provides Authenticity, Integrity, Non-Repudiation
     * 
     * Creation (by Recruiter):
     * 1. Compute SHA-256 hash of original PDF
     * 2. Encrypt hash with Recruiter's RSA PRIVATE key
     * 3. This encrypted hash IS the signature
     * 
     * Verification (by Student):
     * 1. Decrypt signature using Recruiter's RSA PUBLIC key
     * 2. Get the hash from decryption
     * 3. Compute fresh hash of decrypted PDF
     * 4. Compare hashes - if match, signature is valid
     * 
     * What this proves:
     * - AUTHENTICITY: Only recruiter has the private key
     * - INTEGRITY: Any change to PDF = different hash = invalid signature
     * - NON-REPUDIATION: Recruiter cannot deny signing (only they have private key)
     */
    digitalSignature: {
        type: String,
        required: true
    },

    /**
     * PDF HASH (SHA-256)
     * 
     * SECURITY: Integrity verification
     * 
     * SHA-256 produces a 256-bit (64 hex character) hash
     * Properties:
     * - Deterministic: Same input = same hash
     * - One-way: Cannot reverse hash to get input
     * - Collision-resistant: Nearly impossible for two inputs to have same hash
     * - Avalanche effect: Small change in input = completely different hash
     * 
     * Used for quick integrity check before full signature verification
     */
    pdfHash: {
        type: String,
        required: true
    },

    // Original filename (for reference)
    originalFilename: {
        type: String,
        required: true
    },

    /**
     * OFFER STATUS
     * 
     * Possible values:
     * - pending: Offer sent, awaiting student response
     * - accepted: Student accepted the offer
     * - rejected: Student rejected the offer
     * - expired: Offer validity period has passed
     */
    status: {
        type: String,
        enum: ['pending', 'accepted', 'rejected', 'expired'],
        default: 'pending'
    },

    /**
     * ACCEPTANCE TOKEN
     * 
     * SECURITY: Base64 encoded token for acceptance verification
     * 
     * Used to:
     * - Verify acceptance request authenticity
     * - Prevent replay attacks (one-time use)
     * - Track acceptance in audit log
     */
    acceptanceToken: {
        type: String,   
        unique: true,
        sparse: true
    },

    // When the student responded to the offer
    respondedAt: {
        type: Date,
        default: null
    },

    // Offer expiry date
    expiresAt: {
        type: Date,
        required: true
    },

    // Timestamps for audit trail
    createdAt: {
        type: Date,
        default: Date.now
    },
    updatedAt: {
        type: Date,
        default: Date.now
    }
}, {
    timestamps: true
});

// Index for efficient queries
offerSchema.index({ studentId: 1, status: 1 });
offerSchema.index({ recruiterId: 1 });
offerSchema.index({ expiresAt: 1 });

/**
 * METHOD: Check if offer has expired
 */
offerSchema.methods.isExpired = function() {
    return new Date() > this.expiresAt;
};

/**
 * PRE-SAVE: Update status if expired
 */
offerSchema.pre('save', function(next) {
    if (this.isExpired() && this.status === 'pending') {
        this.status = 'expired';
    }
    this.updatedAt = new Date();
    next();
});

const Offer = mongoose.model('Offer', offerSchema);

export default Offer;
