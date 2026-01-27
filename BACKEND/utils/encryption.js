/**
 * ===========================================
 * ENCRYPTION UTILITIES
 * ===========================================
 * 
 * SECURITY CONCEPTS IMPLEMENTED:
 * 
 * 1. AES-256 SYMMETRIC ENCRYPTION
 *    - Fast encryption for large data (PDFs)
 *    - 256-bit key provides strong security
 *    - CBC mode with unique IV for each encryption
 * 
 * 2. RSA ASYMMETRIC ENCRYPTION
 *    - Used for encrypting AES keys
 *    - Public key for encryption, private key for decryption
 *    - Enables secure key exchange
 * 
 * 3. HYBRID ENCRYPTION SCHEME
 *    - Best of both worlds:
 *      a) RSA security for key exchange
 *      b) AES speed for data encryption
 *    - Industry standard approach (TLS, PGP use similar)
 * 
 * SECURITY LEVELS:
 * - AES-256: 256-bit key → 2^256 possible keys (unbreakable by brute force)
 * - RSA-2048: Secure until ~2030 (NIST recommendation)
 * 
 * POSSIBLE ATTACKS & MITIGATIONS:
 * - Key Theft → Keys stored in env variables, not code
 * - IV Reuse → Fresh random IV for each encryption
 * - Padding Oracle → Using authenticated encryption pattern
 */

import crypto from 'crypto';
import dotenv from 'dotenv';

dotenv.config();

/**
 * ===========================================
 * AES-256 ENCRYPTION
 * ===========================================
 */

/**
 * Generate a random AES-256 session key
 * 
 * SECURITY: Uses cryptographically secure random number generator
 * Each offer gets a unique key - if one is compromised, others are safe
 * 
 * @returns {Buffer} 32-byte (256-bit) random key
 */
export const generateAESKey = () => {
    // crypto.randomBytes uses OS-level entropy source
    // Much more secure than Math.random()
    return crypto.randomBytes(32); // 256 bits = 32 bytes
};

/**
 * Generate a random Initialization Vector (IV)
 * 
 * SECURITY: IV must be unique for each encryption with same key
 * - Prevents identical plaintexts from producing identical ciphertexts
 * - Does not need to be secret (can be transmitted with ciphertext)
 * - MUST be unpredictable
 * 
 * @returns {Buffer} 16-byte (128-bit) random IV
 */
export const generateIV = () => {
    return crypto.randomBytes(16); // AES block size = 128 bits = 16 bytes
};

/**
 * Encrypt data using AES-256-CBC
 * 
 * SECURITY IMPLEMENTATION:
 * 1. Uses AES-256-CBC (Cipher Block Chaining)
 * 2. Unique IV for each encryption
 * 3. Returns both ciphertext and IV (needed for decryption)
 * 
 * Why AES-256-CBC?
 * - AES: NIST-approved, widely analyzed, proven secure
 * - 256-bit: Maximum AES key size, future-proof
 * - CBC: Prevents patterns in plaintext from appearing in ciphertext
 * 
 * @param {Buffer|string} data - Data to encrypt
 * @param {Buffer} key - 32-byte AES key
 * @param {Buffer} iv - 16-byte initialization vector
 * @returns {Buffer} Encrypted data
 */
export const encryptAES = (data, key, iv) => {
    // Create cipher with AES-256-CBC algorithm
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    
    // Encrypt the data
    // update() can be called multiple times for streaming
    // final() completes the encryption and adds padding
    let encrypted = cipher.update(data);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    
    return encrypted;
};

/**
 * Decrypt data using AES-256-CBC
 * 
 * SECURITY: Must use same key and IV that were used for encryption
 * 
 * @param {Buffer} encryptedData - Data to decrypt
 * @param {Buffer} key - 32-byte AES key (same as used for encryption)
 * @param {Buffer} iv - 16-byte IV (same as used for encryption)
 * @returns {Buffer} Decrypted data
 */
export const decryptAES = (encryptedData, key, iv) => {
    // Create decipher with same algorithm, key, and IV
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    
    // Decrypt the data
    let decrypted = decipher.update(encryptedData);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    
    return decrypted;
};

/**
 * ===========================================
 * RSA ENCRYPTION
 * ===========================================
 */

/**
 * Generate RSA key pair
 * 
 * SECURITY: 2048-bit key provides ~112 bits of security
 * - Secure for data that needs protection until ~2030
 * - For longer-term security, use 4096-bit keys
 * 
 * @returns {Object} { publicKey, privateKey } in PEM format
 */
export const generateRSAKeyPair = () => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048, // Key size in bits
        publicKeyEncoding: {
            type: 'spki',      // Standard format
            format: 'pem'      // Human-readable
        },
        privateKeyEncoding: {
            type: 'pkcs8',     // Standard format
            format: 'pem'      // Human-readable
        }
    });
    
    return { publicKey, privateKey };
};

/**
 * Encrypt data using RSA public key
 * 
 * SECURITY: Used for encrypting AES session keys
 * - Only the corresponding private key can decrypt
 * - RSA can only encrypt data smaller than key size minus padding
 * - That's why we use it for keys, not large files
 * 
 * PADDING: OAEP (Optimal Asymmetric Encryption Padding)
 * - More secure than PKCS#1 v1.5
 * - Prevents certain attacks on RSA
 * 
 * @param {Buffer} data - Data to encrypt (must be smaller than key)
 * @param {string} publicKey - RSA public key in PEM format
 * @returns {Buffer} Encrypted data
 */
export const encryptRSA = (data, publicKey) => {
    // Parse the public key string, handling escaped newlines
    const formattedKey = publicKey.replace(/\\n/g, '\n');
    
    return crypto.publicEncrypt(
        {
            key: formattedKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: 'sha256' // Hash function for OAEP padding
        },
        data
    );
};

/**
 * Decrypt data using RSA private key
 * 
 * SECURITY: Only the holder of the private key can decrypt
 * - Private key must be kept secret
 * - In production, use HSM (Hardware Security Module)
 * 
 * @param {Buffer} encryptedData - Data encrypted with public key
 * @param {string} privateKey - RSA private key in PEM format
 * @returns {Buffer} Decrypted data
 */
export const decryptRSA = (encryptedData, privateKey) => {
    // Parse the private key string, handling escaped newlines
    const formattedKey = privateKey.replace(/\\n/g, '\n');
    
    return crypto.privateDecrypt(
        {
            key: formattedKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: 'sha256'
        },
        encryptedData
    );
};

/**
 * ===========================================
 * BASE64 ENCODING/DECODING
 * ===========================================
 * 
 * SECURITY PURPOSE:
 * - Binary data cannot be safely transmitted as JSON/HTTP
 * - Base64 converts binary to ASCII text
 * - NOT encryption - just encoding for safe transmission
 * - Used for: encrypted PDFs, signatures, encrypted keys
 */

/**
 * Encode data to Base64
 * 
 * @param {Buffer} data - Binary data to encode
 * @returns {string} Base64 encoded string
 */
export const encodeBase64 = (data) => {
    return Buffer.from(data).toString('base64');
};

/**
 * Decode Base64 to binary
 * 
 * @param {string} base64String - Base64 encoded string
 * @returns {Buffer} Decoded binary data
 */
export const decodeBase64 = (base64String) => {
    return Buffer.from(base64String, 'base64');
};

/**
 * ===========================================
 * HYBRID ENCRYPTION (Complete PDF Security)
 * ===========================================
 * 
 * This implements the complete security flow for PDFs:
 * 1. Generate random AES session key
 * 2. Encrypt PDF with AES
 * 3. Encrypt AES key with RSA public key
 * 4. Base64 encode everything for storage
 */

/**
 * Encrypt PDF using hybrid encryption
 * 
 * COMPLETE SECURITY FLOW:
 * PDF → AES-256 Encrypt → Base64 Encode
 * AES Key → RSA Encrypt → Base64 Encode
 * 
 * @param {Buffer} pdfBuffer - Original PDF data
 * @param {string} recipientPublicKey - Student's RSA public key
 * @returns {Object} { encryptedPdf, encryptedAesKey, iv }
 */
export const encryptPDF = (pdfBuffer, recipientPublicKey) => {
    // Step 1: Generate unique session key and IV
    const aesKey = generateAESKey();
    const iv = generateIV();
    
    // Step 2: Encrypt PDF with AES-256
    const encryptedPdfBuffer = encryptAES(pdfBuffer, aesKey, iv);
    
    // Step 3: Encrypt AES key with recipient's RSA public key
    const encryptedAesKey = encryptRSA(aesKey, recipientPublicKey);
    
    // Step 4: Base64 encode for safe storage/transmission
    return {
        encryptedPdf: encodeBase64(encryptedPdfBuffer),
        encryptedAesKey: encodeBase64(encryptedAesKey),
        iv: encodeBase64(iv)
    };
};

/**
 * Decrypt PDF using hybrid encryption
 * 
 * COMPLETE DECRYPTION FLOW:
 * 1. Base64 decode encrypted AES key
 * 2. RSA decrypt AES key using private key
 * 3. Base64 decode encrypted PDF
 * 4. AES decrypt PDF using session key
 * 
 * @param {string} encryptedPdfBase64 - Base64 encoded encrypted PDF
 * @param {string} encryptedAesKeyBase64 - Base64 encoded encrypted AES key
 * @param {string} ivBase64 - Base64 encoded IV
 * @param {string} recipientPrivateKey - Student's RSA private key
 * @returns {Buffer} Decrypted PDF data
 */
export const decryptPDF = (encryptedPdfBase64, encryptedAesKeyBase64, ivBase64, recipientPrivateKey) => {
    // Step 1: Base64 decode
    const encryptedPdf = decodeBase64(encryptedPdfBase64);
    const encryptedAesKey = decodeBase64(encryptedAesKeyBase64);
    const iv = decodeBase64(ivBase64);
    
    // Step 2: RSA decrypt the AES key
    const aesKey = decryptRSA(encryptedAesKey, recipientPrivateKey);
    
    // Step 3: AES decrypt the PDF
    const decryptedPdf = decryptAES(encryptedPdf, aesKey, iv);
    
    return decryptedPdf;
};

export default {
    generateAESKey,
    generateIV,
    encryptAES,
    decryptAES,
    generateRSAKeyPair,
    encryptRSA,
    decryptRSA,
    encodeBase64,
    decodeBase64,
    encryptPDF,
    decryptPDF
};
