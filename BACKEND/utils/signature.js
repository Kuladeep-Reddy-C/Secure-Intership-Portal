/**
 * ===========================================
 * DIGITAL SIGNATURE UTILITIES (FINAL)
 * ===========================================
 */

import crypto from 'crypto';

/**
 * Compute SHA-256 hash
 */
export const computeSHA256Hash = (data) =>
    crypto.createHash('sha256').update(data).digest('hex');

/**
 * Sign PDF using recruiter PRIVATE KEY (PKCS8 PEM)
 */
export const signPDF = (pdfBuffer, recruiterPrivateKey) => {
    try {
        const formattedKey = recruiterPrivateKey.replace(/\\n/g, '\n');

        const signer = crypto.createSign('RSA-SHA256');
        signer.update(pdfBuffer);
        signer.end();

        const signature = signer.sign(
            {
                key: formattedKey,
                padding: crypto.constants.RSA_PKCS1_PADDING
            },
            'base64'
        );

        return {
            signature,
            hash: computeSHA256Hash(pdfBuffer)
        };
    } catch (err) {
        console.error('❌ SIGN PDF ERROR:', err.message);
        throw err;
    }
};

/**
 * Verify PDF signature using recruiter PUBLIC KEY
 */
export const verifyPDF = (pdfBuffer, signature, storedHash, recruiterPublicKey) => {
    try {
        const formattedKey = recruiterPublicKey.replace(/\\n/g, '\n');

        const verifier = crypto.createVerify('RSA-SHA256');
        verifier.update(pdfBuffer);
        verifier.end();

        const signatureValid = verifier.verify(formattedKey, signature, 'base64');
        const computedHash = computeSHA256Hash(pdfBuffer);
        const hashValid = computedHash === storedHash;

        return {
            isValid: signatureValid && hashValid,
            signatureValid,
            hashValid,
            computedHash
        };
    } catch (err) {
        console.error('❌ VERIFY PDF ERROR:', err.message);
        return {
            isValid: false,
            signatureValid: false,
            hashValid: false,
            computedHash: null
        };
    }
};

/**
 * Generate secure acceptance token
 */
export const generateAcceptanceToken = () =>
    crypto.randomBytes(32).toString('base64');
