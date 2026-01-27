// /**
//  * ===========================================
//  * USER MODEL
//  * ===========================================
//  * 
//  * SECURITY CONCEPTS IMPLEMENTED:
//  * 
//  * 1. PASSWORD HASHING (bcrypt with salt)
//  *    - Passwords are NEVER stored in plain text
//  *    - bcrypt automatically generates a unique salt for each password
//  *    - Salt rounds (12) make brute-force attacks computationally expensive
//  *    - MITIGATES: Password theft, rainbow table attacks
//  * 
//  * 2. ROLE-BASED ACCESS CONTROL (RBAC)
//  *    - Three roles: student, recruiter, admin
//  *    - Each role has specific permissions (Access Control Matrix)
//  *    - Enforced at middleware level
//  * 
//  * 3. OTP FOR MULTI-FACTOR AUTHENTICATION (MFA)
//  *    - OTP is hashed before storage (prevents OTP theft if DB compromised)
//  *    - Time-bound expiry prevents replay attacks
//  *    - SECURITY LEVEL: HIGH
//  * 
//  * 4. RSA KEY STORAGE
//  *    - Each user can have their own RSA public key
//  *    - Used for encrypting AES session keys (hybrid encryption)
//  * 
//  * POSSIBLE ATTACKS & MITIGATIONS:
//  * - Brute Force → bcrypt (slow hashing) + rate limiting
//  * - Password Theft → Salted hashing (unique salt per user)
//  * - OTP Replay → Time-bound expiry + hash storage
//  * - Privilege Escalation → Strict role validation
//  */

// import mongoose from 'mongoose';
// import bcrypt from 'bcrypt';
// import crypto from 'crypto';

// // Define the User schema
// const userSchema = new mongoose.Schema({
//     // Full name of the user
//     name: {
//         type: String,
//         required: [true, 'Name is required'],
//         trim: true,
//         minlength: [2, 'Name must be at least 2 characters'],
//         maxlength: [100, 'Name cannot exceed 100 characters']
//     },

//     // Email - unique identifier for authentication
//     email: {
//         type: String,
//         required: [true, 'Email is required'],
//         unique: true,
//         lowercase: true,
//         trim: true,
//         match: [/^\S+@\S+\.\S+$/, 'Please enter a valid email']
//     },

//     // Roll Number - alternative identifier for students
//     rollNo: {
//         type: String,
//         unique: true,
//         sparse: true, // Allows null values while maintaining uniqueness
//         trim: true
//     },

//     /**
//      * PASSWORD FIELD
//      * SECURITY: Never stored in plain text
//      * 
//      * The password goes through the following process:
//      * 1. User provides plain text password
//      * 2. bcrypt generates a random salt (12 rounds)
//      * 3. Salt + password → hashed together
//      * 4. Only the hash is stored in database
//      * 
//      * Verification:
//      * 1. User provides password
//      * 2. bcrypt extracts salt from stored hash
//      * 3. Hashes provided password with same salt
//      * 4. Compares hashes (timing-safe comparison)
//      */
//     password: {
//         type: String,
//         required: [true, 'Password is required'],
//         minlength: [8, 'Password must be at least 8 characters'],
//         select: false // Never include password in queries by default
//     },

//     /**
//      * ROLE FIELD - Access Control Matrix
//      * 
//      * ACCESS CONTROL MATRIX:
//      * ┌──────────┬─────────────┬───────────────┬────────────┬─────────────┐
//      * │ Role     │ View Offers │ Accept/Reject │ Upload PDF │ Audit Logs  │
//      * ├──────────┼─────────────┼───────────────┼────────────┼─────────────┤
//      * │ Student  │     ✓       │       ✓       │     ✗      │      ✗      │
//      * │ Recruiter│     ✓       │       ✗       │     ✓      │      ✗      │
//      * │ Admin    │     ✓       │       ✗       │     ✗      │      ✓      │
//      * └──────────┴─────────────┴───────────────┴────────────┴─────────────┘
//      */
//     role: {
//         type: String,
//         enum: ['student', 'recruiter', 'admin'],
//         default: 'student'
//     },

//     /**
//      * OTP FIELDS - Multi-Factor Authentication
//      * 
//      * SECURITY IMPLEMENTATION:
//      * - OTP is hashed using SHA-256 before storage
//      * - Even if database is compromised, OTP cannot be retrieved
//      * - Time-bound expiry (5 minutes default) prevents replay attacks
//      */
//     otp: {
//         type: String, // Stored as SHA-256 hash
//         select: false
//     },
//     otpExpiry: {
//         type: Date,
//         select: false
//     },
//     isOtpVerified: {
//         type: Boolean,
//         default: false
//     },

//     /**
//      * RSA PUBLIC KEY
//      * Used in hybrid encryption scheme:
//      * 1. Generate random AES-256 session key
//      * 2. Encrypt PDF with AES-256
//      * 3. Encrypt AES key with this RSA public key
//      * 4. Only this user's private key can decrypt
//      */
//     publicKey: {
//         type: String,
//         default: null
//     },

//     // Account status
//     isActive: {
//         type: Boolean,
//         default: true
//     },

//     // Login tracking for security monitoring
//     lastLogin: {
//         type: Date,
//         default: null
//     },
//     loginAttempts: {
//         type: Number,
//         default: 0
//     },
//     lockUntil: {
//         type: Date,
//         default: null
//     }
// }, {
//     timestamps: true // Adds createdAt and updatedAt automatically
// });

// /**
//  * PRE-SAVE MIDDLEWARE - Password Hashing
//  * 
//  * SECURITY: This runs BEFORE saving to database
//  * Ensures password is always hashed, never stored plain text
//  * 
//  * bcrypt.hash() process:
//  * 1. Generates random salt (12 rounds = 2^12 iterations)
//  * 2. Combines salt with password
//  * 3. Produces hash: $2b$12$[salt][hash]
//  * 
//  * Cost factor of 12 means:
//  * - ~250ms to hash on modern hardware
//  * - Makes brute-force attacks very slow
//  */
// userSchema.pre('save', async function (next) {
//     // Only hash if password is new or modified
//     if (!this.isModified('password')) {
//         return next();
//     }

//     try {
//         // SALT_ROUNDS = 12 (industry standard for security vs performance)
//         // Higher = more secure but slower
//         const SALT_ROUNDS = 12;

//         // Generate salt and hash in one step
//         // bcrypt.hash automatically generates a unique salt
//         this.password = await bcrypt.hash(this.password, SALT_ROUNDS);

//         next();
//     } catch (error) {
//         next(error);
//     }
// });

// /**
//  * METHOD: Compare Password
//  * 
//  * SECURITY: Uses timing-safe comparison
//  * - bcrypt.compare prevents timing attacks
//  * - Attacker cannot determine password length from response time
//  */
// userSchema.methods.comparePassword = async function (candidatePassword) {
//     // bcrypt.compare:
//     // 1. Extracts salt from stored hash
//     // 2. Hashes candidate password with same salt
//     // 3. Compares hashes using timing-safe comparison
//     return await bcrypt.compare(candidatePassword, this.password);
// };

// /**
//  * METHOD: Generate OTP
//  * 
//  * SECURITY IMPLEMENTATION:
//  * 1. Generate 6-digit random OTP using crypto (cryptographically secure)
//  * 2. Hash OTP using SHA-256 before storage
//  * 3. Set expiry time (5 minutes)
//  * 
//  * Why hash OTP?
//  * - If database is compromised, attacker sees only hash
//  * - Cannot use hash to authenticate (need original OTP)
//  * - SHA-256 is one-way, cannot reverse to get OTP
//  */
// userSchema.methods.generateOTP = function () {
//     // Generate cryptographically secure random 6-digit OTP
//     const otp = crypto.randomInt(100000, 1000000).toString();

//     // Hash OTP before storage using SHA-256
//     // SHA-256 produces 256-bit (64 hex character) hash
//     const hashedOtp = crypto.createHash('sha256').update(otp).digest('hex');
//     this.otp = hashedOtp;

//     // Set expiry (5 minutes from now)
//     const OTP_EXPIRY_MINUTES = parseInt(process.env.OTP_EXPIRY_MINUTES) || 5;
//     this.otpExpiry = new Date(Date.now() + OTP_EXPIRY_MINUTES * 60 * 1000);

//     console.log(`[DEBUG] OTP generated: ${otp} (Hash: ${hashedOtp.substring(0, 10)}...)`);
//     console.log(`[DEBUG] OTP Expiry: ${this.otpExpiry}`);

//     // Return plain OTP to send via email
//     // This is the only time plain OTP exists
//     return otp;
// };

// /**
//  * METHOD: Verify OTP
//  * 
//  * SECURITY:
//  * 1. Hash provided OTP with same algorithm
//  * 2. Compare with stored hash
//  * 3. Check expiry time
//  * 4. Clear OTP after verification (prevent reuse)
//  */
// userSchema.methods.verifyOTP = function (providedOTP) {
//     console.log(`[DEBUG] Verifying OTP. User ID: ${this._id}`);

//     // Ensure we have stored OTP and expiry
//     if (!this.otp || !this.otpExpiry) {
//         console.log('[DEBUG] No OTP or expiry found for user');
//         return false;
//     }

//     // Check if OTP has expired
//     const now = Date.now();
//     const expiry = new Date(this.otpExpiry).getTime();
//     if (now > expiry) {
//         console.log(`[DEBUG] OTP has expired. Now: ${now}, Expiry: ${expiry}`);
//         return false;
//     }

//     // Convert to string and trim whitespace
//     const otpString = String(providedOTP).trim();

//     // Hash provided OTP and compare with stored hash
//     const hashedProvidedOTP = crypto.createHash('sha256').update(otpString).digest('hex');

//     console.log(`[DEBUG] Provided OTP: ${otpString}`);
//     console.log(`[DEBUG] Hashes - Stored: ${this.otp}, Computed: ${hashedProvidedOTP}`);

//     const isValid = hashedProvidedOTP === this.otp;
//     console.log('OTP verification:', isValid ? 'SUCCESS' : 'FAILED');

//     return isValid;
// };

// /**
//  * METHOD: Clear OTP
//  * 
//  * SECURITY: Clear OTP after successful verification
//  * Prevents OTP reuse (replay attack mitigation)
//  */
// userSchema.methods.clearOTP = function () {
//     this.otp = undefined;
//     this.otpExpiry = undefined;
//     this.isOtpVerified = true;
// };

// /**
//  * METHOD: Check if account is locked
//  * 
//  * SECURITY: Account lockout after multiple failed attempts
//  * Mitigates brute-force attacks
//  */
// userSchema.methods.isLocked = function () {
//     return this.lockUntil && this.lockUntil > Date.now();
// };

// /**
//  * METHOD: Increment login attempts
//  * 
//  * SECURITY: Track failed login attempts
//  * Lock account after 5 failed attempts for 30 minutes
//  */
// userSchema.methods.incrementLoginAttempts = async function () {
//     const MAX_ATTEMPTS = 5;
//     const LOCK_TIME = 30 * 60 * 1000; // 30 minutes

//     // Reset if lock has expired
//     if (this.lockUntil && this.lockUntil < Date.now()) {
//         this.loginAttempts = 1;
//         this.lockUntil = undefined;
//     } else {
//         this.loginAttempts += 1;

//         // Lock account if max attempts reached
//         if (this.loginAttempts >= MAX_ATTEMPTS) {
//             this.lockUntil = new Date(Date.now() + LOCK_TIME);
//         }
//     }

//     await this.save();
// };

// /**
//  * METHOD: Reset login attempts
//  * Called after successful login
//  */
// userSchema.methods.resetLoginAttempts = async function () {
//     this.loginAttempts = 0;
//     this.lockUntil = undefined;
//     this.lastLogin = new Date();
//     await this.save();
// };

// // Create and export the model
// const User = mongoose.model('User', userSchema);

// export default User;


/**
 * ===========================================
 * USER MODEL (FINAL – FIXED)
 * ===========================================
 */

import mongoose from 'mongoose';
import bcrypt from 'bcrypt';
import crypto from 'crypto';

const userSchema = new mongoose.Schema({
    name: { type: String, required: true },

    email: {
        type: String,
        unique: true,
        lowercase: true,
        required: true
    },

    rollNo: {
        type: String,
        unique: true,
        sparse: true
    },

    password: {
        type: String,
        required: true,
        select: false
    },

    role: {
        type: String,
        enum: ['student', 'recruiter', 'admin'],
        default: 'student'
    },

    // ================= OTP =================
    otp: {
        type: String,
        select: false
    },
    otpExpiry: {
        type: Date,
        select: false
    },
    isOtpVerified: {
        type: Boolean,
        default: false
    },

    // ================= ACCOUNT STATUS =================
    isActive: {
        type: Boolean,
        default: true   // ✅ CRITICAL FIX
    },

    // ================= SECURITY =================
    publicKey: String,
    loginAttempts: { type: Number, default: 0 },
    lockUntil: { type: Date, default: null }

}, { timestamps: true });

/**
 * ===========================================
 * PASSWORD HASHING
 * ===========================================
 */
userSchema.pre('save', async function (next) {
    if (!this.isModified('password')) return next();
    this.password = await bcrypt.hash(this.password, 12);
    next();
});

userSchema.methods.comparePassword = function (password) {
    return bcrypt.compare(password, this.password);
};

/**
 * ===========================================
 * OTP GENERATION
 * ===========================================
 */
userSchema.methods.generateOTP = function () {
    const otp = crypto.randomInt(100000, 1000000).toString();

    this.otp = crypto.createHash('sha256').update(otp).digest('hex');
    this.otpExpiry = new Date(Date.now() + 5 * 60 * 1000);
    this.isOtpVerified = false;

    console.log('[OTP GENERATED]', otp);
    return otp;
};

/**
 * ===========================================
 * OTP VERIFICATION
 * ===========================================
 */
userSchema.methods.verifyOTP = function (providedOtp) {
    if (!this.otp || !this.otpExpiry) return false;
    if (Date.now() > this.otpExpiry) return false;

    const hashed = crypto
        .createHash('sha256')
        .update(String(providedOtp).trim())
        .digest('hex');

    return hashed === this.otp;
};

userSchema.methods.clearOTP = function () {
    this.otp = undefined;
    this.otpExpiry = undefined;
    this.isOtpVerified = true;
};

/**
 * ===========================================
 * RESET LOGIN ATTEMPTS (AFTER SUCCESSFUL MFA)
 * ===========================================
 */
userSchema.methods.resetLoginAttempts = async function () {
    this.loginAttempts = 0;
    this.lockUntil = null;
    this.lastLogin = new Date(); // optional but useful
    await this.save();
};


export default mongoose.model('User', userSchema);
