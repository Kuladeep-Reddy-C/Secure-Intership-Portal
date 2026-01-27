/**
 * ===========================================
 * EMAIL UTILITIES
 * ===========================================
 * 
 * SECURITY CONCEPTS IMPLEMENTED:
 * 
 * 1. MULTI-FACTOR AUTHENTICATION (MFA)
 *    - OTP sent via email as second authentication factor
 *    - Something you know (password) + Something you have (email access)
 *    - Significantly increases account security
 * 
 * 2. OUT-OF-BAND VERIFICATION
 *    - OTP sent through separate channel (email)
 *    - Attacker needs to compromise both channels
 *    - Mitigates credential theft attacks
 * 
 * SECURITY LEVEL: HIGH
 * - OTP is time-bound (expires in 5 minutes)
 * - OTP is one-time use
 * - OTP is hashed before storage (see User model)
 * 
 * EMAIL SECURITY BEST PRACTICES:
 * - Use TLS for SMTP connection
 * - Store credentials in environment variables
 * - Use app-specific passwords (not main account password)
 * - Rate limit OTP requests to prevent abuse
 */

import nodemailer from 'nodemailer';
import dotenv from 'dotenv';

dotenv.config();

/**
 * Create email transporter
 * 
 * SECURITY: Uses TLS for secure email transmission
 * Credentials stored in environment variables
 * 
 * For Gmail:
 * 1. Enable 2FA on your Google account
 * 2. Generate an App Password
 * 3. Use App Password in EMAIL_PASS
 */
const createTransporter = () => {
    return nodemailer.createTransport({
        host: process.env.EMAIL_HOST || 'smtp.gmail.com',
        port: parseInt(process.env.EMAIL_PORT) || 587,
        secure: false, // true for 465, false for other ports (uses STARTTLS)
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS
        },
        tls: {
            // Do not fail on invalid certs (for development)
            // Set to true in production
            rejectUnauthorized: process.env.NODE_ENV === 'production'
        }
    });
};

/**
 * Send OTP email to user
 * 
 * SECURITY IMPLEMENTATION:
 * - OTP is sent in plain text (necessary for user to read)
 * - Email should be accessed over secure connection
 * - OTP expires in 5 minutes to limit exposure window
 * 
 * @param {string} email - Recipient email address
 * @param {string} otp - One-time password (6 digits)
 * @param {string} name - User's name for personalization
 * @returns {Promise<Object>} Email sending result
 */
export const sendOTPEmail = async (email, otp, name = 'User') => {
    try {
        const transporter = createTransporter();
        
        // Email content
        const mailOptions = {
            from: `"Secure Internship Portal" <${process.env.EMAIL_FROM || process.env.EMAIL_USER}>`,
            to: email,
            subject: '🔐 Your OTP for Secure Internship Portal',
            html: `
                <!DOCTYPE html>
                <html>
                <head>
                    <style>
                        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
                        .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
                        .otp-box { background: white; border: 2px dashed #667eea; padding: 20px; text-align: center; margin: 20px 0; border-radius: 10px; }
                        .otp-code { font-size: 36px; font-weight: bold; letter-spacing: 8px; color: #667eea; }
                        .warning { background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 20px 0; }
                        .security-tips { background: #d4edda; border-left: 4px solid #28a745; padding: 15px; margin: 20px 0; }
                        .footer { text-align: center; color: #888; font-size: 12px; margin-top: 20px; }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header">
                            <h1>🔐 Secure Internship Portal</h1>
                            <p>Multi-Factor Authentication</p>
                        </div>
                        <div class="content">
                            <p>Hello <strong>${name}</strong>,</p>
                            <p>You are attempting to log in to the Secure Internship Portal. Please use the following One-Time Password (OTP) to complete your authentication:</p>
                            
                            <div class="otp-box">
                                <p style="margin: 0; color: #666;">Your OTP Code</p>
                                <p class="otp-code">${otp}</p>
                                <p style="margin: 0; color: #888; font-size: 14px;">Valid for 5 minutes</p>
                            </div>
                            
                            <div class="warning">
                                <strong>⚠️ Security Warning:</strong>
                                <ul style="margin: 10px 0;">
                                    <li>Never share this OTP with anyone</li>
                                    <li>Our team will never ask for your OTP</li>
                                    <li>This OTP expires in 5 minutes</li>
                                </ul>
                            </div>
                            
                            <div class="security-tips">
                                <strong>🛡️ Why MFA?</strong>
                                <p style="margin: 5px 0;">Multi-Factor Authentication adds an extra layer of security by requiring:</p>
                                <ul style="margin: 10px 0;">
                                    <li>Something you know (your password)</li>
                                    <li>Something you have (access to this email)</li>
                                </ul>
                            </div>
                            
                            <p>If you did not request this OTP, please ignore this email and ensure your account is secure.</p>
                        </div>
                        <div class="footer">
                            <p>This is an automated message from Secure Internship Portal</p>
                            <p>Foundations of Cyber Security Lab Project</p>
                        </div>
                    </div>
                </body>
                </html>
            `,
            text: `
                Secure Internship Portal - OTP Verification
                
                Hello ${name},
                
                Your One-Time Password (OTP) is: ${otp}
                
                This OTP is valid for 5 minutes.
                
                Security Warning:
                - Never share this OTP with anyone
                - Our team will never ask for your OTP
                
                If you did not request this OTP, please ignore this email.
            `
        };
        
        // Send email
        const info = await transporter.sendMail(mailOptions);
        
        console.log('📧 OTP Email sent:', info.messageId);
        
        return {
            success: true,
            messageId: info.messageId
        };
    } catch (error) {
        console.error('❌ Email sending error:', error);
        
        // In development, log the OTP to console as fallback
        if (process.env.NODE_ENV !== 'production') {
            console.log('==========================================');
            console.log('📧 EMAIL FALLBACK (Development Mode)');
            console.log(`To: ${email}`);
            console.log(`OTP: ${otp}`);
            console.log('==========================================');
        }
        
        return {
            success: false,
            error: error.message
        };
    }
};

/**
 * Send offer notification email
 * 
 * Notifies student when a new internship offer is received
 * 
 * @param {string} email - Student's email
 * @param {string} name - Student's name
 * @param {string} company - Company name
 * @param {string} position - Position/title
 */
export const sendOfferNotificationEmail = async (email, name, company, position) => {
    try {
        const transporter = createTransporter();
        
        const mailOptions = {
            from: `"Secure Internship Portal" <${process.env.EMAIL_FROM || process.env.EMAIL_USER}>`,
            to: email,
            subject: `🎉 New Internship Offer from ${company}!`,
            html: `
                <!DOCTYPE html>
                <html>
                <head>
                    <style>
                        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                        .header { background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
                        .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
                        .offer-box { background: white; border: 2px solid #11998e; padding: 20px; margin: 20px 0; border-radius: 10px; }
                        .security-note { background: #e3f2fd; border-left: 4px solid #2196f3; padding: 15px; margin: 20px 0; }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header">
                            <h1>🎉 Congratulations!</h1>
                            <p>You have received a new internship offer</p>
                        </div>
                        <div class="content">
                            <p>Hello <strong>${name}</strong>,</p>
                            <p>Great news! You have received a new internship offer:</p>
                            
                            <div class="offer-box">
                                <h3 style="color: #11998e; margin-top: 0;">${position}</h3>
                                <p><strong>Company:</strong> ${company}</p>
                                <p>Please log in to the Secure Internship Portal to view and respond to this offer.</p>
                            </div>
                            
                            <div class="security-note">
                                <strong>🔐 Security Features:</strong>
                                <ul style="margin: 10px 0;">
                                    <li>Your offer letter is AES-256 encrypted</li>
                                    <li>Digitally signed by the recruiter</li>
                                    <li>Hash verified for integrity</li>
                                </ul>
                            </div>
                        </div>
                    </div>
                </body>
                </html>
            `
        };
        
        await transporter.sendMail(mailOptions);
        return { success: true };
    } catch (error) {
        console.error('❌ Offer notification email error:', error);
        return { success: false, error: error.message };
    }
};

/**
 * Send acceptance confirmation email
 * 
 * Confirms to student that their offer response was recorded
 * 
 * @param {string} email - Student's email
 * @param {string} name - Student's name
 * @param {string} company - Company name
 * @param {string} status - 'accepted' or 'rejected'
 */
export const sendAcceptanceConfirmationEmail = async (email, name, company, status) => {
    try {
        const transporter = createTransporter();
        
        const isAccepted = status === 'accepted';
        
        const mailOptions = {
            from: `"Secure Internship Portal" <${process.env.EMAIL_FROM || process.env.EMAIL_USER}>`,
            to: email,
            subject: `Offer ${isAccepted ? 'Accepted' : 'Declined'} - ${company}`,
            html: `
                <!DOCTYPE html>
                <html>
                <head>
                    <style>
                        body { font-family: Arial, sans-serif; }
                        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                        .header { background: ${isAccepted ? 'linear-gradient(135deg, #11998e 0%, #38ef7d 100%)' : 'linear-gradient(135deg, #eb3349 0%, #f45c43 100%)'}; color: white; padding: 30px; text-align: center; border-radius: 10px; }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header">
                            <h1>${isAccepted ? '✅ Offer Accepted!' : '❌ Offer Declined'}</h1>
                        </div>
                        <div style="padding: 20px;">
                            <p>Hello ${name},</p>
                            <p>This confirms that you have <strong>${isAccepted ? 'accepted' : 'declined'}</strong> the internship offer from <strong>${company}</strong>.</p>
                            <p>This action has been recorded in our secure audit log.</p>
                        </div>
                    </div>
                </body>
                </html>
            `
        };
        
        await transporter.sendMail(mailOptions);
        return { success: true };
    } catch (error) {
        console.error('❌ Confirmation email error:', error);
        return { success: false, error: error.message };
    }
};

export default {
    sendOTPEmail,
    sendOfferNotificationEmail,
    sendAcceptanceConfirmationEmail
};
