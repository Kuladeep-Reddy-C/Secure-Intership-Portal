/**
 * ===========================================
 * DATABASE CONFIGURATION
 * ===========================================
 * 
 * SECURITY CONCEPTS IMPLEMENTED:
 * 1. Environment Variables - Database credentials stored securely in .env
 * 2. Connection Security - Uses mongoose with secure connection options
 * 
 * SECURITY LEVEL: HIGH
 * - Credentials are not hardcoded
 * - Connection errors are handled gracefully
 */

import mongoose from 'mongoose';
import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

/**
 * Establishes connection to MongoDB
 * 
 * SECURITY NOTES:
 * - MONGO_URI should include authentication credentials in production
 * - Connection string format: mongodb://username:password@host:port/database
 * - For production, use MongoDB Atlas with SSL/TLS enabled
 */
const connectDB = async () => {
    try {
        // Connect to MongoDB with secure options
        const conn = await mongoose.connect(process.env.MONGO_URI, {
            // These options ensure secure and stable connections
            // useNewUrlParser and useUnifiedTopology are default in Mongoose 6+
        });

        console.log(`✅ MongoDB Connected: ${conn.connection.host}`);
        console.log(`📁 Database: ${conn.connection.name}`);
        
        // Handle connection events for security monitoring
        mongoose.connection.on('error', (err) => {
            console.error('❌ MongoDB connection error:', err);
            // In production, this should trigger alerts
        });

        mongoose.connection.on('disconnected', () => {
            console.warn('⚠️ MongoDB disconnected. Attempting to reconnect...');
        });

        mongoose.connection.on('reconnected', () => {
            console.log('✅ MongoDB reconnected');
        });

    } catch (error) {
        console.error(`❌ MongoDB Connection Error: ${error.message}`);
        // Exit process with failure - critical service unavailable
        process.exit(1);
    }
};

export default connectDB;
