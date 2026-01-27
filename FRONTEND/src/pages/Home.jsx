/**
 * ===========================================
 * HOME PAGE
 * ===========================================
 * 
 * Landing page explaining the security features
 */

import React from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

const Home = () => {
  const { user } = useAuth();

  const securityFeatures = [
    {
      icon: '🔐',
      title: 'Multi-Factor Authentication',
      description: 'Password + Email OTP for enhanced security',
      level: 'HIGH'
    },
    {
      icon: '🔒',
      title: 'AES-256 Encryption',
      description: 'Military-grade encryption for all offer PDFs',
      level: 'HIGH'
    },
    {
      icon: '🔑',
      title: 'RSA Hybrid Encryption',
      description: 'Secure key exchange using public-key cryptography',
      level: 'HIGH'
    },
    {
      icon: '✍️',
      title: 'Digital Signatures',
      description: 'Verify authenticity and prevent tampering',
      level: 'HIGH'
    },
    {
      icon: '#️⃣',
      title: 'SHA-256 Hashing',
      description: 'Integrity verification for all documents',
      level: 'HIGH'
    },
    {
      icon: '👤',
      title: 'Role-Based Access',
      description: 'Student, Recruiter, and Admin roles',
      level: 'HIGH'
    }
  ];

  return (
    <div className="min-h-screen bg-gradient-to-br from-primary-50 to-primary-100">
      {/* Hero Section */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pt-20 pb-16">
        <div className="text-center">
          <h1 className="text-4xl md:text-6xl font-bold text-gray-900 mb-6">
            <span className="text-primary-600">Secure</span> Internship Portal
          </h1>
          <p className="text-xl text-gray-600 max-w-3xl mx-auto mb-8">
            A comprehensive security-focused platform for managing internship offers.
            Implementing industry-standard cryptographic protocols to ensure
            confidentiality, integrity, and authenticity.
          </p>
          
          {/* CTA Buttons */}
          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            {user ? (
              <Link
                to={`/${user.role}`}
                className="btn-primary text-lg px-8 py-3"
              >
                Go to Dashboard
              </Link>
            ) : (
              <>
                <Link
                  to="/register"
                  className="btn-primary text-lg px-8 py-3"
                >
                  Get Started
                </Link>
                <Link
                  to="/login"
                  className="btn-secondary text-lg px-8 py-3"
                >
                  Login
                </Link>
              </>
            )}
          </div>
        </div>
      </div>

      {/* Security Features Section */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-16">
        <h2 className="text-3xl font-bold text-center text-gray-900 mb-4">
          Security Features
        </h2>
        <p className="text-gray-600 text-center mb-12 max-w-2xl mx-auto">
          Every internship offer PDF implements ALL security concepts together:
          Encrypted, Signed, Hashed, and Encoded.
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {securityFeatures.map((feature, index) => (
            <div key={index} className="card hover:shadow-lg transition-shadow">
              <div className="text-4xl mb-4">{feature.icon}</div>
              <h3 className="text-xl font-semibold text-gray-900 mb-2">
                {feature.title}
              </h3>
              <p className="text-gray-600 mb-3">{feature.description}</p>
              <span className="security-badge-high">
                Security Level: {feature.level}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* How It Works Section */}
      <div className="bg-white py-16">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <h2 className="text-3xl font-bold text-center text-gray-900 mb-12">
            How It Works
          </h2>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
            {/* Student Flow */}
            <div className="text-center">
              <div className="w-16 h-16 bg-blue-100 rounded-full flex items-center justify-center mx-auto mb-4">
                <span className="text-2xl">👨‍🎓</span>
              </div>
              <h3 className="text-xl font-semibold mb-2">Student</h3>
              <ul className="text-gray-600 text-left space-y-2">
                <li>✅ Register & Login with MFA</li>
                <li>✅ View encrypted offers</li>
                <li>✅ Verify digital signatures</li>
                <li>✅ Accept or reject offers</li>
              </ul>
            </div>

            {/* Recruiter Flow */}
            <div className="text-center">
              <div className="w-16 h-16 bg-green-100 rounded-full flex items-center justify-center mx-auto mb-4">
                <span className="text-2xl">👔</span>
              </div>
              <h3 className="text-xl font-semibold mb-2">Recruiter</h3>
              <ul className="text-gray-600 text-left space-y-2">
                <li>✅ Upload offer PDFs</li>
                <li>✅ Auto-encrypt with AES-256</li>
                <li>✅ Digitally sign documents</li>
                <li>✅ Track offer status</li>
              </ul>
            </div>

            {/* Admin Flow */}
            <div className="text-center">
              <div className="w-16 h-16 bg-purple-100 rounded-full flex items-center justify-center mx-auto mb-4">
                <span className="text-2xl">👨‍💼</span>
              </div>
              <h3 className="text-xl font-semibold mb-2">Admin</h3>
              <ul className="text-gray-600 text-left space-y-2">
                <li>✅ View all offers</li>
                <li>✅ Access audit logs</li>
                <li>✅ Monitor security events</li>
                <li>✅ Manage users</li>
              </ul>
            </div>
          </div>
        </div>
      </div>

      {/* PDF Security Flow */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-16">
        <h2 className="text-3xl font-bold text-center text-gray-900 mb-4">
          PDF Security Flow
        </h2>
        <p className="text-gray-600 text-center mb-8">
          Each internship offer implements 4 security concepts together
        </p>

        <div className="bg-white rounded-xl shadow-lg p-8 max-w-4xl mx-auto">
          <div className="space-y-4">
            <div className="flex items-center space-x-4 p-4 bg-blue-50 rounded-lg">
              <span className="text-2xl">1️⃣</span>
              <div>
                <h4 className="font-semibold">SHA-256 Hash</h4>
                <p className="text-sm text-gray-600">Compute hash of original PDF for integrity</p>
              </div>
            </div>
            <div className="flex items-center space-x-4 p-4 bg-green-50 rounded-lg">
              <span className="text-2xl">2️⃣</span>
              <div>
                <h4 className="font-semibold">Digital Signature</h4>
                <p className="text-sm text-gray-600">Sign with Recruiter's RSA private key</p>
              </div>
            </div>
            <div className="flex items-center space-x-4 p-4 bg-yellow-50 rounded-lg">
              <span className="text-2xl">3️⃣</span>
              <div>
                <h4 className="font-semibold">AES-256 Encryption</h4>
                <p className="text-sm text-gray-600">Encrypt PDF with unique session key</p>
              </div>
            </div>
            <div className="flex items-center space-x-4 p-4 bg-purple-50 rounded-lg">
              <span className="text-2xl">4️⃣</span>
              <div>
                <h4 className="font-semibold">RSA Key Exchange</h4>
                <p className="text-sm text-gray-600">Encrypt AES key with Student's public key</p>
              </div>
            </div>
            <div className="flex items-center space-x-4 p-4 bg-pink-50 rounded-lg">
              <span className="text-2xl">5️⃣</span>
              <div>
                <h4 className="font-semibold">Base64 Encoding</h4>
                <p className="text-sm text-gray-600">Encode for safe storage and transmission</p>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Footer */}
      <footer className="bg-gray-900 text-white py-8">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
          <p className="text-gray-400">
            Foundations of Cyber Security Lab Project
          </p>
          <p className="text-sm text-gray-500 mt-2">
            Implementing: Authentication, Authorization, Encryption, Hashing, Digital Signatures, Encoding
          </p>
        </div>
      </footer>
    </div>
  );
};

export default Home;
