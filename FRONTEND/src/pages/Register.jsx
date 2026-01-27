/**
 * ===========================================
 * REGISTER PAGE
 * ===========================================
 * 
 * SECURITY:
 * - Password hashed on backend with bcrypt
 * - RSA key pair generated for user
 * - Private key returned only at registration
 */

import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

const Register = () => {
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    password: '',
    confirmPassword: '',
    role: 'student',
    rollNo: ''
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState(false);
  const [privateKey, setPrivateKey] = useState('');
  const navigate = useNavigate();
  const { register, storePrivateKey } = useAuth();

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');

    // Validate passwords match
    if (formData.password !== formData.confirmPassword) {
      setError('Passwords do not match');
      return;
    }

    // Validate password strength
    if (formData.password.length < 8) {
      setError('Password must be at least 8 characters long');
      return;
    }

    setLoading(true);

    try {
      const response = await register({
        name: formData.name,
        email: formData.email,
        password: formData.password,
        role: formData.role,
        rollNo: formData.rollNo || undefined
      });

      if (response.success) {
        // Store private key
        setPrivateKey(response.data.privateKey);
        storePrivateKey(response.data.privateKey);
        setSuccess(true);
      }
    } catch (err) {
      setError(err.response?.data?.message || 'Registration failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const copyPrivateKey = () => {
    navigator.clipboard.writeText(privateKey);
    alert('Private key copied to clipboard!');
  };

  const downloadPrivateKey = () => {
    const blob = new Blob([privateKey], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'private_key.pem';
    a.click();
    URL.revokeObjectURL(url);
  };

  if (success) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50 py-12 px-4">
        <div className="max-w-2xl w-full">
          <div className="card">
            <div className="text-center mb-6">
              <span className="text-6xl">🎉</span>
              <h2 className="mt-4 text-2xl font-bold text-gray-900">
                Registration Successful!
              </h2>
            </div>

            {/* Important Security Notice */}
            <div className="bg-red-50 border border-red-200 rounded-lg p-4 mb-6">
              <h3 className="font-bold text-red-800 mb-2">
                ⚠️ IMPORTANT: Save Your Private Key
              </h3>
              <p className="text-red-700 text-sm mb-4">
                This private key is required to decrypt your offer letters.
                <strong> It will NOT be shown again.</strong> Store it securely!
              </p>
              
              <div className="bg-white rounded border p-3 mb-4">
                <pre className="text-xs overflow-x-auto whitespace-pre-wrap break-all">
                  {privateKey}
                </pre>
              </div>

              <div className="flex gap-2">
                <button onClick={copyPrivateKey} className="btn-secondary text-sm">
                  📋 Copy
                </button>
                <button onClick={downloadPrivateKey} className="btn-secondary text-sm">
                  💾 Download
                </button>
              </div>
            </div>

            <div className="bg-green-50 border border-green-200 rounded-lg p-4 mb-6">
              <h4 className="font-medium text-green-800">What happens next?</h4>
              <ul className="text-green-700 text-sm mt-2 space-y-1">
                <li>✅ Your account has been created</li>
                <li>✅ Your private key is stored in this browser</li>
                <li>✅ You can now login with your email and password</li>
              </ul>
            </div>

            <button
              onClick={() => navigate('/login')}
              className="w-full btn-primary py-3"
            >
              Go to Login
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-md w-full">
        <div className="card">
          {/* Header */}
          <div className="text-center mb-8">
            <span className="text-4xl">📝</span>
            <h2 className="mt-4 text-3xl font-bold text-gray-900">
              Create Account
            </h2>
            <p className="mt-2 text-gray-600">
              Join the Secure Internship Portal
            </p>
          </div>

          {/* Error Message */}
          {error && (
            <div className="mb-4 p-4 bg-red-50 border border-red-200 rounded-lg">
              <p className="text-red-600 text-sm">{error}</p>
            </div>
          )}

          {/* Registration Form */}
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Full Name
              </label>
              <input
                type="text"
                name="name"
                value={formData.name}
                onChange={handleChange}
                required
                className="input-field"
                placeholder="John Doe"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Email Address
              </label>
              <input
                type="email"
                name="email"
                value={formData.email}
                onChange={handleChange}
                required
                className="input-field"
                placeholder="you@example.com"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Role
              </label>
              <select
                name="role"
                value={formData.role}
                onChange={handleChange}
                className="input-field"
              >
                <option value="student">Student</option>
                <option value="recruiter">Recruiter</option>
              </select>
            </div>

            {formData.role === 'student' && (
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Roll Number (Optional)
                </label>
                <input
                  type="text"
                  name="rollNo"
                  value={formData.rollNo}
                  onChange={handleChange}
                  className="input-field"
                  placeholder="e.g., 2024CS001"
                />
              </div>
            )}

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Password
              </label>
              <input
                type="password"
                name="password"
                value={formData.password}
                onChange={handleChange}
                required
                minLength={8}
                className="input-field"
                placeholder="Min. 8 characters"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Confirm Password
              </label>
              <input
                type="password"
                name="confirmPassword"
                value={formData.confirmPassword}
                onChange={handleChange}
                required
                className="input-field"
                placeholder="Confirm your password"
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full btn-primary py-3 flex items-center justify-center"
            >
              {loading ? (
                <>
                  <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin mr-2"></div>
                  Creating account...
                </>
              ) : (
                'Create Account'
              )}
            </button>
          </form>

          {/* Security Note */}
          <div className="mt-6 p-4 bg-blue-50 rounded-lg">
            <h4 className="font-medium text-blue-800 mb-1">🔑 RSA Keys</h4>
            <p className="text-sm text-blue-600">
              An RSA key pair will be generated for you. Keep your private key safe - it's needed to decrypt offers.
            </p>
          </div>

          {/* Login Link */}
          <div className="mt-6 text-center">
            <p className="text-gray-600">
              Already have an account?{' '}
              <Link to="/login" className="text-primary-600 hover:text-primary-700 font-medium">
                Sign in
              </Link>
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Register;
