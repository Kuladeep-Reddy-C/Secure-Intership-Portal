/**
 * ===========================================
 * OTP VERIFICATION PAGE
 * ===========================================
 * 
 * SECURITY: Multi-Factor Authentication (Step 2)
 * - Time-bound OTP verification
 * - OTP sent via email
 */

import React, { useState, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

const OTPVerification = () => {
  const [otp, setOtp] = useState(['', '', '', '', '', '']);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [resendLoading, setResendLoading] = useState(false);
  const [countdown, setCountdown] = useState(300); // 5 minutes
  const navigate = useNavigate();
  const location = useLocation();
  const { verifyOTP, resendOTP, tempToken, user } = useAuth();

  const email = location.state?.email || '';

  // Redirect if no temp token or already logged in
  useEffect(() => {
    if (!tempToken) {
      navigate('/login');
    }
    if (user) {
      navigate(`/${user.role}`);
    }
  }, [tempToken, user, navigate]);

  // Countdown timer
  useEffect(() => {
    const timer = setInterval(() => {
      setCountdown((prev) => (prev > 0 ? prev - 1 : 0));
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  const formatTime = (seconds) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins}:${secs.toString().padStart(2, '0')}`;
  };

  // Handle OTP input
  const handleChange = (index, value) => {
    if (value.length > 1) return; // Prevent multiple characters
    
    const newOtp = [...otp];
    newOtp[index] = value;
    setOtp(newOtp);

    // Auto-focus next input
    if (value && index < 5) {
      const nextInput = document.getElementById(`otp-${index + 1}`);
      nextInput?.focus();
    }
  };

  // Handle backspace
  const handleKeyDown = (index, e) => {
    if (e.key === 'Backspace' && !otp[index] && index > 0) {
      const prevInput = document.getElementById(`otp-${index - 1}`);
      prevInput?.focus();
    }
  };

  // Handle paste
  const handlePaste = (e) => {
    e.preventDefault();
    const pastedData = e.clipboardData.getData('text').slice(0, 6);
    const newOtp = pastedData.split('').concat(Array(6).fill('')).slice(0, 6);
    setOtp(newOtp);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    const otpString = otp.join('');
    
    if (otpString.length !== 6) {
      setError('Please enter complete OTP');
      return;
    }

    setError('');
    setLoading(true);

    try {
      const response = await verifyOTP(otpString);
      
      if (response.success) {
        const userRole = response.data.user.role;
        navigate(`/${userRole}`);
      }
    } catch (err) {
      setError(err.response?.data?.message || 'Invalid OTP. Please try again.');
      setOtp(['', '', '', '', '', '']);
    } finally {
      setLoading(false);
    }
  };

  const handleResendOTP = async () => {
    setResendLoading(true);
    setError('');

    try {
      await resendOTP();
      setCountdown(300); // Reset countdown
      setOtp(['', '', '', '', '', '']);
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to resend OTP');
    } finally {
      setResendLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-md w-full">
        <div className="card">
          {/* Header */}
          <div className="text-center mb-8">
            <span className="text-4xl">📧</span>
            <h2 className="mt-4 text-3xl font-bold text-gray-900">
              Verify OTP
            </h2>
            <p className="mt-2 text-gray-600">
              Enter the 6-digit code sent to
            </p>
            <p className="font-medium text-primary-600">{email}</p>
          </div>

          {/* Countdown Timer */}
          <div className="text-center mb-6">
            <div className={`text-2xl font-mono ${countdown < 60 ? 'text-red-600' : 'text-gray-700'}`}>
              {formatTime(countdown)}
            </div>
            <p className="text-sm text-gray-500">Time remaining</p>
          </div>

          {/* Error Message */}
          {error && (
            <div className="mb-4 p-4 bg-red-50 border border-red-200 rounded-lg">
              <p className="text-red-600 text-sm">{error}</p>
            </div>
          )}

          {/* OTP Input */}
          <form onSubmit={handleSubmit}>
            <div className="flex justify-center gap-2 mb-6">
              {otp.map((digit, index) => (
                <input
                  key={index}
                  id={`otp-${index}`}
                  type="text"
                  inputMode="numeric"
                  pattern="[0-9]*"
                  maxLength={1}
                  value={digit}
                  onChange={(e) => handleChange(index, e.target.value.replace(/\D/g, ''))}
                  onKeyDown={(e) => handleKeyDown(index, e)}
                  onPaste={index === 0 ? handlePaste : undefined}
                  className="w-12 h-14 text-center text-2xl font-bold border-2 border-gray-300 rounded-lg focus:border-primary-500 focus:ring-2 focus:ring-primary-200 outline-none transition-all"
                  disabled={loading || countdown === 0}
                />
              ))}
            </div>

            <button
              type="submit"
              disabled={loading || countdown === 0}
              className="w-full btn-primary py-3 flex items-center justify-center"
            >
              {loading ? (
                <>
                  <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin mr-2"></div>
                  Verifying...
                </>
              ) : (
                'Verify OTP'
              )}
            </button>
          </form>

          {/* Resend OTP */}
          <div className="mt-6 text-center">
            {countdown === 0 ? (
              <button
                onClick={handleResendOTP}
                disabled={resendLoading}
                className="text-primary-600 hover:text-primary-700 font-medium"
              >
                {resendLoading ? 'Sending...' : 'Resend OTP'}
              </button>
            ) : (
              <p className="text-gray-500">
                Didn't receive code?{' '}
                <button
                  onClick={handleResendOTP}
                  disabled={resendLoading}
                  className="text-primary-600 hover:text-primary-700 font-medium"
                >
                  Resend OTP
                </button>
              </p>
            )}
          </div>

          {/* Security Info */}
          <div className="mt-6 p-4 bg-green-50 rounded-lg">
            <h4 className="font-medium text-green-800 mb-1">🛡️ MFA Security</h4>
            <p className="text-sm text-green-600">
              This extra step ensures that even if someone knows your password, 
              they can't access your account without access to your email.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default OTPVerification;
