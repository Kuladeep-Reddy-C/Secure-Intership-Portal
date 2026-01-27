/**
 * ===========================================
 * AUTHENTICATION CONTEXT
 * ===========================================
 * 
 * Manages authentication state across the application
 * 
 * SECURITY FEATURES:
 * - JWT token stored in localStorage
 * - User data managed in context
 * - Automatic token validation on app load
 */

import React, { createContext, useContext, useState, useEffect } from 'react';
import api from '../services/api';

const AuthContext = createContext(null);

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [tempToken, setTempToken] = useState(null);

  // Check for existing session on app load
  useEffect(() => {
    checkAuth();
  }, []);

  const checkAuth = async () => {
    const token = localStorage.getItem('token');
    if (token) {
      try {
        const response = await api.get('/auth/me');
        setUser(response.data.data);
      } catch (error) {
        console.error('Auth check failed:', error);
        localStorage.removeItem('token');
        localStorage.removeItem('user');
      }
    }
    setLoading(false);
  };

  // Login - Step 1: Verify credentials, get temp token
  const login = async (email, password) => {
    const response = await api.post('/auth/login', { email, password });
    if (response.data.requiresOTP) {
      setTempToken(response.data.data.tempToken);
    }
    return response.data;
  };

  // Login - Step 2: Verify OTP
  const verifyOTP = async (otp) => {
    const response = await api.post('/auth/verify-otp', { 
      tempToken, 
      otp 
    });
    
    if (response.data.success) {
      const { token, user } = response.data.data;
      localStorage.setItem('token', token);
      localStorage.setItem('user', JSON.stringify(user));
      setUser(user);
      setTempToken(null);
    }
    
    return response.data;
  };

  // Resend OTP
  const resendOTP = async () => {
    const response = await api.post('/auth/resend-otp', { tempToken });
    return response.data;
  };

  // Register new user
  const register = async (userData) => {
    const response = await api.post('/auth/register', userData);
    return response.data;
  };

  // Logout
  const logout = async () => {
    try {
      await api.post('/auth/logout');
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      localStorage.removeItem('token');
      localStorage.removeItem('user');
      localStorage.removeItem('privateKey');
      setUser(null);
      setTempToken(null);
    }
  };

  // Store private key securely (client-side)
  const storePrivateKey = (privateKey) => {
    localStorage.setItem('privateKey', privateKey);
  };

  // Get stored private key
  const getPrivateKey = () => {
    return localStorage.getItem('privateKey');
  };

  const value = {
    user,
    loading,
    tempToken,
    login,
    verifyOTP,
    resendOTP,
    register,
    logout,
    storePrivateKey,
    getPrivateKey,
    checkAuth
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};

export default AuthContext;
