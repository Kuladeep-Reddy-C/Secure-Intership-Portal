/**
 * ===========================================
 * API SERVICE
 * ===========================================
 * 
 * Axios instance configured with:
 * - Base URL from environment variable
 * - JWT token injection via interceptor
 * - Error handling
 */

import axios from 'axios';

// Create axios instance with base URL from environment
const api = axios.create({
  baseURL: import.meta.env.VITE_BACKEND_URL || 'http://localhost:5000/api',
  headers: {
    'Content-Type': 'application/json'
  }
});

// Request interceptor - Add JWT token to requests
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor - Handle common errors
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response) {
      // Handle specific error codes
      switch (error.response.status) {
        case 401:
          // Token expired or invalid
          if (error.response.data.error === 'TOKEN_EXPIRED' || 
              error.response.data.error === 'INVALID_TOKEN') {
            localStorage.removeItem('token');
            localStorage.removeItem('user');
            window.location.href = '/login';
          }
          break;
        case 403:
          // Forbidden - access denied
          console.error('Access denied:', error.response.data.message);
          break;
        case 429:
          // Rate limited
          console.error('Rate limit exceeded');
          break;
      }
    }
    return Promise.reject(error);
  }
);

export default api;
