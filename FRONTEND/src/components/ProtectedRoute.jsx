/**
 * ===========================================
 * PROTECTED ROUTE COMPONENT
 * ===========================================
 * 
 * SECURITY: Role-Based Access Control (RBAC)
 * 
 * This component enforces authorization at the route level:
 * - Checks if user is authenticated
 * - Verifies user has required role
 * - Redirects unauthorized users
 */

import React from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

const ProtectedRoute = ({ children, allowedRoles }) => {
  const { user, loading } = useAuth();
  const location = useLocation();

  // Show loading while checking auth
  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="w-12 h-12 border-4 border-primary-600 border-t-transparent rounded-full animate-spin"></div>
      </div>
    );
  }

  // Not authenticated - redirect to login
  if (!user) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  // Check if user's role is allowed
  if (allowedRoles && !allowedRoles.includes(user.role)) {
    // Redirect to their own dashboard
    return <Navigate to={`/${user.role}`} replace />;
  }

  // Authorized - render the protected content
  return children;
};

export default ProtectedRoute;
