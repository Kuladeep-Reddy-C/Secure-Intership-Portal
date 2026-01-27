/**
 * ===========================================
 * STUDENT DASHBOARD
 * ===========================================
 * 
 * Features:
 * - View encrypted offers
 * - Decrypt offers with private key
 * - Verify digital signatures
 * - Accept/Reject offers
 */

import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import api from '../services/api';
import { useAuth } from '../context/AuthContext';

const StudentDashboard = () => {
  const [offers, setOffers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const { user, getPrivateKey } = useAuth();

  useEffect(() => {
    fetchOffers();
  }, []);

  const fetchOffers = async () => {
    try {
      const response = await api.get('/offers');
      setOffers(response.data.data);
    } catch (err) {
      setError('Failed to fetch offers');
    } finally {
      setLoading(false);
    }
  };

  const getStatusBadge = (status) => {
    const badges = {
      pending: 'status-pending',
      accepted: 'status-accepted',
      rejected: 'status-rejected',
      expired: 'status-expired'
    };
    return badges[status] || 'status-pending';
  };

  const hasPrivateKey = !!getPrivateKey();

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="w-12 h-12 border-4 border-primary-600 border-t-transparent rounded-full animate-spin"></div>
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-gray-900">
          Welcome, {user?.name}! 👋
        </h1>
        <p className="text-gray-600 mt-2">
          View and manage your internship offers
        </p>
      </div>

      {/* Private Key Warning */}
      {!hasPrivateKey && (
        <div className="mb-6 p-4 bg-yellow-50 border border-yellow-200 rounded-lg">
          <h3 className="font-bold text-yellow-800">⚠️ Private Key Missing</h3>
          <p className="text-yellow-700 text-sm mt-1">
            Your private key is not stored in this browser. You won't be able to decrypt offer letters.
            Please import your private key or use the browser where you registered.
          </p>
        </div>
      )}

      {/* Security Info */}
      <div className="mb-6 p-4 bg-blue-50 rounded-lg">
        <h3 className="font-medium text-blue-800 mb-2">🔐 Security Features</h3>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-sm text-blue-700">
          <span>✅ AES-256 Encrypted</span>
          <span>✅ Digitally Signed</span>
          <span>✅ Hash Verified</span>
          <span>✅ Base64 Encoded</span>
        </div>
      </div>

      {/* Error Message */}
      {error && (
        <div className="mb-6 p-4 bg-red-50 border border-red-200 rounded-lg">
          <p className="text-red-600">{error}</p>
        </div>
      )}

      {/* Offers List */}
      {offers.length === 0 ? (
        <div className="card text-center py-12">
          <span className="text-6xl">📭</span>
          <h3 className="mt-4 text-xl font-medium text-gray-900">No Offers Yet</h3>
          <p className="text-gray-600 mt-2">
            You haven't received any internship offers yet.
          </p>
        </div>
      ) : (
        <div className="grid gap-6">
          {offers.map((offer) => (
            <div key={offer._id} className="card hover:shadow-lg transition-shadow">
              <div className="flex flex-col md:flex-row md:items-center md:justify-between">
                <div className="flex-1">
                  <div className="flex items-center gap-3 mb-2">
                    <h3 className="text-xl font-semibold text-gray-900">
                      {offer.title}
                    </h3>
                    <span className={getStatusBadge(offer.status)}>
                      {offer.status.charAt(0).toUpperCase() + offer.status.slice(1)}
                    </span>
                  </div>
                  <p className="text-gray-600 mb-2">{offer.company}</p>
                  <div className="flex flex-wrap gap-4 text-sm text-gray-500">
                    <span>📅 Received: {new Date(offer.createdAt).toLocaleDateString()}</span>
                    <span>⏰ Expires: {new Date(offer.expiresAt).toLocaleDateString()}</span>
                    {offer.recruiterId && (
                      <span>👔 From: {offer.recruiterId.name}</span>
                    )}
                  </div>
                </div>
                
                <div className="mt-4 md:mt-0 md:ml-4 flex gap-2">
                  <Link
                    to={`/student/offer/${offer._id}`}
                    className="btn-primary text-sm"
                  >
                    View Offer
                  </Link>
                </div>
              </div>

              {/* Security Indicators */}
              <div className="mt-4 pt-4 border-t flex flex-wrap gap-2">
                <span className="security-badge-high">🔒 Encrypted</span>
                <span className="security-badge-high">✍️ Signed</span>
                <span className="security-badge-high">#️⃣ Hash: {offer.pdfHash?.substring(0, 8)}...</span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default StudentDashboard;
