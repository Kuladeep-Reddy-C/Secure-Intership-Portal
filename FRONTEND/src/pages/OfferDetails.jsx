/**
 * ===========================================
 * OFFER DETAILS PAGE
 * ===========================================
 * 
 * SECURITY FEATURES DEMONSTRATED:
 * - PDF Decryption (AES-256 + RSA)
 * - Digital Signature Verification
 * - Hash Integrity Check
 * - Accept/Reject with audit trail
 */

import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import api from '../services/api';
import { useAuth } from '../context/AuthContext';

const OfferDetails = () => {
  const { id } = useParams();
  const navigate = useNavigate();
  const { getPrivateKey } = useAuth();
  
  const [offer, setOffer] = useState(null);
  const [loading, setLoading] = useState(true);
  const [decrypting, setDecrypting] = useState(false);
  const [verifying, setVerifying] = useState(false);
  const [actionLoading, setActionLoading] = useState(false);
  const [error, setError] = useState('');
  const [decryptedPdf, setDecryptedPdf] = useState(null);
  const [verification, setVerification] = useState(null);
  const [privateKeyInput, setPrivateKeyInput] = useState('');
  const [showPrivateKeyModal, setShowPrivateKeyModal] = useState(false);

  useEffect(() => {
    fetchOffer();
    const storedKey = getPrivateKey();
    if (storedKey) {
      setPrivateKeyInput(storedKey);
    }
  }, [id]);

  const fetchOffer = async () => {
    try {
      const response = await api.get(`/offers/${id}`);
      setOffer(response.data.data);
    } catch (err) {
      setError('Failed to fetch offer');
    } finally {
      setLoading(false);
    }
  };

  const handleDecrypt = async () => {
    if (!privateKeyInput) {
      setShowPrivateKeyModal(true);
      return;
    }

    setDecrypting(true);
    setError('');

    try {
      const response = await api.post(`/offers/${id}/decrypt`, {
        privateKey: privateKeyInput
      });

      if (response.data.success) {
        setDecryptedPdf(response.data.data);
      }
    } catch (err) {
      setError(err.response?.data?.message || 'Decryption failed. Check your private key.');
    } finally {
      setDecrypting(false);
    }
  };

  const handleVerify = async () => {
    if (!privateKeyInput) {
      setShowPrivateKeyModal(true);
      return;
    }

    setVerifying(true);
    setError('');

    try {
      const response = await api.post(`/offers/${id}/verify`, {
        privateKey: privateKeyInput
      });

      setVerification(response.data.data);
    } catch (err) {
      setError(err.response?.data?.message || 'Verification failed.');
    } finally {
      setVerifying(false);
    }
  };

  const handleAccept = async () => {
    if (!verification?.isValid) {
      setError('Please verify the offer first before accepting.');
      return;
    }

    setActionLoading(true);
    try {
      await api.post(`/offers/${id}/accept`);
      fetchOffer();
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to accept offer');
    } finally {
      setActionLoading(false);
    }
  };

  const handleReject = async () => {
    setActionLoading(true);
    try {
      await api.post(`/offers/${id}/reject`);
      fetchOffer();
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to reject offer');
    } finally {
      setActionLoading(false);
    }
  };

  const downloadPdf = () => {
    if (!decryptedPdf) return;

    const byteCharacters = atob(decryptedPdf.pdfBase64);
    const byteNumbers = new Array(byteCharacters.length);
    for (let i = 0; i < byteCharacters.length; i++) {
      byteNumbers[i] = byteCharacters.charCodeAt(i);
    }
    const byteArray = new Uint8Array(byteNumbers);
    const blob = new Blob([byteArray], { type: 'application/pdf' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = decryptedPdf.filename || 'offer.pdf';
    a.click();
    URL.revokeObjectURL(url);
  };

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="w-12 h-12 border-4 border-primary-600 border-t-transparent rounded-full animate-spin"></div>
      </div>
    );
  }

  if (!offer) {
    return (
      <div className="max-w-4xl mx-auto px-4 py-8">
        <div className="card text-center py-12">
          <span className="text-6xl">❌</span>
          <h3 className="mt-4 text-xl font-medium text-gray-900">Offer Not Found</h3>
          <button onClick={() => navigate('/student')} className="btn-primary mt-4">
            Back to Dashboard
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-4xl mx-auto px-4 py-8">
      {/* Header */}
      <div className="mb-6">
        <button
          onClick={() => navigate('/student')}
          className="text-primary-600 hover:text-primary-700 flex items-center gap-1 mb-4"
        >
          ← Back to Dashboard
        </button>
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-gray-900">{offer.title}</h1>
            <p className="text-gray-600 text-lg">{offer.company}</p>
          </div>
          <span className={`px-3 py-1 rounded-full text-sm font-medium ${
            offer.status === 'pending' ? 'bg-yellow-100 text-yellow-800' :
            offer.status === 'accepted' ? 'bg-green-100 text-green-800' :
            offer.status === 'rejected' ? 'bg-red-100 text-red-800' :
            'bg-gray-100 text-gray-800'
          }`}>
            {offer.status.charAt(0).toUpperCase() + offer.status.slice(1)}
          </span>
        </div>
      </div>

      {/* Error Message */}
      {error && (
        <div className="mb-6 p-4 bg-red-50 border border-red-200 rounded-lg">
          <p className="text-red-600">{error}</p>
        </div>
      )}

      {/* Offer Details */}
      <div className="card mb-6">
        <h2 className="text-xl font-semibold mb-4">Offer Information</h2>
        <div className="grid grid-cols-2 gap-4 text-sm">
          <div>
            <p className="text-gray-500">Recruiter</p>
            <p className="font-medium">{offer.recruiterId?.name}</p>
          </div>
          <div>
            <p className="text-gray-500">Date Received</p>
            <p className="font-medium">{new Date(offer.createdAt).toLocaleDateString()}</p>
          </div>
          <div>
            <p className="text-gray-500">Expires On</p>
            <p className="font-medium">{new Date(offer.expiresAt).toLocaleDateString()}</p>
          </div>
          <div>
            <p className="text-gray-500">Original File</p>
            <p className="font-medium">{offer.originalFilename}</p>
          </div>
        </div>
        {offer.description && (
          <div className="mt-4 pt-4 border-t">
            <p className="text-gray-500 text-sm">Description</p>
            <p className="mt-1">{offer.description}</p>
          </div>
        )}
      </div>

      {/* Security Status */}
      <div className="card mb-6">
        <h2 className="text-xl font-semibold mb-4">🔐 Security Status</h2>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="p-3 bg-green-50 rounded-lg text-center">
            <span className="text-2xl">🔒</span>
            <p className="text-sm font-medium text-green-800 mt-1">AES-256 Encrypted</p>
          </div>
          <div className="p-3 bg-green-50 rounded-lg text-center">
            <span className="text-2xl">✍️</span>
            <p className="text-sm font-medium text-green-800 mt-1">Digitally Signed</p>
          </div>
          <div className="p-3 bg-green-50 rounded-lg text-center">
            <span className="text-2xl">#️⃣</span>
            <p className="text-sm font-medium text-green-800 mt-1">SHA-256 Hashed</p>
          </div>
          <div className="p-3 bg-green-50 rounded-lg text-center">
            <span className="text-2xl">📦</span>
            <p className="text-sm font-medium text-green-800 mt-1">Base64 Encoded</p>
          </div>
        </div>
        <div className="mt-4 p-3 bg-gray-50 rounded-lg">
          <p className="text-xs text-gray-500">PDF Hash (SHA-256)</p>
          <p className="font-mono text-xs break-all">{offer.pdfHash}</p>
        </div>
      </div>

      {/* Actions */}
      <div className="card mb-6">
        <h2 className="text-xl font-semibold mb-4">Actions</h2>
        
        <div className="space-y-4">
          {/* Decrypt Button */}
          <div className="flex items-center justify-between p-4 bg-blue-50 rounded-lg">
            <div>
              <h3 className="font-medium text-blue-800">Step 1: Decrypt PDF</h3>
              <p className="text-sm text-blue-600">Decrypt using your private RSA key</p>
            </div>
            <button
              onClick={handleDecrypt}
              disabled={decrypting || !!decryptedPdf}
              className={`px-4 py-2 rounded-lg font-medium ${
                decryptedPdf 
                  ? 'bg-green-500 text-white' 
                  : 'bg-blue-600 hover:bg-blue-700 text-white'
              }`}
            >
              {decrypting ? 'Decrypting...' : decryptedPdf ? '✓ Decrypted' : 'Decrypt'}
            </button>
          </div>

          {/* Verify Button */}
          <div className="flex items-center justify-between p-4 bg-purple-50 rounded-lg">
            <div>
              <h3 className="font-medium text-purple-800">Step 2: Verify Signature</h3>
              <p className="text-sm text-purple-600">Verify authenticity and integrity</p>
            </div>
            <button
              onClick={handleVerify}
              disabled={verifying || !decryptedPdf}
              className={`px-4 py-2 rounded-lg font-medium ${
                verification?.isValid 
                  ? 'bg-green-500 text-white' 
                  : verification && !verification.isValid
                  ? 'bg-red-500 text-white'
                  : 'bg-purple-600 hover:bg-purple-700 text-white disabled:opacity-50'
              }`}
            >
              {verifying ? 'Verifying...' : verification?.isValid ? '✓ Valid' : verification ? '✗ Invalid' : 'Verify'}
            </button>
          </div>

          {/* Download Button */}
          {decryptedPdf && (
            <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
              <div>
                <h3 className="font-medium text-gray-800">Download PDF</h3>
                <p className="text-sm text-gray-600">Save the decrypted offer letter</p>
              </div>
              <button
                onClick={downloadPdf}
                className="bg-gray-600 hover:bg-gray-700 text-white px-4 py-2 rounded-lg font-medium"
              >
                📥 Download
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Verification Results */}
      {verification && (
        <div className={`card mb-6 ${verification.isValid ? 'border-green-500' : 'border-red-500'} border-2`}>
          <h2 className="text-xl font-semibold mb-4">
            {verification.isValid ? '✅ Verification Successful' : '❌ Verification Failed'}
          </h2>
          <div className="space-y-3">
            <div className={`p-3 rounded-lg ${verification.signatureValid ? 'bg-green-50' : 'bg-red-50'}`}>
              <p className="font-medium">{verification.securityChecks.authenticity}</p>
              <p className="text-sm text-gray-600">Digital signature verification</p>
            </div>
            <div className={`p-3 rounded-lg ${verification.hashValid ? 'bg-green-50' : 'bg-red-50'}`}>
              <p className="font-medium">{verification.securityChecks.integrity}</p>
              <p className="text-sm text-gray-600">Hash integrity check</p>
            </div>
            <div className={`p-3 rounded-lg ${verification.signatureValid ? 'bg-green-50' : 'bg-red-50'}`}>
              <p className="font-medium">{verification.securityChecks.nonRepudiation}</p>
              <p className="text-sm text-gray-600">Non-repudiation guarantee</p>
            </div>
          </div>
        </div>
      )}

      {/* Accept/Reject Actions */}
      {offer.status === 'pending' && (
        <div className="card">
          <h2 className="text-xl font-semibold mb-4">Respond to Offer</h2>
          {!verification?.isValid && (
            <p className="text-yellow-600 mb-4">
              ⚠️ Please verify the offer signature before accepting.
            </p>
          )}
          <div className="flex gap-4">
            <button
              onClick={handleAccept}
              disabled={actionLoading || !verification?.isValid}
              className="flex-1 btn-success py-3 disabled:opacity-50"
            >
              {actionLoading ? 'Processing...' : '✓ Accept Offer'}
            </button>
            <button
              onClick={handleReject}
              disabled={actionLoading}
              className="flex-1 btn-danger py-3"
            >
              {actionLoading ? 'Processing...' : '✗ Reject Offer'}
            </button>
          </div>
        </div>
      )}

      {/* Private Key Modal */}
      {showPrivateKeyModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
          <div className="bg-white rounded-xl p-6 max-w-lg w-full">
            <h3 className="text-xl font-semibold mb-4">Enter Private Key</h3>
            <p className="text-gray-600 text-sm mb-4">
              Your RSA private key is required to decrypt the offer. 
              This key was provided when you registered.
            </p>
            <textarea
              value={privateKeyInput}
              onChange={(e) => setPrivateKeyInput(e.target.value)}
              placeholder="-----BEGIN RSA PRIVATE KEY-----&#10;...&#10;-----END RSA PRIVATE KEY-----"
              rows={10}
              className="input-field font-mono text-xs"
            />
            <div className="flex gap-3 mt-4">
              <button
                onClick={() => setShowPrivateKeyModal(false)}
                className="flex-1 btn-secondary"
              >
                Cancel
              </button>
              <button
                onClick={() => {
                  setShowPrivateKeyModal(false);
                  handleDecrypt();
                }}
                disabled={!privateKeyInput}
                className="flex-1 btn-primary"
              >
                Decrypt
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default OfferDetails;
