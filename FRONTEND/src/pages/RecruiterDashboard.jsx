/**
 * ===========================================
 * RECRUITER DASHBOARD (FINAL + CLEAN UI)
 * ===========================================
 */

import React, { useState, useEffect, useCallback } from 'react';
import api from '../services/api';
import { useAuth } from '../context/AuthContext';

const RecruiterDashboard = () => {
  const { user, loading: authLoading } = useAuth();

  const [pageLoading, setPageLoading] = useState(true);
  const [offers, setOffers] = useState([]);
  const [students, setStudents] = useState([]);

  const [uploading, setUploading] = useState(false);
  const [showUploadForm, setShowUploadForm] = useState(false);

  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  const [privateKey, setPrivateKey] = useState(
    localStorage.getItem('privateKey') || ''
  );

  const [formData, setFormData] = useState({
    title: '',
    company: '',
    description: '',
    studentEmail: '',
    expiryDays: '30',
    pdf: null
  });

  /**
   * ===========================================
   * FETCH DATA
   * ===========================================
   */
  const fetchData = useCallback(async () => {
    if (!user || user.role !== 'recruiter') return;

    try {
      const [offersRes, studentsRes] = await Promise.all([
        api.get('/offers'),
        api.get('/offers/students/list')
      ]);

      setOffers(offersRes.data.data);
      setStudents(studentsRes.data.data);
    } catch {
      setError('Failed to load recruiter data');
    } finally {
      setPageLoading(false);
    }
  }, [user]);

  useEffect(() => {
    if (!authLoading && user?.role === 'recruiter') {
      fetchData();
    }
  }, [authLoading, user, fetchData]);

  /**
   * ===========================================
   * HANDLERS
   * ===========================================
   */
  const handleChange = (e) => {
    const { name, value, files } = e.target;
    setFormData((prev) => ({
      ...prev,
      [name]: name === 'pdf' ? files[0] : value
    }));
  };

  const handleSavePrivateKey = () => {
    if (!privateKey.trim().includes('BEGIN PRIVATE KEY')) {
      setError('Invalid private key format');
      return;
    }
    localStorage.setItem('privateKey', privateKey.trim());
    setSuccess('Private key restored successfully');
    setError('');
  };

  /**
   * ===========================================
   * UPLOAD OFFER
   * ===========================================
   */
  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');
    setUploading(true);

    try {
      const storedKey = localStorage.getItem('privateKey');

      if (!storedKey) {
        setError('Private key required before uploading');
        setUploading(false);
        return;
      }

      const data = new FormData();
      Object.entries(formData).forEach(([key, value]) => {
        if (value) data.append(key, value);
      });

      data.append('recruiterPrivateKey', storedKey);

      const response = await api.post('/offers/upload', data, {
        headers: {
          'Content-Type': 'multipart/form-data' // 🔥 CRITICAL FIX
        }
      });

      if (response.data.success) {
        setSuccess('Offer uploaded successfully!');
        setShowUploadForm(false);
        setFormData({
          title: '',
          company: '',
          description: '',
          studentEmail: '',
          expiryDays: '30',
          pdf: null
        });
        fetchData();
      }
    } catch (err) {
      setError(err.response?.data?.message || 'Upload failed');
    } finally {
      setUploading(false);
    }
  };


  /**
   * ===========================================
   * UI STATES
   * ===========================================
   */
  if (authLoading || pageLoading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="w-10 h-10 border-4 border-blue-600 border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  return (
    <div className="max-w-6xl mx-auto p-6 space-y-6">

      {/* HEADER */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold">Recruiter Dashboard 👔</h1>
          <p className="text-gray-500">Manage and send secure offers</p>
        </div>
        <button
          onClick={() => setShowUploadForm(!showUploadForm)}
          className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
        >
          {showUploadForm ? 'Close' : '+ New Offer'}
        </button>
      </div>

      {/* ALERTS */}
      {error && <div className="p-3 bg-red-100 text-red-700 rounded">{error}</div>}
      {success && <div className="p-3 bg-green-100 text-green-700 rounded">{success}</div>}

      {/* PRIVATE KEY RESTORE */}
      {!localStorage.getItem('privateKey') && (
        <div className="p-5 bg-yellow-50 border border-yellow-300 rounded-lg">
          <h3 className="font-semibold text-yellow-800 mb-2">
            🔑 Restore Private Key
          </h3>
          <textarea
            rows={5}
            className="w-full p-3 border rounded-md font-mono text-sm"
            placeholder="-----BEGIN PRIVATE KEY-----"
            value={privateKey}
            onChange={(e) => setPrivateKey(e.target.value)}
          />
          <button
            onClick={handleSavePrivateKey}
            className="mt-3 px-4 py-2 bg-yellow-600 text-white rounded"
          >
            Save Private Key
          </button>
        </div>
      )}

      {/* UPLOAD FORM */}
      {showUploadForm && (
        <div className="p-6 bg-white rounded-lg shadow">
          <h2 className="text-xl font-semibold mb-4">Create New Offer</h2>

          <form onSubmit={handleSubmit} className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <input className="input" name="title" placeholder="Position Title" value={formData.title} onChange={handleChange} required />
            <input className="input" name="company" placeholder="Company Name" value={formData.company} onChange={handleChange} required />
            <select className="input" name="studentEmail" value={formData.studentEmail} onChange={handleChange} required>
              <option value="">Select Student</option>
              {students.map((s) => (
                <option key={s._id} value={s.email}>{s.name} ({s.email})</option>
              ))}
            </select>
            <input className="input" type="number" name="expiryDays" min="1" max="90" value={formData.expiryDays} onChange={handleChange} />
            <textarea className="input md:col-span-2" name="description" placeholder="Description" value={formData.description} onChange={handleChange} />
            <input className="md:col-span-2" type="file" name="pdf" accept="application/pdf" onChange={handleChange} required />

            <button
              disabled={uploading || !localStorage.getItem('privateKey')}
              className="md:col-span-2 py-3 bg-blue-600 text-white rounded-lg disabled:opacity-50"
            >
              {uploading ? 'Uploading...' : 'Upload Secure Offer'}
            </button>
          </form>
        </div>
      )}

      {/* OFFERS */}
      <div>
        <h2 className="text-xl font-semibold mb-3">Sent Offers</h2>
        {offers.length === 0 ? (
          <p className="text-gray-500">No offers sent yet</p>
        ) : (
          offers.map((offer) => (
            <div key={offer._id} className="p-4 bg-white rounded-lg shadow mb-2">
              <h3 className="font-semibold">{offer.title}</h3>
              <p className="text-gray-500">{offer.company}</p>
              <span className="text-sm text-blue-600">{offer.status}</span>
            </div>
          ))
        )}
      </div>

    </div>
  );
};

export default RecruiterDashboard;
