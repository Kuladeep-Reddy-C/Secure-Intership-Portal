/**
 * ===========================================
 * RECRUITER DASHBOARD (FIXED + LOGS)
 * ===========================================
 */

import React, { useState, useEffect, useCallback } from 'react';
import api from '../services/api';
import { useAuth } from '../context/AuthContext';

const RecruiterDashboard = () => {
  const { user, loading: authLoading } = useAuth();

  // Page state (NOT auth loading)
  const [pageLoading, setPageLoading] = useState(true);
  const [offers, setOffers] = useState([]);
  const [students, setStudents] = useState([]);

  const [uploading, setUploading] = useState(false);
  const [showUploadForm, setShowUploadForm] = useState(false);

  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

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
   * FETCH DATA (OFFERS + STUDENTS)
   * ===========================================
   */
  const fetchData = useCallback(async () => {
    const token = localStorage.getItem('token');

    console.log('========== FETCH DATA ==========');
    console.log('Auth loading:', authLoading);
    console.log('User:', user);
    console.log('JWT token:', token);

    if (!token) {
      console.warn('❌ No token found, aborting fetch');
      return;
    }

    if (!user || user.role !== 'recruiter') {
      console.warn('❌ User not recruiter, aborting fetch');
      return;
    }

    try {
      console.log('➡️ Fetching offers & students...');

      const [offersRes, studentsRes] = await Promise.all([
        api.get('/offers'),
        api.get('/offers/students/list')
      ]);

      console.log('✅ Offers fetched:', offersRes.data.data.length);
      console.log('✅ Students fetched:', studentsRes.data.data.length);

      setOffers(offersRes.data.data);
      setStudents(studentsRes.data.data);
    } catch (err) {
      console.error('❌ Fetch error:', err.response?.status, err.response?.data);
      setError('Failed to fetch recruiter data');
    } finally {
      setPageLoading(false);
    }
  }, [authLoading, user]);

  /**
   * ===========================================
   * EFFECT: WAIT FOR AUTH → FETCH
   * ===========================================
   */
  useEffect(() => {
    if (!authLoading && user?.role === 'recruiter') {
      fetchData();
    }
  }, [authLoading, user, fetchData]);

  /**
   * ===========================================
   * FORM HANDLERS
   * ===========================================
   */
  const handleChange = (e) => {
    const { name, value, files } = e.target;
    setFormData((prev) => ({
      ...prev,
      [name]: name === 'pdf' ? files[0] : value
    }));
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
      // 1️⃣ Get recruiter private key
      const recruiterPrivateKey = localStorage.getItem('privateKey');

      if (!recruiterPrivateKey) {
        setError('Private key missing. Please re-login.');
        setUploading(false);
        return;
      }

      // 2️⃣ Create FormData FIRST
      const data = new FormData();

      // 3️⃣ Append normal form fields
      Object.entries(formData).forEach(([key, value]) => {
        if (value) data.append(key, value);
      });

      // 4️⃣ Append recruiter private key
      data.append('recruiterPrivateKey', recruiterPrivateKey);

      console.log('➡️ Uploading offer...');

      // 5️⃣ Send request
      const response = await api.post('/offers/upload', data, {
        headers: { 'Content-Type': 'multipart/form-data' }
      });

      if (response.data.success) {
        console.log('✅ Offer uploaded');
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
      console.error('❌ Upload error:', err.response?.data);
      setError(err.response?.data?.message || 'Upload failed');
    } finally {
      setUploading(false);
    }
  };

  /**
   * ===========================================
   * STATUS BADGE
   * ===========================================
   */
  const getStatusBadge = (status) => {
    const badges = {
      pending: 'status-pending',
      accepted: 'status-accepted',
      rejected: 'status-rejected',
      expired: 'status-expired'
    };
    return badges[status] || 'status-pending';
  };

  /**
   * ===========================================
   * LOADING STATE
   * ===========================================
   */
  if (authLoading || pageLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="w-12 h-12 border-4 border-primary-600 border-t-transparent rounded-full animate-spin"></div>
      </div>
    );
  }

  /**
   * ===========================================
   * RENDER
   * ===========================================
   */
  return (
    <div className="max-w-7xl mx-auto px-4 py-8">
      {/* Header */}
      <div className="flex justify-between items-center mb-8">
        <div>
          <h1 className="text-3xl font-bold">Recruiter Dashboard 👔</h1>
          <p className="text-gray-600">Upload and manage internship offers</p>
        </div>
        <button
          onClick={() => setShowUploadForm(!showUploadForm)}
          className="btn-primary"
        >
          {showUploadForm ? 'Cancel' : '+ New Offer'}
        </button>
      </div>

      {/* Alerts */}
      {success && <div className="alert-success">{success}</div>}
      {error && <div className="alert-error">{error}</div>}

      {/* Upload Form */}
      {showUploadForm && (
        <div className="card mb-8">
          <h2 className="text-xl font-semibold mb-4">Create New Offer</h2>

          <form onSubmit={handleSubmit} className="space-y-4">
            <input name="title" value={formData.title} onChange={handleChange} required placeholder="Title" />
            <input name="company" value={formData.company} onChange={handleChange} required placeholder="Company" />
            <textarea name="description" value={formData.description} onChange={handleChange} />
            
            <select name="studentEmail" value={formData.studentEmail} onChange={handleChange} required>
              <option value="">Select a student...</option>
              {students.map((s) => (
                <option key={s._id} value={s.email}>
                  {s.name} ({s.email})
                </option>
              ))}
            </select>

            <input type="file" name="pdf" accept="application/pdf" onChange={handleChange} required />

            <button disabled={uploading} className="btn-primary w-full">
              {uploading ? 'Uploading...' : 'Upload Offer'}
            </button>
          </form>
        </div>
      )}

      {/* Offers */}
      <h2 className="text-xl font-semibold mb-4">Sent Offers</h2>
      {offers.length === 0 ? (
        <p>No offers yet</p>
      ) : (
        offers.map((offer) => (
          <div key={offer._id} className="card mb-3">
            <h3 className="font-semibold">{offer.title}</h3>
            <p>{offer.company}</p>
            <span className={getStatusBadge(offer.status)}>{offer.status}</span>
          </div>
        ))
      )}
    </div>
  );
};

export default RecruiterDashboard;
