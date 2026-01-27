/**
 * ===========================================
 * ADMIN DASHBOARD
 * ===========================================
 * 
 * Features:
 * - View audit logs
 * - Monitor security events
 * - System statistics
 */

import React, { useState, useEffect } from 'react';
import api from '../services/api';

const AdminDashboard = () => {
  const [stats, setStats] = useState(null);
  const [logs, setLogs] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('overview');

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    try {
      const [statsRes, logsRes, alertsRes] = await Promise.all([
        api.get('/admin/statistics'),
        api.get('/admin/audit-logs?limit=50'),
        api.get('/admin/security-alerts')
      ]);
      setStats(statsRes.data.data);
      setLogs(logsRes.data.data.logs);
      setAlerts(alertsRes.data.data.alerts);
    } catch (err) {
      console.error('Failed to fetch data:', err);
    } finally {
      setLoading(false);
    }
  };

  const getSeverityBadge = (severity) => {
    const badges = {
      low: 'bg-gray-100 text-gray-800',
      medium: 'bg-yellow-100 text-yellow-800',
      high: 'bg-orange-100 text-orange-800',
      critical: 'bg-red-100 text-red-800'
    };
    return badges[severity] || badges.low;
  };

  const getActionIcon = (action) => {
    if (action.includes('LOGIN')) return '🔑';
    if (action.includes('REGISTER')) return '📝';
    if (action.includes('OTP')) return '📧';
    if (action.includes('OFFER')) return '📄';
    if (action.includes('CRYPTO')) return '🔐';
    if (action.includes('ACCESS')) return '🚪';
    return '📋';
  };

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
          Admin Dashboard 🛡️
        </h1>
        <p className="text-gray-600 mt-2">
          Monitor security events and system activity
        </p>
      </div>

      {/* Tabs */}
      <div className="mb-6 border-b">
        <div className="flex gap-4">
          {['overview', 'logs', 'alerts'].map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`pb-2 px-1 capitalize ${
                activeTab === tab
                  ? 'border-b-2 border-primary-600 text-primary-600 font-medium'
                  : 'text-gray-500 hover:text-gray-700'
              }`}
            >
              {tab === 'alerts' ? `Alerts (${alerts.length})` : tab}
            </button>
          ))}
        </div>
      </div>

      {/* Overview Tab */}
      {activeTab === 'overview' && stats && (
        <div className="space-y-6">
          {/* User Stats */}
          <div>
            <h2 className="text-xl font-semibold mb-4">User Statistics</h2>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="card text-center">
                <p className="text-3xl font-bold text-primary-600">{stats.users.total}</p>
                <p className="text-gray-600">Total Users</p>
              </div>
              <div className="card text-center">
                <p className="text-3xl font-bold text-blue-600">
                  {stats.users.byRole?.student || 0}
                </p>
                <p className="text-gray-600">Students</p>
              </div>
              <div className="card text-center">
                <p className="text-3xl font-bold text-green-600">
                  {stats.users.byRole?.recruiter || 0}
                </p>
                <p className="text-gray-600">Recruiters</p>
              </div>
              <div className="card text-center">
                <p className="text-3xl font-bold text-purple-600">
                  {stats.users.byRole?.admin || 0}
                </p>
                <p className="text-gray-600">Admins</p>
              </div>
            </div>
          </div>

          {/* Offer Stats */}
          <div>
            <h2 className="text-xl font-semibold mb-4">Offer Statistics</h2>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="card text-center">
                <p className="text-3xl font-bold text-gray-900">{stats.offers.total}</p>
                <p className="text-gray-600">Total Offers</p>
              </div>
              <div className="card text-center">
                <p className="text-3xl font-bold text-yellow-600">
                  {stats.offers.byStatus?.pending || 0}
                </p>
                <p className="text-gray-600">Pending</p>
              </div>
              <div className="card text-center">
                <p className="text-3xl font-bold text-green-600">
                  {stats.offers.byStatus?.accepted || 0}
                </p>
                <p className="text-gray-600">Accepted</p>
              </div>
              <div className="card text-center">
                <p className="text-3xl font-bold text-red-600">
                  {stats.offers.byStatus?.rejected || 0}
                </p>
                <p className="text-gray-600">Rejected</p>
              </div>
            </div>
          </div>

          {/* Security Stats */}
          <div>
            <h2 className="text-xl font-semibold mb-4">Security (Last 24 Hours)</h2>
            <div className="grid grid-cols-2 gap-4">
              <div className="card">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-gray-500">Security Alerts</p>
                    <p className="text-2xl font-bold text-orange-600">
                      {stats.security.alertsLast24Hours}
                    </p>
                  </div>
                  <span className="text-3xl">⚠️</span>
                </div>
              </div>
              <div className="card">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-gray-500">Failed Logins</p>
                    <p className="text-2xl font-bold text-red-600">
                      {stats.security.failedLoginsLast24Hours}
                    </p>
                  </div>
                  <span className="text-3xl">🚫</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Audit Logs Tab */}
      {activeTab === 'logs' && (
        <div className="card overflow-hidden">
          <h2 className="text-xl font-semibold mb-4">Recent Audit Logs</h2>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Time</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Action</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">User</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Description</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Severity</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200">
                {logs.map((log) => (
                  <tr key={log._id} className="hover:bg-gray-50">
                    <td className="px-4 py-3 text-sm text-gray-500">
                      {new Date(log.timestamp).toLocaleString()}
                    </td>
                    <td className="px-4 py-3 text-sm">
                      <span className="flex items-center gap-2">
                        {getActionIcon(log.action)}
                        <span className="font-mono text-xs">{log.action}</span>
                      </span>
                    </td>
                    <td className="px-4 py-3 text-sm text-gray-900">
                      {log.userEmail || 'System'}
                    </td>
                    <td className="px-4 py-3 text-sm text-gray-600 max-w-xs truncate">
                      {log.description}
                    </td>
                    <td className="px-4 py-3 text-sm">
                      <span className={`px-2 py-1 rounded-full text-xs ${getSeverityBadge(log.severity)}`}>
                        {log.severity}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Security Alerts Tab */}
      {activeTab === 'alerts' && (
        <div className="space-y-4">
          <h2 className="text-xl font-semibold">Security Alerts (Last 24 Hours)</h2>
          
          {alerts.length === 0 ? (
            <div className="card text-center py-12">
              <span className="text-6xl">✅</span>
              <h3 className="mt-4 text-xl font-medium text-gray-900">No Security Alerts</h3>
              <p className="text-gray-600 mt-2">
                No high-severity security events in the last 24 hours.
              </p>
            </div>
          ) : (
            <div className="space-y-4">
              {alerts.map((alert) => (
                <div key={alert._id} className={`card border-l-4 ${
                  alert.severity === 'critical' ? 'border-red-500' :
                  alert.severity === 'high' ? 'border-orange-500' : 'border-yellow-500'
                }`}>
                  <div className="flex items-start justify-between">
                    <div>
                      <div className="flex items-center gap-2 mb-2">
                        <span className={`px-2 py-1 rounded-full text-xs ${getSeverityBadge(alert.severity)}`}>
                          {alert.severity.toUpperCase()}
                        </span>
                        <span className="font-mono text-sm text-gray-600">{alert.action}</span>
                      </div>
                      <p className="text-gray-800">{alert.description}</p>
                      <div className="mt-2 text-sm text-gray-500">
                        <span>👤 {alert.userEmail || 'Unknown'}</span>
                        <span className="mx-2">•</span>
                        <span>🌐 {alert.ipAddress}</span>
                        <span className="mx-2">•</span>
                        <span>🕐 {new Date(alert.timestamp).toLocaleString()}</span>
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default AdminDashboard;
