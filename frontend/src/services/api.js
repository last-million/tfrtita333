import axios from 'axios';

// Base API configuration
const API_URL = import.meta.env.VITE_API_URL || 'https://ajingolik.fun/api';

// Create axios instance with default config
const axiosInstance = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Add request interceptor for authentication
axiosInstance.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('auth_token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Module exports
export const api = {
  // Authentication endpoints
  auth: {
    login: (credentials) => axiosInstance.post('/auth/login', credentials),
    register: (userData) => axiosInstance.post('/auth/register', userData),
    logout: () => axiosInstance.post('/auth/logout'),
    refreshToken: () => axiosInstance.post('/auth/refresh'),
    resetPassword: (email) => axiosInstance.post('/auth/reset-password', { email }),
  },

  // User management
  users: {
    getCurrent: () => axiosInstance.get('/users/me'),
    update: (userData) => axiosInstance.put('/users/me', userData),
    getAll: () => axiosInstance.get('/users'),
    getById: (id) => axiosInstance.get(`/users/${id}`),
    create: (userData) => axiosInstance.post('/users', userData),
    updateById: (id, userData) => axiosInstance.put(`/users/${id}`, userData),
    delete: (id) => axiosInstance.delete(`/users/${id}`),
  },

  // Call management
  calls: {
    getAll: (params) => axiosInstance.get('/calls', { params }),
    getById: (id) => axiosInstance.get(`/calls/${id}`),
    create: (callData) => axiosInstance.post('/calls', callData),
    update: (id, callData) => axiosInstance.put(`/calls/${id}`, callData),
    delete: (id) => axiosInstance.delete(`/calls/${id}`),
    getTranscript: (id) => axiosInstance.get(`/calls/${id}/transcript`),
    getAnalysis: (id) => axiosInstance.get(`/calls/${id}/analysis`),
    getActions: (id) => axiosInstance.get(`/calls/${id}/actions`),
  },

  // Knowledge base
  knowledge: {
    getDocuments: () => axiosInstance.get('/knowledge-base/documents'),
    getDocument: (id) => axiosInstance.get(`/knowledge-base/documents/${id}`),
    createDocument: (doc) => axiosInstance.post('/knowledge-base/documents', doc),
    updateDocument: (id, doc) => axiosInstance.put(`/knowledge-base/documents/${id}`, doc),
    deleteDocument: (id) => axiosInstance.delete(`/knowledge-base/documents/${id}`),
    searchDocuments: (query) => axiosInstance.get('/knowledge-base/search', { params: { query } }),
  },
  
  // Google Drive integration
  drive: {
    listFiles: () => axiosInstance.get('/google/drive/files'),
    getFile: (fileId) => axiosInstance.get(`/google/drive/files/${fileId}`),
    importFile: (fileId) => axiosInstance.post('/google/drive/import', { fileId }),
    getAuth: () => axiosInstance.get('/google/auth'),
  },
  
  // Supabase integration
  supabase: {
    listTables: () => axiosInstance.get('/supabase/tables'),
    getTable: (tableName) => axiosInstance.get(`/supabase/tables/${tableName}`),
    importTable: (tableName) => axiosInstance.post('/supabase/import', { tableName }),
    getConfig: () => axiosInstance.get('/supabase/config'),
  },
  
  // Service connections
  services: {
    getConnections: () => axiosInstance.get('/services/connections'),
    updateConnection: (service, config) => axiosInstance.put(`/services/${service}`, config),
    testConnection: (service) => axiosInstance.post(`/services/${service}/test`),
  },
  
  // System settings and configuration
  system: {
    getConfig: () => axiosInstance.get('/system/config'),
    updateConfig: (config) => axiosInstance.put('/system/config', config),
    getStatus: () => axiosInstance.get('/system/status'),
    getLogs: (params) => axiosInstance.get('/system/logs', { params }),
  },
  
  // Data export
  export: {
    toCSV: (params) => axiosInstance.get('/export/csv', { params, responseType: 'blob' }),
    toJSON: (params) => axiosInstance.get('/export/json', { params, responseType: 'blob' }),
    scheduleSync: (config) => axiosInstance.post('/export/sync', config),
    getSyncJobs: () => axiosInstance.get('/export/sync/jobs'),
  },
  
  // Health check
  health: () => axiosInstance.get('/health'),
};

export default api;
