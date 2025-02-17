import axios from 'axios';
import { toast } from 'react-toastify';

const api = axios.create({
  baseURL: '/',
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json'
  }
});

// Request interceptor
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    console.error('Request error:', error);
    return Promise.reject(error);
  }
);

// Response interceptor
api.interceptors.response.use(
  (response) => response,
  (error) => {
    console.error('Response error:', error);
    
    if (error.response?.status === 401) {
      localStorage.removeItem('token');
      window.location.href = '/login';
      return Promise.reject(error);
    }

    // Extract serializable error information
    let errorMessage = 'An error occurred';
    let statusCode = 0;

    if (error.response) {
      errorMessage = error.response.data?.message || errorMessage;
      statusCode = error.response.status;
      console.error('Server responded with error:', error.response.status, error.response.data);
    } else if (error.request) {
      errorMessage = 'No response from server';
      console.error('No response from server:', error.request);
    } else {
      errorMessage = error.message || 'Request setup error';
      console.error('Request setup error:', error.message);
    }

    // Conditionally show toast only in browser environment
    if (typeof window !== 'undefined') {
      toast.error(errorMessage);
    }
    
    // Create a NEW, completely serializable error object
    const serializableError = {
      message: errorMessage,
      status: statusCode,
    };

    return Promise.reject(serializableError);
  }
);

export const handleApiError = (error) => {
  console.error('API Error:', error);
  if (error.response) {
    return {
      status: error.response.status,
      message: error.response.data.message || 'Server error occurred',
      data: error.response.data
    };
  } else if (error.request) {
    return {
      status: 0,
      message: 'No response from server',
      data: null
    };
  } else {
    return {
      status: 0,
      message: error.message || 'Request setup error',
      data: null
    };
  }
};

export default api;
