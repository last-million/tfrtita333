import { useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import api from '../api';

export function useAuth() {
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);
  const navigate = useNavigate();

  const login = useCallback(async (username, password) => {
    setIsLoading(true);
    setError(null);
    try {
      const response = await api.post('/api/auth/login', { username, password });
      localStorage.setItem('token', response.data.token);
      navigate('/');
      return response.data;
    } catch (error) {
      setError(error.response?.data?.message || 'Login failed');
      throw error;
    } finally {
      setIsLoading(false);
    }
  }, [navigate]);

  const logout = useCallback(() => {
    localStorage.removeItem('token');
    navigate('/login');
  }, [navigate]);

  return {
    login,
    logout,
    isLoading,
    error
  };
}
