// frontend/src/App.jsx
import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { ThemeProvider } from './context/ThemeContext';
import { LanguageProvider } from './context/LanguageContext';
import { KnowledgeBaseProvider } from './context/KnowledgeBaseContext';
import { AuthProvider } from './context/AuthContext';
import ProtectedRoute from './components/ProtectedRoute';

// Components
import Header from './components/Header';
import Navbar from './components/Navbar';
import Dashboard from './pages/Dashboard';
import CallManager from './pages/CallManager';
import CallHistory from './pages/CallHistory';
import CallDetails from './pages/CallDetails';
import KnowledgeBase from './pages/KnowledgeBase';
import Authentication from './pages/Authentication';
import SystemConfig from './pages/SystemConfig';
import LoginPage from './pages/LoginPage';

// Styles
import './App.css';

const Layout = ({ children }) => {
  return (
    <div className="app-container">
      <div className="top-navbar">
        <div className="app-logo">
          <img src="/logo.svg" alt="Voice Call AI" style={{ height: '30px', marginRight: '10px' }} />
          Voice Call AI
        </div>
        <div className="top-nav-links">
          <a href="/" className="top-nav-link">Dashboard</a>
          <a href="/calls" className="top-nav-link">Call Manager</a>
          <a href="/call-history" className="top-nav-link">Call History</a>
          <a href="/knowledge-base" className="top-nav-link">Knowledge Base</a>
          <a href="/system-config" className="top-nav-link">System Config</a>
          <a href="/auth" className="top-nav-link">Services</a>
        </div>
        <div style={{ marginLeft: 'auto' }}>
          <Header />
        </div>
      </div>
      <div className="content-wrapper">
        <main className="main-content">
          {children}
        </main>
      </div>
    </div>
  );
};

function App() {
  return (
    <AuthProvider>
      <ThemeProvider>
        <LanguageProvider>
          <KnowledgeBaseProvider>
            <Router>
              <Routes>
                {/* Login page - public route */}
                <Route path="/login" element={<LoginPage />} />
                
                {/* Protected routes */}
                <Route path="/" element={
                  <ProtectedRoute>
                    <Layout>
                      <Dashboard />
                    </Layout>
                  </ProtectedRoute>
                } />
                
                <Route path="/calls" element={
                  <ProtectedRoute>
                    <Layout>
                      <CallManager />
                    </Layout>
                  </ProtectedRoute>
                } />
                
                <Route path="/call-history" element={
                  <ProtectedRoute>
                    <Layout>
                      <CallHistory />
                    </Layout>
                  </ProtectedRoute>
                } />
                
                <Route path="/call-details/:callSid" element={
                  <ProtectedRoute>
                    <Layout>
                      <CallDetails />
                    </Layout>
                  </ProtectedRoute>
                } />
                
                <Route path="/knowledge-base" element={
                  <ProtectedRoute>
                    <Layout>
                      <KnowledgeBase />
                    </Layout>
                  </ProtectedRoute>
                } />
                
                <Route path="/auth" element={
                  <ProtectedRoute>
                    <Layout>
                      <Authentication />
                    </Layout>
                  </ProtectedRoute>
                } />
                
                {/* Admin-only routes */}
                <Route path="/system-config" element={
                  <ProtectedRoute adminRequired={true}>
                    <Layout>
                      <SystemConfig />
                    </Layout>
                  </ProtectedRoute>
                } />
                
                {/* User management (admin only) */}
                <Route path="/users" element={
                  <ProtectedRoute adminRequired={true}>
                    <Layout>
                      <SystemConfig />
                    </Layout>
                  </ProtectedRoute>
                } />

                {/* Catch all route */}
                <Route path="*" element={<Navigate to="/" replace />} />
              </Routes>
            </Router>
          </KnowledgeBaseProvider>
        </LanguageProvider>
      </ThemeProvider>
    </AuthProvider>
  );
}

export default App;
