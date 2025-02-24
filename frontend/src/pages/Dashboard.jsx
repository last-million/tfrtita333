import React, { useState, useEffect } from 'react'
import './Dashboard.css'
import { api } from '../services/api';

function Dashboard() {
  const [services, setServices] = useState([
    { 
      name: 'Twilio', 
      connected: false, 
      icon: '📞',
      description: 'Voice and SMS communication'
    },
    { 
      name: 'Supabase', 
      connected: false, 
      icon: '🗃️',
      description: 'Database and authentication'
    },
    { 
      name: 'Google Calendar', 
      connected: false, 
      icon: '📅',
      description: 'Meeting scheduling'
    },
    { 
      name: 'Ultravox', 
      connected: false, 
      icon: '🤖',
      description: 'AI voice processing'
    }
  ])

  const [stats, setStats] = useState({
    totalCalls: 0,
    activeServices: 0,
    knowledgeBaseDocuments: 0,
    aiResponseAccuracy: '85%'
  })

  const [recentActivities, setRecentActivities] = useState([
    {
      id: 1,
      type: 'Call',
      description: 'Outbound call to +1234567890',
      timestamp: '2 hours ago'
    },
    {
      id: 2,
      type: 'Document',
      description: 'Vectorized "Company Handbook"',
      timestamp: '4 hours ago'
    }
  ])

  useEffect(() => {
    // Load service connection status from local storage
    const savedConnectionStatus = JSON.parse(localStorage.getItem('serviceConnectionStatus') || '{}');

    // Update the services state based on the saved connection status
    setServices(prevServices => {
      return prevServices.map(service => {
        return {
          ...service,
          connected: !!savedConnectionStatus[service.name] // Check if service is connected
        };
      });
    });

    // Fetch dashboard stats from the backend API
    const fetchDashboardStats = async () => {
      try {
        const response = await api.get('/api/dashboard/stats');
        setStats(response.data);
      } catch (error) {
        console.error("Error fetching dashboard stats:", error);
      }
    };

    fetchDashboardStats();
  }, []);

  return (
    <div className="dashboard-page">
      <div className="dashboard">
        <div className="dashboard-header">
          <h1>Voice Call AI Dashboard</h1>
          <div className="quick-actions">
            <button>New Call</button>
            <button>Upload Document</button>
          </div>
        </div>
        
        <div className="dashboard-grid">
          {/* Services Overview */}
          <div className="dashboard-card services-overview">
            <h3>Connected Services</h3>
            <div className="services-list">
              {services.map((service, index) => (
                <div key={index} className="service-item">
                  <div className="service-info">
                    <span className="service-icon">{service.icon}</span>
                    <div>
                      <strong>{service.name}</strong>
                      <p>{service.description}</p>
                    </div>
                  </div>
                  <span 
                    className={`status-badge ${service.connected ? 'connected' : 'disconnected'}`}
                  >
                    {service.connected ? 'Connected' : 'Disconnect'}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* System Statistics */}
          <div className="dashboard-card system-stats">
            <h3>System Overview</h3>
            <div className="stats-grid">
              <div className="stat-item">
                <h4>Total Calls</h4>
                <p className="stat-value">{stats.totalCalls}</p>
              </div>
              <div className="stat-item">
                <h4>Active Services</h4>
                <p className="stat-value">{stats.activeServices}</p>
              </div>
              <div className="stat-item">
                <h4>Knowledge Base</h4>
                <p className="stat-value">{stats.knowledgeBaseDocuments} Docs</p>
              </div>
              <div className="stat-item">
                <h4>AI Accuracy</h4>
                <p className="stat-value">{stats.aiResponseAccuracy}</p>
              </div>
            </div>
          </div>

          {/* Recent Activities */}
          <div className="dashboard-card recent-activities">
            <h3>Recent Activities</h3>
            {recentActivities.map(activity => (
              <div key={activity.id} className="activity-item">
                <div className="activity-details">
                  <strong>{activity.type}</strong>
                  <p>{activity.description}</p>
                </div>
                <span className="activity-timestamp">{activity.timestamp}</span>
              </div>
            ))}
          </div>

          {/* Quick Links */}
          <div className="dashboard-card quick-links">
            <h3>Quick Links</h3>
            <div className="links-grid">
              <a href="/calls" className="quick-link">
                <span>📞</span>
                Manage Calls
              </a>
              <a href="/knowledge-base" className="quick-link">
                <span>📚</span>
                Knowledge Base
              </a>
              <a href="/auth" className="quick-link">
                <span>🔗</span>
                Connect Services
              </a>
              <a href="/system-config" className="quick-link">
                <span>⚙️</span>
                System Config
              </a>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

export default Dashboard
