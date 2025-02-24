import React, { useState } from 'react'
import { Link, useLocation } from 'react-router-dom'
import ThemeToggle from './ThemeToggle'
import './Header.css'
import { useLanguage } from '../context/LanguageContext';
import translations from '../translations';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faBars, faTimes } from '@fortawesome/free-solid-svg-icons';

function Header() {
  const location = useLocation()
  const [activeMenu, setActiveMenu] = useState(location.pathname)
  const { language, setLanguage } = useLanguage();
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);

  const handleLanguageChange = (e) => {
    setLanguage(e.target.value);
    if (e.target.value === 'ar') {
      document.body.classList.add('rtl');
    } else {
      document.body.classList.remove('rtl');
    }
  };

  const toggleMobileMenu = () => {
    setIsMobileMenuOpen(!isMobileMenuOpen);
  };

  const menuItems = [
    { path: '/', label: translations[language].dashboard, icon: '🏠' },
    { path: '/calls', label: translations[language].calls, icon: '📞' },
    { path: '/call-history', label: translations[language].callHistory, icon: '' },
    { path: '/knowledge-base', label: translations[language].knowledge, icon: '🧠' },
    { path: '/auth', label: translations[language].services, icon: '🔗' },
    { path: '/system-config', label: translations[language].settings, icon: '⚙️' }
  ];

  return (
    <header className="app-header">
      <div className="header-logo">
        <span>Voice AI</span>
        <div className="logo-pulse"></div>
      </div>
      <button className="mobile-menu-button" onClick={toggleMobileMenu}>
        <FontAwesomeIcon icon={faBars} />
      </button>
      <nav className={`header-navigation ${isMobileMenuOpen ? 'mobile-menu-open' : ''}`}>
        <div className={`mobile-menu ${isMobileMenuOpen ? 'open' : ''}`}>
          <button className="close-menu-button" onClick={toggleMobileMenu}>
            <FontAwesomeIcon icon={faTimes} />
          </button>
          {menuItems.map((item) => (
            <Link
              key={item.path}
              to={item.path}
              className={`nav-item ${activeMenu === item.path ? 'active' : ''}`}
              onClick={() => {
                setActiveMenu(item.path);
                setIsMobileMenuOpen(false);
              }}
            >
              <span className="nav-icon">{item.icon}</span>
              <span className="nav-label">{item.label}</span>
            </Link>
          ))}
        </div>
        <div className="header-navigation">
          {menuItems.map((item) => (
            <Link
              key={item.path}
              to={item.path}
              className={`nav-item ${activeMenu === item.path ? 'active' : ''}`}
              onClick={() => setActiveMenu(item.path)}
            >
              <span className="nav-icon">{item.icon}</span>
              <span className="nav-label">{item.label}</span>
            </Link>
          ))}
        </div>
      </nav>
      <div className="header-actions">
        <select value={language} onChange={handleLanguageChange}>
          <option value="en">English</option>
          <option value="fr">Français</option>
          <option value="ar">العربية</option>
        </select>
        <ThemeToggle />
      </div>
    </header>
  )
}

export default Header
