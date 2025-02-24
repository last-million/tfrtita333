import React from 'react'
import { Link } from 'react-router-dom'
import './Navbar.css'

function Navbar() {
  return (
    <nav className="navbar">
      <div className="navbar-logo">
        <h2>Voice Call AI</h2>
      </div>
      <ul className="navbar-links">
        <li><Link to="/">Dashboard</Link></li>
        <li><Link to="/calls">Call Manager</Link></li>
        <li><Link to="/call-history">Call History</Link></li>
        <li><Link to="/knowledge-base">Knowledge Base</Link></li>
        <li><Link to="/system-config">System Config</Link></li>
        <li><Link to="/auth">Connect Services</Link></li>
      </ul>
    </nav>
  )
}

export default Navbar
