import React, { useState, useEffect } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import './CallHistory.css'
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faPhone, faClock, faUser, faFileAudio, faFileText, faDollarSign, faList, faCalendar, faEnvelope } from '@fortawesome/free-solid-svg-icons';

function CallHistory() {
  const [calls, setCalls] = useState([
    {
      id: 1,
      call_sid: 'CA123',
      number: '+1234567890',
      type: 'Outbound',
      duration: '5m 30s',
      status: 'Completed',
      timestamp: '2023-08-15 10:30 AM',
      agent: 'John Doe',
      client: 'Jane Smith',
      summary: 'Discussed website redesign and scheduling a follow-up meeting.',
      recording_url: 'https://example.com/recording1.mp3',
      transcription: 'Agent: Hello, this is John from our agency...\nClient: Hi John, I am calling about...\nAgent: We can offer you a 10% discount...\nClient: That sounds great!',
      cost: '$0.50',
      segments: 3,
      scheduled_meeting: '2023-08-20 11:00 AM',
      email_sent: 'Yes',
      email_address: 'john.doe@example.com',
      email_text: 'Subject: Meeting Summary\n\nHi Jane,\nIt was great speaking with you today. Here is a summary of our discussion...',
      email_received: 'No',
      email_received_text: null,
      ultravox_cost: (5.5 * 0.05).toFixed(2)
    },
    {
      id: 2,
      call_sid: 'CA456',
      number: '+9876543210',
      type: 'Inbound',
      duration: '2m 45s',
      status: 'Missed',
      timestamp: '2023-08-14 03:15 PM',
      agent: 'Alice Smith',
      client: 'Bob Johnson',
      summary: 'Missed call, no message left.',
      recording_url: null,
      transcription: null,
      cost: '$0.00',
      segments: 0,
      scheduled_meeting: null,
      email_sent: 'No',
      email_address: null,
      email_text: null,
      email_received: 'Yes',
      email_received_text: 'Subject: Re: Missed Call\n\nHi Alice,\nI am sorry I missed your call. Please call me back at your convenience.',
      ultravox_cost: 0
    }
  ])

  const [filter, setFilter] = useState({
    type: 'all',
    status: 'all'
  })

  const navigate = useNavigate();

  const handleCallClick = (callSid) => {
    navigate(`/call-history/${callSid}`);
  };

  const filteredCalls = calls.filter(call => {
    const typeMatch = filter.type === 'all' || call.type.toLowerCase() === filter.type;
    const statusMatch = filter.status === 'all' || call.status.toLowerCase() === filter.status;
    return typeMatch && statusMatch;
  });

  return (
    <div className="call-history-page">
      <h1>Call History</h1>
      
      <div className="filters">
        <select 
          value={filter.type} 
          onChange={(e) => setFilter({...filter, type: e.target.value})}
        >
          <option value="all">All Types</option>
          <option value="inbound">Inbound</option>
          <option value="outbound">Outbound</option>
        </select>
        
        <select 
          value={filter.status} 
          onChange={(e) => setFilter({...filter, status: e.target.value})}
        >
          <option value="all">All Statuses</option>
          <option value="completed">Completed</option>
          <option value="missed">Missed</option>
        </select>
      </div>

      <table className="call-history-table">
        <thead>
          <tr>
            <th>Number</th>
            <th>Type</th>
            <th>Duration</th>
            <th>Status</th>
            <th>Timestamp</th>
          </tr>
        </thead>
        <tbody>
          {filteredCalls.map(call => (
            <tr key={call.call_sid} onClick={() => handleCallClick(call.call_sid)}>
              <td>{call.number}</td>
              <td>{call.type}</td>
              <td>{call.duration}</td>
              <td>{call.status}</td>
              <td>{call.timestamp}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function CallDetail() {
  const { callSid } = useParams();
  const navigate = useNavigate();
  const [call, setCall] = useState(null);
  const [showTranscription, setShowTranscription] = useState(false);

  useEffect(() => {
    // Simulate fetching call details from a database
    // In a real application, you would use the callSid to fetch the data
    const mockCall = {
      call_sid: 'CA123',
      number: '+1234567890',
      type: 'Outbound',
      duration: '5m 30s',
      status: 'Completed',
      timestamp: '2023-08-15 10:30 AM',
      agent: 'John Doe',
      client: 'Jane Smith',
      summary: 'Discussed website redesign and scheduling a follow-up meeting.',
      recording_url: 'https://example.com/recording1.mp3',
      transcription: 'Agent: Hello, this is John from our agency...\nClient: Hi John, I am calling about...\nAgent: We can offer you a 10% discount...\nClient: That sounds great!',
      cost: '$0.50',
      segments: 3,
      scheduled_meeting: '2023-08-20 11:00 AM',
      email_sent: 'Yes',
      email_address: 'john.doe@example.com',
      email_text: 'Subject: Meeting Summary\n\nHi Jane,\nIt was great speaking with you today. Here is a summary of our discussion...',
      email_received: 'No',
      email_received_text: 'Subject: Re: Missed Call\n\nHi Alice,\nI am sorry I missed your call. Please call me back at your convenience.',
      ultravox_cost: (5.5 * 0.05).toFixed(2)
    };
    setCall(mockCall);
  }, [callSid]);

  if (!call) {
    return <div>Loading...</div>;
  }

  const toggleTranscription = () => {
    setShowTranscription(!showTranscription);
  };

  return (
    <div className="call-detail-page">
      <div className="call-detail-header">
        <h2>Call Details</h2>
        <button className="back-button" onClick={() => navigate('/call-history')}>
          Back to Call History
        </button>
      </div>

      <div className="call-detail-content">
        <div className="call-detail-section horizontal">
          <div className="call-detail-card">
            <h3>Call Information</h3>
            <div className="call-detail-item">
              <span className="call-detail-label">
                <FontAwesomeIcon icon={faPhone} className="call-detail-icon" />
                Call SID:
              </span>
              <span className="call-detail-value">{call.call_sid}</span>
            </div>
            <div className="call-detail-item">
              <span className="call-detail-label">
                <FontAwesomeIcon icon={faPhone} className="call-detail-icon" />
                Number:
              </span>
              <span className="call-detail-value">{call.number}</span>
            </div>
            <div className="call-detail-item">
              <span className="call-detail-label">
                <FontAwesomeIcon icon={faList} className="call-detail-icon" />
                Type:
              </span>
              <span className="call-detail-value">{call.type}</span>
            </div>
            <div className="call-detail-item">
              <span className="call-detail-label">
                <FontAwesomeIcon icon={faClock} className="call-detail-icon" />
                Duration:
              </span>
              <span className="call-detail-value">{call.duration}</span>
            </div>
            <div className="call-detail-item">
              <span className="call-detail-label">
                <FontAwesomeIcon icon={faList} className="call-detail-icon" />
                Status:
              </span>
              <span className="call-detail-value">{call.status}</span>
            </div>
            <div className="call-detail-item">
              <span className="call-detail-label">
                <FontAwesomeIcon icon={faClock} className="call-detail-icon" />
                Timestamp:
              </span>
              <span className="call-detail-value">{call.timestamp}</span>
            </div>
          </div>

          <div className="call-detail-card">
            <h3>Agent &amp; Client Details</h3>
            <div className="call-detail-item">
              <span className="call-detail-label">
                <FontAwesomeIcon icon={faUser} className="call-detail-icon" />
                Agent:
              </span>
              <span className="call-detail-value">{call.agent}</span>
            </div>
            <div className="call-detail-item">
              <span className="call-detail-label">
                <FontAwesomeIcon icon={faUser} className="call-detail-icon" />
                Client:
              </span>
              <span className="call-detail-value">{call.client}</span>
            </div>
          </div>
        </div>

        <div className="call-detail-section">
          <div className="call-detail-card">
            <h3>Call Summary</h3>
            <div className="call-detail-item">
              <span className="call-detail-label">Summary:</span>
              <span className="call-detail-value">{call.summary}</span>
            </div>
            <div className="call-detail-item">
              <span className="call-detail-label">
                <FontAwesomeIcon icon={faFileAudio} className="call-detail-icon" />
                Recording:
              </span>
              <span className="call-detail-value">
                {call.recording_url ? (
                  <audio controls className="audio-player">
                    <source src={call.recording_url} type="audio/mp3" />
                    Your browser does not support the audio element.
                  </audio>
                ) : (
                  'No recording available'
                )}
              </span>
            </div>
            <div className="call-detail-item">
              <span className="call-detail-label">
                <FontAwesomeIcon icon={faFileText} className="call-detail-icon" />
                Transcription:
              </span>
              <span className="call-detail-value">
                <button className="show-transcription-button" onClick={toggleTranscription}>
                  {showTranscription ? 'Hide Transcription' : 'Show Transcription'}
                </button>
              </span>
            </div>
            {showTranscription && (
              <div className="call-detail-item">
                <div className="transcription-container">
                  <div className="transcription-text">
                    {call.transcription}
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>

        <div className="call-detail-section">
          <div className="call-detail-card">
            <h3>Technical Details</h3>
            <div className="call-detail-grid">
              <div className="call-detail-item">
                <span className="call-detail-label">
                  <FontAwesomeIcon icon={faDollarSign} className="call-detail-icon" />
                  Twilio Cost:
                </span>
                <span className="call-detail-value">{call.cost}</span>
              </div>
               <div className="call-detail-item">
                <span className="call-detail-label">
                  <FontAwesomeIcon icon={faDollarSign} className="call-detail-icon" />
                  Ultravox Cost:
                </span>
                <span className="call-detail-value">${call.ultravox_cost}</span>
              </div>
              <div className="call-detail-item">
                <span className="call-detail-label">
                  <FontAwesomeIcon icon={faList} className="call-detail-icon" />
                  Segments:
                </span>
                <span className="call-detail-value">{call.segments}</span>
              </div>
              <div className="call-detail-item">
                <span className="call-detail-label">
                  <FontAwesomeIcon icon={faCalendar} className="call-detail-icon" />
                  Scheduled Meeting:
                </span>
                <span className="call-detail-value">
                  {call.scheduled_meeting ? `Yes (${call.scheduled_meeting})` : 'No'}
                </span>
              </div>
              <div className="call-detail-item">
                <span className="call-detail-label">
                  <FontAwesomeIcon icon={faEnvelope} className="call-detail-icon" />
                  Email Sent:
                </span>
                <span className="call-detail-value">
                  {call.email_sent === 'Yes' ? `Yes (${call.email_address})` : 'No'}
                  {call.email_sent === 'Yes' && (
                    <div className="transcription-text">
                      {call.email_text}
                    </div>
                  )}
                </span>
              </div>
               <div className="call-detail-item">
                <span className="call-detail-label">
                  <FontAwesomeIcon icon={faEnvelope} className="call-detail-icon" />
                  Email Received:
                </span>
                <span className="call-detail-value">
                  {call.email_received === 'Yes' ? `Yes` : 'No'}
                   {call.email_received === 'Yes' && (
                    <div className="transcription-text">
                      {call.email_received_text}
                    </div>
                  )}
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default CallHistory
export { CallDetail }
