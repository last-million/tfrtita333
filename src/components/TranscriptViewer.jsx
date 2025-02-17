import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { ultravoxClient } from '../lib/ultravox'

export default function TranscriptViewer({ callId }) {
  const [autoScroll, setAutoScroll] = useState(true)
  
  const { data: transcript, isLoading } = useQuery(
    ['transcript', callId],
    () => ultravoxClient.getCallTranscript(callId),
    {
      enabled: !!callId,
      refetchInterval: 5000 // Refresh every 5 seconds for active calls
    }
  )

  const formatMessage = (message) => {
    const role = message.role === 'MESSAGE_ROLE_AGENT' ? 'Agent' : 'User'
    const className = role === 'Agent' ? 'bg-blue-50' : 'bg-gray-50'
    
    return (
      <div key={message.callStageMessageIndex} className={`p-4 ${className} rounded-lg mb-2`}>
        <div className="font-medium text-gray-900">{role}</div>
        <div className="mt-1 text-gray-600">{message.text}</div>
      </div>
    )
  }

  if (isLoading) {
    return <div>Loading transcript...</div>
  }

  return (
    <div className="bg-white rounded-lg shadow">
      <div className="p-4 border-b border-gray-200">
        <div className="flex justify-between items-center">
          <h3 className="text-lg font-medium text-gray-900">Call Transcript</h3>
          <label className="flex items-center">
            <input
              type="checkbox"
              checked={autoScroll}
              onChange={(e) => setAutoScroll(e.target.checked)}
              className="rounded border-gray-300 text-indigo-600 focus:ring-indigo-500"
            />
            <span className="ml-2 text-sm text-gray-600">Auto-scroll</span>
          </label>
        </div>
      </div>
      
      <div className="p-4 max-h-96 overflow-y-auto">
        {transcript?.results.map(formatMessage)}
      </div>
    </div>
  )
}
