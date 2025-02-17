import { useQuery } from '@tanstack/react-query'
import { ultravoxClient } from '../lib/ultravox'

export default function CallTranscriptModal({ call, onClose }) {
  const { data: transcript, isLoading } = useQuery(
    ['transcript', call.callId],
    () => ultravoxClient.getCallTranscript(call.callId)
  )

  return (
    <div className="fixed inset-0 bg-gray-500 bg-opacity-75 flex items-center justify-center">
      <div className="bg-white dark:bg-gray-800 rounded-lg p-6 max-w-4xl w-full max-h-[90vh] overflow-hidden">
        <div className="flex justify-between items-center mb-4">
          <h3 className="text-lg font-medium text-gray-900 dark:text-white">
            Call Transcript
          </h3>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-gray-500 dark:text-gray-300 dark:hover:text-gray-200"
          >
            <span className="sr-only">Close</span>
            <svg className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
        
        <div className="overflow-y-auto max-h-[calc(90vh-8rem)]">
          {isLoading ? (
            <div className="flex justify-center py-4">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-indigo-500"></div>
            </div>
          ) : (
            <div className="space-y-4">
              {transcript?.results.map((message, index) => (
                <div
                  key={index}
                  className={`p-4 rounded-lg ${
                    message.role === 'MESSAGE_ROLE_AGENT'
                      ? 'bg-indigo-50 dark:bg-indigo-900'
                      : 'bg-gray-50 dark:bg-gray-700'
                  }`}
                >
                  <div className="font-medium text-gray-900 dark:text-white">
                    {message.role === 'MESSAGE_ROLE_AGENT' ? 'Agent' : 'User'}
                  </div>
                  <div className="mt-1 text-gray-600 dark:text-gray-300">{message.text}</div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
