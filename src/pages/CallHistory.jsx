import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { format } from 'date-fns'
import { 
  ChartBarIcon, 
  PhoneIcon, 
  DocumentTextIcon,
  ClockIcon,
  HeartIcon
} from '@heroicons/react/24/outline'
import { ultravoxClient } from '../lib/ultravox'
import CallTranscriptModal from '../components/CallTranscriptModal'
import CallStatsModal from '../components/CallStatsModal'

export default function CallHistory() {
  const [filters, setFilters] = useState({
    dateRange: { start: '', end: '' },
    status: '',
    intent: '',
    searchTerm: '',
    duration: { min: '', max: '' }
  })

  const [selectedCall, setSelectedCall] = useState(null)
  const [showTranscript, setShowTranscript] = useState(false)
  const [showStats, setShowStats] = useState(false)

  const { data, isLoading } = useQuery(
    ['calls', filters],
    async () => {
      const response = await ultravoxClient.getCallHistory(filters)
      return response
    }
  )

  const getIntentColor = (intent) => {
    switch (intent?.toLowerCase()) {
      case 'interested':
        return 'bg-green-100 text-green-800 dark:bg-green-800 dark:text-green-100'
      case 'not_interested':
        return 'bg-red-100 text-red-800 dark:bg-red-800 dark:text-red-100'
      default:
        return 'bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-100'
    }
  }

  const formatDuration = (seconds) => {
    const minutes = Math.floor(seconds / 60)
    const remainingSeconds = seconds % 60
    return `${minutes}m ${remainingSeconds}s`
  }

  return (
    <div className="space-y-6 dark:bg-gray-900">
      <div className="sm:flex sm:items-center">
        <div className="sm:flex-auto">
          <h1 className="text-2xl font-semibold text-gray-900 dark:text-white">Call History</h1>
          <p className="mt-2 text-sm text-gray-700 dark:text-gray-300">
            View and analyze your call history with detailed information and analytics.
          </p>
        </div>
      </div>

      {/* Advanced Filters */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-6">
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">Search</label>
          <input
            type="text"
            className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm dark:bg-gray-800 dark:border-gray-700 dark:text-white"
            placeholder="Search phone numbers..."
            value={filters.searchTerm}
            onChange={(e) => setFilters(prev => ({ ...prev, searchTerm: e.target.value }))}
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">Start Date</label>
          <input
            type="date"
            className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm dark:bg-gray-800 dark:border-gray-700 dark:text-white"
            value={filters.dateRange.start}
            onChange={(e) => setFilters(prev => ({ 
              ...prev, 
              dateRange: { ...prev.dateRange, start: e.target.value }
            }))}
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">End Date</label>
          <input
            type="date"
            className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm dark:bg-gray-800 dark:border-gray-700 dark:text-white"
            value={filters.dateRange.end}
            onChange={(e) => setFilters(prev => ({ 
              ...prev, 
              dateRange: { ...prev.dateRange, end: e.target.value }
            }))}
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">Status</label>
          <select
            className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm dark:bg-gray-800 dark:border-gray-700 dark:text-white"
            value={filters.status}
            onChange={(e) => setFilters(prev => ({ ...prev, status: e.target.value }))}
          >
            <option value="">All</option>
            <option value="completed">Completed</option>
            <option value="failed">Failed</option>
            <option value="in_progress">In Progress</option>
          </select>
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">Intent</label>
          <select
            className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm dark:bg-gray-800 dark:border-gray-700 dark:text-white"
            value={filters.intent}
            onChange={(e) => setFilters(prev => ({ ...prev, intent: e.target.value }))}
          >
            <option value="">All</option>
            <option value="interested">Interested</option>
            <option value="not_interested">Not Interested</option>
          </select>
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">Duration</label>
          <div className="flex space-x-2">
            <input
              type="number"
              placeholder="Min"
              className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm dark:bg-gray-800 dark:border-gray-700 dark:text-white"
              value={filters.duration.min}
              onChange={(e) => setFilters(prev => ({ 
                ...prev, 
                duration: { ...prev.duration, min: e.target.value }
              }))}
            />
            <input
              type="number"
              placeholder="Max"
              className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm dark:bg-gray-800 dark:border-gray-700 dark:text-white"
              value={filters.duration.max}
              onChange={(e) => setFilters(prev => ({ 
                ...prev, 
                duration: { ...prev.duration, max: e.target.value }
              }))}
            />
          </div>
        </div>
      </div>

      {/* Call List */}
      <div className="mt-8 flex flex-col">
        <div className="-mx-4 overflow-x-auto sm:-mx-6 lg:-mx-8">
          <div className="inline-block min-w-full py-2 align-middle">
            <div className="overflow-hidden shadow ring-1 ring-black ring-opacity-5 md:rounded-lg">
              <table className="min-w-full divide-y divide-gray-300 dark:divide-gray-700">
                <thead className="bg-gray-50 dark:bg-gray-800">
                  <tr>
                    <th className="px-3 py-3.5 text-left text-sm font-semibold text-gray-900 dark:text-white">Date</th>
                    <th className="px-3 py-3.5 text-left text-sm font-semibold text-gray-900 dark:text-white">Phone Number</th>
                    <th className="px-3 py-3.5 text-left text-sm font-semibold text-gray-900 dark:text-white">Duration</th>
                    <th className="px-3 py-3.5 text-left text-sm font-semibold text-gray-900 dark:text-white">Status</th>
                    <th className="px-3 py-3.5 text-left text-sm font-semibold text-gray-900 dark:text-white">Intent</th>
                    <th className="px-3 py-3.5 text-left text-sm font-semibold text-gray-900 dark:text-white">Summary</th>
                    <th className="px-3 py-3.5 text-left text-sm font-semibold text-gray-900 dark:text-white">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-200 dark:divide-gray-700 bg-white dark:bg-gray-900">
                  {isLoading ? (
                    <tr>
                      <td colSpan="7" className="px-3 py-4 text-sm text-gray-500 dark:text-gray-400 text-center">
                        <div className="flex justify-center">
                          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-indigo-500"></div>
                        </div>
                      </td>
                    </tr>
                  ) : (
                    data?.calls.map((call) => (
                      <tr key={call.callId} className="hover:bg-gray-50 dark:hover:bg-gray-800">
                        <td className="whitespace-nowrap px-3 py-4 text-sm text-gray-500 dark:text-gray-400">
                          {format(new Date(call.created), 'MMM d, yyyy HH:mm')}
                        </td>
                        <td className="whitespace-nowrap px-3 py-4 text-sm text-gray-500 dark:text-gray-400">
                          {call.phone_number}
                        </td>
                        <td className="whitespace-nowrap px-3 py-4 text-sm text-gray-500 dark:text-gray-400">
                          {formatDuration(call.duration)}
                        </td>
                        <td className="whitespace-nowrap px-3 py-4 text-sm">
                          <span className={`inline-flex rounded-full px-2 text-xs font-semibold leading-5 ${
                            call.status === 'completed' ? 'bg-green-100 text-green-800 dark:bg-green-800 dark:text-green-100' :
                            call.status === 'failed' ? 'bg-red-100 text-red-800 dark:bg-red-800 dark:text-red-100' :
                            'bg-yellow-100 text-yellow-800 dark:bg-yellow-800 dark:text-yellow-100'
                          }`}>
                            {call.status}
                          </span>
                        </td>
                        <td className="whitespace-nowrap px-3 py-4 text-sm">
                          <span className={`inline-flex rounded-full px-2 text-xs font-semibold leading-5 ${getIntentColor(call.intent)}`}>
                            {call.intent || 'Unknown'}
                          </span>
                        </td>
                        <td className="px-3 py-4 text-sm text-gray-500 dark:text-gray-400">
                          {call.shortSummary}
                        </td>
                        <td className="whitespace-nowrap px-3 py-4 text-sm">
                          <div className="flex space-x-2">
                            <button
                              onClick={() => {
                                setSelectedCall(call)
                                setShowTranscript(true)
                              }}
                              className="text-indigo-600 hover:text-indigo-900 dark:text-indigo-400 dark:hover:text-indigo-300"
                              title="View Transcript"
                            >
                              <DocumentTextIcon className="h-5 w-5" />
                            </button>
                            <button
                              onClick={() => window.open(`/api/calls/${call.callId}/recording`, '_blank')}
                              className="text-indigo-600 hover:text-indigo-900 dark:text-indigo-400 dark:hover:text-indigo-300"
                              title="Play Recording"
                            >
                              <PhoneIcon className="h-5 w-5" />
                            </button>
                            <button
                              onClick={() => {
                                setSelectedCall(call)
                                setShowStats(true)
                              }}
                              className="text-indigo-600 hover:text-indigo-900 dark:text-indigo-400 dark:hover:text-indigo-300"
                              title="View Stats"
                            >
                              <ChartBarIcon className="h-5 w-5" />
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>

      {/* Modals */}
      {showTranscript && selectedCall && (
        <CallTranscriptModal
          call={selectedCall}
          onClose={() => {
            setShowTranscript(false)
            setSelectedCall(null)
          }}
        />
      )}

      {showStats && selectedCall && (
        <CallStatsModal
          call={selectedCall}
          onClose={() => {
            setShowStats(false)
            setSelectedCall(null)
          }}
        />
      )}
    </div>
  )
}
