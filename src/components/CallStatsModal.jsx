import { useQuery } from '@tanstack/react-query'
import { ultravoxClient } from '../lib/ultravox'
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend
} from 'chart.js'
import { Line } from 'react-chartjs-2'

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend
)

export default function CallStatsModal({ call, onClose }) {
  const { data: stats, isLoading } = useQuery(
    ['callStats', call.callId],
    () => ultravoxClient.getCallDetails(call.callId)
  )

  const formatDuration = (seconds) => {
    const minutes = Math.floor(seconds / 60)
    const remainingSeconds = seconds % 60
    return `${minutes}m ${remainingSeconds}s`
  }

  return (
    <div className="fixed inset-0 bg-gray-500 bg-opacity-75 flex items-center justify-center">
      <div className="bg-white dark:bg-gray-800 rounded-lg p-6 max-w-4xl w-full">
        <div className="flex justify-between items-center mb-4">
          <h3 className="text-lg font-medium text-gray-900 dark:text-white">
            Call Statistics
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

        {isLoading ? (
          <div className="flex justify-center py-4">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-indigo-500"></div>
          </div>
        ) : (
          <div className="space-y-6">
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
              <div className="bg-gray-50 dark:bg-gray-700 p-4 rounded-lg">
                <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400">Duration</h4>
                <p className="mt-1 text-lg font-semibold text-gray-900 dark:text-white">
                  {formatDuration(call.duration)}
                </p>
              </div>
              <div className="bg-gray-50 dark:bg-gray-700 p-4 rounded-lg">
                <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400">Intent</h4>
                <p className="mt-1 text-lg font-semibold text-gray-900 dark:text-white">
                  {call.intent || 'Unknown'}
                </p>
              </div>
              <div className="bg-gray-50 dark:bg-gray-700 p-4 rounded-lg">
                <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400">Status</h4>
                <p className="mt-1 text-lg font-semibold text-gray-900 dark:text-white">
                  {call.status}
                </p>
              </div>
            </div>

            <div className="bg-white dark:bg-gray-900 p-4 rounded-lg">
              <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-4">
                Call Summary
              </h4>
              <p className="text-gray-900 dark:text-white">{call.shortSummary}</p>
            </div>

            {stats?.sentiment && (
              <div className="bg-white dark:bg-gray-900 p-4 rounded-lg">
                <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-4">
                  Sentiment Analysis
                </h4>
                <Line
                  data={{
                    labels: stats.sentiment.map((_, index) => `Segment ${index + 1}`),
                    datasets: [
                      {
                        label: 'Sentiment Score',
                        data: stats.sentiment,
                        borderColor: 'rgb(99, 102, 241)',
                        tension: 0.1
                      }
                    ]
                  }}
                  options={{
                    responsive: true,
                    plugins: {
                      legend: {
                        position: 'top',
                      },
                      title: {
                        display: true,
                        text: 'Sentiment Throughout Call'
                      }
                    },
                    scales: {
                      y: {
                        min: -1,
                        max: 1
                      }
                    }
                  }}
                />
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
