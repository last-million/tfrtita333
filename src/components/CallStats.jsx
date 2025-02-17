import { useQuery } from '@tanstack/react-query'
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts'
import { ultravoxClient } from '../lib/ultravox'

export default function CallStats() {
  const { data: stats, isLoading } = useQuery(['callStats'], async () => {
    const calls = await ultravoxClient.getCallHistory()
    
    // Process calls data to generate stats
    const totalCalls = calls.results.length
    const completedCalls = calls.results.filter(call => call.endReason === 'completed').length
    const successRate = ((completedCalls / totalCalls) * 100).toFixed(1)
    
    // Generate call volume data
    const callVolume = processCallVolumeData(calls.results)
    
    return {
      totalCalls,
      completedCalls,
      successRate,
      callVolume
    }
  })

  if (isLoading) {
    return <div>Loading stats...</div>
  }

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 gap-5 sm:grid-cols-3">
        <StatCard
          title="Total Calls"
          value={stats.totalCalls}
          icon={<PhoneIcon className="h-6 w-6" />}
        />
        <StatCard
          title="Completed Calls"
          value={stats.completedCalls}
          icon={<CheckCircleIcon className="h-6 w-6" />}
        />
        <StatCard
          title="Success Rate"
          value={`${stats.successRate}%`}
          icon={<ChartBarIcon className="h-6 w-6" />}
        />
      </div>

      <div className="bg-white p-6 rounded-lg shadow">
        <h3 className="text-lg font-medium text-gray-900 mb-4">Call Volume</h3>
        <ResponsiveContainer width="100%" height={300}>
          <BarChart data={stats.callVolume}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey="date" />
            <YAxis />
            <Tooltip />
            <Legend />
            <Bar dataKey="calls" fill="#4F46E5" />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}

function StatCard({ title, value, icon }) {
  return (
    <div className="bg-white overflow-hidden shadow rounded-lg">
      <div className="p-5">
        <div className="flex items-center">
          <div className="flex-shrink-0 text-indigo-600">
            {icon}
          </div>
          <div className="ml-5 w-0 flex-1">
            <dl>
              <dt className="text-sm font-medium text-gray-500 truncate">{title}</dt>
              <dd className="text-lg font-medium text-gray-900">{value}</dd>
            </dl>
          </div>
        </div>
      </div>
    </div>
  )
}

function processCallVolumeData(calls) {
  // Group calls by date and count
  const volumeByDate = calls.reduce((acc, call) => {
    const date = new Date(call.created).toLocaleDateString()
    acc[date] = (acc[date] || 0) + 1
    return acc
  }, {})

  // Convert to chart data format
  return Object.entries(volumeByDate).map(([date, calls]) => ({
    date,
    calls
  }))
}
