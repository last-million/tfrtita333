import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import api from '../lib/api'
import CallManager from '../components/CallManager'

export default function Dashboard() {
  const { data: stats } = useQuery(['stats'], () => 
    api.get('/api/health').then(res => res.data)
  )

  return (
    <div className="py-6">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <h1 className="text-2xl font-semibold text-gray-900">Dashboard</h1>
        
        <div className="mt-6">
          <div className="bg-white shadow rounded-lg p-4">
            <h2 className="text-lg font-medium text-gray-900">System Status</h2>
            <p className="mt-1 text-sm text-gray-500">
              {stats?.status === 'healthy' ? '✅ System is operational' : '❌ System issues detected'}
            </p>
          </div>
        </div>

        <div className="mt-6">
          <CallManager />
        </div>
      </div>
    </div>
  )
}
