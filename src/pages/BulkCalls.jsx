import { useState } from 'react'
import { useForm } from 'react-hook-form'
import axios from '../lib/axios'

export default function BulkCalls() {
  const { register, handleSubmit, reset } = useForm()
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)

  const onSubmit = async (data) => {
    try {
      setLoading(true)
      const response = await axios.post('/api/bulk-calls', {
        numbers: data.numbers.split('\n').map(n => n.trim()).filter(Boolean),
        message: data.message
      })
      setResult({ success: true, message: `Started ${response.data.count} calls` })
      reset()
    } catch (error) {
      setResult({ success: false, message: error.response?.data?.message || 'Failed to initiate calls' })
    } finally {
      setLoading(false)
    }
  }

  return (
    <div>
      <div className="md:grid md:grid-cols-3 md:gap-6">
        <div className="md:col-span-1">
          <div className="px-4 sm:px-0">
            <h3 className="text-lg font-medium leading-6 text-gray-900">Bulk Call Campaign</h3>
            <p className="mt-1 text-sm text-gray-600">
              Initiate multiple outbound calls simultaneously.
            </p>
          </div>
        </div>

        <div className="mt-5 md:mt-0 md:col-span-2">
          <form onSubmit={handleSubmit(onSubmit)}>
            <div className="shadow sm:rounded-md sm:overflow-hidden">
              <div className="px-4 py-5 bg-white space-y-6 sm:p-6">
                <div>
                  <label className="block text-sm font-medium text-gray-700">Phone Numbers</label>
                  <div className="mt-1">
                    <textarea
                      {...register('numbers', { required: true })}
                      rows={4}
                      className="shadow-sm focus:ring-indigo-500 focus:border-indigo-500 mt-1 block w-full sm:text-sm border border-gray-300 rounded-md"
                      placeholder="Enter phone numbers (one per line)"
                    />
                  </div>
                  <p className="mt-2 text-sm text-gray-500">One phone number per line</p>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700">Initial Message</label>
                  <div className="mt-1">
                    <textarea
                      {...register('message', { required: true })}
                      rows={4}
                      className="shadow-sm focus:ring-indigo-500 focus:border-indigo-500 mt-1 block w-full sm:text-sm border border-gray-300 rounded-md"
                      placeholder="Enter the message for the AI agent to start with"
                    />
                  </div>
                </div>
              </div>

              {result && (
                <div className={`px-4 py-3 ${result.success ? 'bg-green-50' : 'bg-red-50'}`}>
                  <p className={`text-sm ${result.success ? 'text-green-800' : 'text-red-800'}`}>
                    {result.message}
                  </p>
                </div>
              )}

              <div className="px-4 py-3 bg-gray-50 text-right sm:px-6">
                <button
                  type="submit"
                  disabled={loading}
                  className="inline-flex justify-center py-2 px-4 border border-transparent shadow-sm text-sm font-medium rounded-md text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 disabled:opacity-50"
                >
                  {loading ? 'Starting...' : 'Start Campaign'}
                </button>
              </div>
            </div>
          </form>
        </div>
      </div>
    </div>
  )
}
