import { useState } from 'react'
import { useForm } from 'react-hook-form'
import { ultravoxClient } from '../lib/ultravox'

export default function BulkCallForm() {
  const { register, handleSubmit, reset } = useForm()
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [result, setResult] = useState(null)

  const onSubmit = async (data) => {
    setIsSubmitting(true)
    try {
      const phoneNumbers = data.numbers.split('\n').map(n => n.trim()).filter(Boolean)
      const results = await Promise.all(
        phoneNumbers.map(phoneNumber => 
          ultravoxClient.createCall(phoneNumber, data.systemPrompt)
        )
      )
      setResult({
        success: true,
        message: `Successfully initiated ${results.length} calls`
      })
      reset()
    } catch (error) {
      setResult({
        success: false,
        message: error.message || 'Failed to initiate calls'
      })
    } finally {
      setIsSubmitting(false)
    }
  }

  return (
    <form onSubmit={handleSubmit(onSubmit)} className="space-y-6">
      <div>
        <label className="block text-sm font-medium text-gray-700">
          Phone Numbers (one per line)
        </label>
        <textarea
          {...register('numbers', { required: true })}
          rows={4}
          className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm"
          placeholder="+1234567890&#10;+0987654321"
        />
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-700">
          System Prompt
        </label>
        <textarea
          {...register('systemPrompt', { required: true })}
          rows={4}
          className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm"
          placeholder="Enter the system prompt for the AI agent..."
        />
      </div>

      {result && (
        <div className={`rounded-md p-4 ${
          result.success ? 'bg-green-50 text-green-800' : 'bg-red-50 text-red-800'
        }`}>
          {result.message}
        </div>
      )}

      <div className="flex justify-end">
        <button
          type="submit"
          disabled={isSubmitting}
          className="inline-flex justify-center rounded-md border border-transparent bg-indigo-600 py-2 px-4 text-sm font-medium text-white shadow-sm hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 disabled:opacity-50"
        >
          {isSubmitting ? 'Initiating Calls...' : 'Start Bulk Calls'}
        </button>
      </div>
    </form>
  )
}
