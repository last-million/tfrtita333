import { useQuery, useQueryClient } from '@tanstack/react-query'
import { ultravoxClient } from '../ultravox'
import { handleApiError } from '../api'
import { CALL_STATUSES } from '../constants'

export function useCallHistory(filters, options = {}) {
  const queryClient = useQueryClient()

  return useQuery(
    ['calls', filters],
    async () => {
      try {
        const response = await ultravoxClient.getCallHistory(filters)
        return response
      } catch (error) {
        throw handleApiError(error)
      }
    },
    {
      keepPreviousData: true,
      staleTime: 30000, // 30 seconds
      refetchInterval: (data) => {
        // Refetch every 10 seconds if there are active calls
        const hasActiveCalls = data?.results?.some(
          call => call.status === CALL_STATUSES.IN_PROGRESS
        )
        return hasActiveCalls ? 10000 : false
      },
      ...options,
      onError: (error) => {
        console.error('Call history fetch error:', error)
        options.onError?.(error)
      }
    }
  )
}
