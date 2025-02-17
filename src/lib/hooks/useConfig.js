import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import api from '../api'
import { buildSystemPrompt } from '../systemPromptBuilder'

export function useConfig() {
  const queryClient = useQueryClient()

  const { data: config, isLoading, error } = useQuery(
    ['config'],
    () => api.get('/api/config').then(res => res.data)
  )

  const updateConfig = useMutation(
    async (newConfig) => {
      // Build new system prompt based on enabled tools and knowledge base
      const systemPrompt = buildSystemPrompt(newConfig)
      const configWithPrompt = {
        ...newConfig,
        systemPrompt
      }
      
      const response = await api.put('/api/config', configWithPrompt)
      return response.data
    },
    {
      onSuccess: () => {
        queryClient.invalidateQueries(['config'])
      }
    }
  )

  return {
    config,
    isLoading,
    error,
    updateConfig: updateConfig.mutate,
    isUpdating: updateConfig.isLoading
  }
}
