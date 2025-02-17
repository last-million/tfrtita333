import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import api from '../api'

export function useTwilioConfig() {
  const queryClient = useQueryClient()
  const [useEnvConfig, setUseEnvConfig] = useState(true)

  const { data: config, isLoading } = useQuery(
    ['twilio-config'],
    () => api.get('/api/config/twilio').then(res => res.data)
  )

  const updateConfig = useMutation(
    (newConfig) => api.put('/api/config/twilio', newConfig),
    {
      onSuccess: () => {
        queryClient.invalidateQueries(['twilio-config'])
      }
    }
  )

  const toggleConfigSource = async (useEnv) => {
    setUseEnvConfig(useEnv)
    await updateConfig.mutateAsync({ useEnvConfig: useEnv })
  }

  return {
    config,
    isLoading,
    useEnvConfig,
    toggleConfigSource,
    updateConfig: updateConfig.mutate
  }
}
