import { useState } from 'react'
import api from '../api'

export function useGoogleAuth() {
  const [loading, setLoading] = useState(false)

  const initiateAuth = async (service) => {
    setLoading(true)
    try {
      const { data } = await api.get(`/api/auth/google/url?service=${service}`)
      const popup = window.open(
        data.url,
        'Google Auth',
        'width=600,height=600'
      )

      return new Promise((resolve, reject) => {
        window.addEventListener('message', async (event) => {
          if (event.data.type === 'google_auth_success') {
            popup.close()
            try {
              const response = await api.post('/api/auth/google/callback', {
                code: event.data.code,
                service
              })
              resolve(response.data)
            } catch (error) {
              reject(error)
            }
          }
        })
      })
    } catch (error) {
      throw error
    } finally {
      setLoading(false)
    }
  }

  return {
    initiateAuth,
    loading
  }
}
