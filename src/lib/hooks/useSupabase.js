import { useState, useEffect } from 'react'
import { createClient } from '@supabase/supabase-js'
import api from '../api'

export function useSupabase() {
  const [client, setClient] = useState(null)
  const [tables, setTables] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const initSupabase = async () => {
      try {
        const config = await api.get('/api/config/supabase')
        if (config.data?.url && config.data?.apiKey) {
          const supabase = createClient(config.data.url, config.data.apiKey)
          setClient(supabase)
          
          // Fetch tables
          const { data: tableData } = await supabase.rpc('get_tables')
          setTables(tableData || [])
        }
      } catch (error) {
        console.error('Supabase initialization error:', error)
      } finally {
        setLoading(false)
      }
    }

    initSupabase()
  }, [])

  const vectorizeTable = async (tableId) => {
    try {
      await api.post('/api/vectorize', { tableId })
    } catch (error) {
      console.error('Vectorization error:', error)
      throw error
    }
  }

  return {
    client,
    tables,
    loading,
    vectorizeTable
  }
}
