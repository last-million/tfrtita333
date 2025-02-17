import axios from 'axios'

const instance = axios.create({
  baseURL: '/',
  headers: {
    'Content-Type': 'application/json'
  }
})

// Add request interceptor to add auth header
instance.interceptors.request.use(
  (config) => {
    const isAuthenticated = localStorage.getItem('isAuthenticated')
    if (isAuthenticated) {
      config.headers.Authorization = `Bearer ${isAuthenticated}`
    }
    return config
  },
  (error) => {
    return Promise.reject(error)
  }
)

// Add response interceptor to handle auth errors
instance.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('isAuthenticated')
      window.location.href = '/login'
    }
    return Promise.reject(error)
  }
)

export default instance
