import { Routes, Route } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { ToastContainer } from 'react-toastify'
import 'react-toastify/dist/ReactToastify.css'
import Dashboard from './pages/Dashboard'
import Login from './pages/Login'
import Layout from './components/Layout'
import ErrorBoundary from './lib/errorBoundary'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      cacheTime: 1000 * 60 * 60 * 24, // 24 hours
      onError: () => {
        // Suppress all errors silently
      },
    },
  },
})

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <ErrorBoundary>
        <div className="min-h-screen bg-gray-100">
          <Routes>
            <Route path="/login" element={<Login />} />
            <Route path="/" element={<Layout />}>
              <Route index element={<Dashboard />} />
            </Route>
          </Routes>
          <ToastContainer />
        </div>
      </ErrorBoundary>
    </QueryClientProvider>
  )
}

export default App
