import { useState, useEffect } from 'react'
import { useAuth } from '../lib/hooks/useAuth'
import api from '../lib/api'
import { toast } from 'react-toastify'

export default function Profile() {
  const { user, logout } = useAuth()
  const [profile, setProfile] = useState(null)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState(null)
  const [isEditing, setIsEditing] = useState(false)
  const [updatedName, setUpdatedName] = useState('')

  useEffect(() => {
    const fetchProfile = async () => {
      setIsLoading(true)
      setError(null)
      try {
        const response = await api.get('/api/profile')
        setProfile(response.data)
        setUpdatedName(response.data.name)
      } catch (error) {
        setError(error.message || 'Failed to load profile')
      } finally {
        setIsLoading(false)
      }
    }

    fetchProfile()
  }, [])

  const handleUpdateName = async () => {
    setIsLoading(true)
    setError(null)
    try {
      await api.put('/api/profile', { name: updatedName })
      setProfile({ ...profile, name: updatedName })
      toast.success('Profile updated successfully')
      setIsEditing(false)
    } catch (error) {
      setError(error.message || 'Failed to update profile')
      toast.error(error.message || 'Failed to update profile')
    } finally {
      setIsLoading(false)
    }
  }

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-lg">Loading profile...</div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-red-500">Error: {error}</div>
      </div>
    )
  }

  return (
    <div className="max-w-3xl mx-auto py-10 px-4 sm:px-6 lg:px-8">
      <h1 className="text-3xl font-extrabold text-gray-900 dark:text-white">Your Profile</h1>
      <div className="mt-6 bg-white dark:bg-gray-800 shadow overflow-hidden sm:rounded-md">
        <div className="px-4 py-5 sm:p-6">
          <dl className="grid grid-cols-1 gap-x-4 gap-y-8 sm:grid-cols-2">
            <div className="sm:col-span-1">
              <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Email</dt>
              <dd className="mt-1 text-sm text-gray-900 dark:text-gray-300">{profile?.email}</dd>
            </div>
            <div className="sm:col-span-1">
              <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Role</dt>
              <dd className="mt-1 text-sm text-gray-900 dark:text-gray-300">{profile?.role}</dd>
            </div>
            <div className="sm:col-span-1">
              <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Last Login</dt>
              <dd className="mt-1 text-sm text-gray-900 dark:text-gray-300">
                {profile?.lastLogin ? new Date(profile.lastLogin).toLocaleString() : 'Never'}
              </dd>
            </div>
            <div className="sm:col-span-2">
              <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Name</dt>
              {isEditing ? (
                <div className="mt-1 flex rounded-md shadow-sm">
                  <input
                    type="text"
                    className="form-input block w-full rounded-none rounded-l-md transition duration-150 ease-in-out sm:text-sm sm:leading-5"
                    value={updatedName}
                    onChange={(e) => setUpdatedName(e.target.value)}
                  />
                  <span className="inline-flex items-center px-3 rounded-r-md border border-l-0 border-gray-300 bg-gray-50 text-gray-500 sm:text-sm">
                    <button
                      onClick={handleUpdateName}
                      className="text-indigo-600 hover:text-indigo-900 focus:outline-none focus:shadow-outline"
                    >
                      Save
                    </button>
                  </span>
                </div>
              ) : (
                <div className="mt-1 flex justify-between items-center">
                  <dd className="text-sm text-gray-900 dark:text-gray-300">{profile?.name}</dd>
                  <button
                    onClick={() => setIsEditing(true)}
                    className="text-indigo-600 hover:text-indigo-900 focus:outline-none focus:shadow-outline"
                  >
                    Edit
                  </button>
                </div>
              )}
            </div>
          </dl>
        </div>
        <div className="bg-gray-50 dark:bg-gray-700 px-4 py-4 sm:px-6">
          <button
            onClick={logout}
            className="inline-flex items-center px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 hover:bg-gray-50 dark:hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-indigo-500"
          >
            Sign Out
          </button>
        </div>
      </div>
    </div>
  )
}
