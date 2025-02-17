import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { toast } from 'react-toastify'
import api from '../lib/api'
import { handleApiError } from '../lib/api'
import { useAuth } from '../lib/hooks/useAuth'

export default function UserManagement() {
  const [showNewUserForm, setShowNewUserForm] = useState(false)
  const [editingUser, setEditingUser] = useState(null)
  const queryClient = useQueryClient()
  const { user: currentUser } = useAuth()

  const { data: users, isLoading } = useQuery(
    ['users'],
    async () => {
      try {
        const response = await api.get('/api/users')
        return response.data
      } catch (error) {
        throw handleApiError(error)
      }
    }
  )

  const createUser = useMutation(
    async (userData) => {
      const response = await api.post('/api/users', userData)
      return response.data
    },
    {
      onSuccess: () => {
        queryClient.invalidateQueries(['users'])
        setShowNewUserForm(false)
        toast.success('User created successfully')
      },
      onError: (error) => {
        toast.error(handleApiError(error).message)
      }
    }
  )

  const updateUser = useMutation(
    async (userData) => {
      const response = await api.put(`/api/users/${userData.id}`, userData)
      return response.data
    },
    {
      onSuccess: () => {
        queryClient.invalidateQueries(['users'])
        setEditingUser(null)
        toast.success('User updated successfully')
      },
      onError: (error) => {
        toast.error(handleApiError(error).message)
      }
    }
  )

  const toggleUserStatus = useMutation(
    async (userId) => {
      const response = await api.patch(`/api/users/${userId}/toggle-status`)
      return response.data
    },
    {
      onSuccess: () => {
        queryClient.invalidateQueries(['users'])
        toast.success('User status updated successfully')
      },
      onError: (error) => {
        toast.error(handleApiError(error).message)
      }
    }
  )

  const deleteUser = useMutation(
    async (userId) => {
      const response = await api.delete(`/api/users/${userId}`)
      return response.data
    },
    {
      onSuccess: () => {
        queryClient.invalidateQueries(['users'])
        toast.success('User deleted successfully')
      },
      onError: (error) => {
        toast.error(handleApiError(error).message)
      }
    }
  )

  const handleDeleteUser = (userId) => {
    if (window.confirm('Are you sure you want to delete this user?')) {
      deleteUser.mutate(userId)
    }
  }

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-600"></div>
      </div>
    )
  }

  return (
    <div>
      <div className="sm:flex sm:items-center">
        <div className="sm:flex-auto">
          <h1 className="text-2xl font-semibold text-gray-900">Users</h1>
          <p className="mt-2 text-sm text-gray-700">
            Manage user access and permissions for the system.
          </p>
        </div>
        {currentUser?.role === 'admin' && (
          <div className="mt-4 sm:mt-0 sm:ml-16 sm:flex-none">
            <button
              onClick={() => setShowNewUserForm(true)}
              className="inline-flex items-center justify-center rounded-md border border-transparent bg-indigo-600 px-4 py-2 text-sm font-medium text-white shadow-sm hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 sm:w-auto"
            >
              Add user
            </button>
          </div>
        )}
      </div>

      <div className="mt-8 flex flex-col">
        <div className="-mx-4 -my-2 overflow-x-auto sm:-mx-6 lg:-mx-8">
          <div className="inline-block min-w-full py-2 align-middle md:px-6 lg:px-8">
            <div className="overflow-hidden shadow ring-1 ring-black ring-opacity-5 md:rounded-lg">
              <table className="min-w-full divide-y divide-gray-300">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-3 py-3.5 text-left text-sm font-semibold text-gray-900">Name</th>
                    <th className="px-3 py-3.5 text-left text-sm font-semibold text-gray-900">Email</th>
                    <th className="px-3 py-3.5 text-left text-sm font-semibold text-gray-900">Role</th>
                    <th className="px-3 py-3.5 text-left text-sm font-semibold text-gray-900">Status</th>
                    <th className="px-3 py-3.5 text-left text-sm font-semibold text-gray-900">Last Login</th>
                    <th className="relative py-3.5 pl-3 pr-4 sm:pr-6">
                      <span className="sr-only">Actions</span>
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-200 bg-white">
                  {users?.map((user) => (
                    <tr key={user.id}>
                      <td className="whitespace-nowrap px-3 py-4 text-sm text-gray-900">
                        {user.name}
                      </td>
                      <td className="whitespace-nowrap px-3 py-4 text-sm text-gray-500">
                        {user.email}
                      </td>
                      <td className="whitespace-nowrap px-3 py-4 text-sm text-gray-500">
                        <span className={`inline-flex rounded-full px-2 text-xs font-semibold leading-5 ${
                          user.role === 'admin' ? 'bg-purple-100 text-purple-800' : 'bg-blue-100 text-blue-800'
                        }`}>
                          {user.role}
                        </span>
                      </td>
                      <td className="whitespace-nowrap px-3 py-4 text-sm">
                        <span className={`inline-flex rounded-full px-2 text-xs font-semibold leading-5 ${
                          user.active ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'
                        }`}>
                          {user.active ? 'Active' : 'Inactive'}
                        </span>
                      </td>
                      <td className="whitespace-nowrap px-3 py-4 text-sm text-gray-500">
                        {user.lastLogin ? new Date(user.lastLogin).toLocaleString() : 'Never'}
                      </td>
                      <td className="relative whitespace-nowrap py-4 pl-3 pr-4 text-right text-sm font-medium sm:pr-6">
                        {currentUser?.role === 'admin' && currentUser?.id !== user.id && (
                          <div className="flex justify-end space-x-2">
                            <button
                              onClick={() => setEditingUser(user)}
                              className="text-indigo-600 hover:text-indigo-900"
                            >
                              Edit
                            </button>
                            <button
                              onClick={() => toggleUserStatus.mutate(user.id)}
                              className="text-blue-600 hover:text-blue-900"
                            >
                              {user.active ? 'Deactivate' : 'Activate'}
                            </button>
                            <button
                              onClick={() => handleDeleteUser(user.id)}
                              className="text-red-600 hover:text-red-900"
                            >
                              Delete
                            </button>
                          </div>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>

      {/* User Form Modal */}
      {(showNewUserForm || editingUser) && (
        <UserFormModal
          user={editingUser}
          onSubmit={(userData) => {
            if (editingUser) {
              updateUser.mutate(userData)
            } else {
              createUser.mutate(userData)
            }
          }}
          onClose={() => {
            setShowNewUserForm(false)
            setEditingUser(null)
          }}
          isSubmitting={createUser.isLoading || updateUser.isLoading}
        />
      )}
    </div>
  )
}

function UserFormModal({ user, onSubmit, onClose, isSubmitting }) {
  const [formData, setFormData] = useState({
    name: user?.name || '',
    email: user?.email || '',
    role: user?.role || 'user',
    password: '',
    confirmPassword: ''
  })

  const [errors, setErrors] = useState({})

  const validateForm = () => {
    const newErrors = {}
    if (!formData.name) newErrors.name = 'Name is required'
    if (!formData.email) newErrors.email = 'Email is required'
    if (!user && !formData.password) newErrors.password = 'Password is required'
    if (!user && formData.password !== formData.confirmPassword) {
      newErrors.confirmPassword = 'Passwords do not match'
    }
    setErrors(newErrors)
    return Object.keys(newErrors).length === 0
  }

  const handleSubmit = (e) => {
    e.preventDefault()
    if (validateForm()) {
      const userData = {
        ...formData,
        id: user?.id
      }
      if (!user) {
        delete userData.confirmPassword
      } else if (!userData.password) {
        delete userData.password
        delete userData.confirmPassword
      }
      onSubmit(userData)
    }
  }

  return (
    <div className="fixed inset-0 bg-gray-500 bg-opacity-75 flex items-center justify-center">
      <div className="bg-white rounded-lg p-6 max-w-md w-full">
        <h3 className="text-lg font-medium text-gray-900 mb-4">
          {user ? 'Edit User' : 'Add New User'}
        </h3>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700">Name</label>
            <input
              type="text"
              value={formData.name}
              onChange={(e) => setFormData({ ...formData, name: e.target.value })}
              className={`mt-1 block w-full rounded-md shadow-sm sm:text-sm ${
                errors.name ? 'border-red-300' : 'border-gray-300'
              }`}
            />
            {errors.name && <p className="mt-1 text-sm text-red-600">{errors.name}</p>}
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700">Email</label>
            <input
              type="email"
              value={formData.email}
              onChange={(e) => setFormData({ ...formData, email: e.target.value })}
              className={`mt-1 block w-full rounded-md shadow-sm sm:text-sm ${
                errors.email ? 'border-red-300' : 'border-gray-300'
              }`}
            />
            {errors.email && <p className="mt-1 text-sm text-red-600">{errors.email}</p>}
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700">Role</label>
            <select
              value={formData.role}
              onChange={(e) => setFormData({ ...formData, role: e.target.value })}
              className="mt-1 block w-full rounded-md border-gray-300 shadow-sm sm:text-sm"
            >
              <option value="user">User</option>
              <option value="admin">Admin</option>
            </select>
          </div>

          {(!user || formData.password) && (
            <>
              <div>
                <label className="block text-sm font-medium text-gray-700">
                  {user ? 'New Password (leave blank to keep current)' : 'Password'}
                </label>
                <input
                  type="password"
                  value={formData.password}
                  onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                  className={`mt-1 block w-full rounded-md shadow-sm sm:text-sm ${
                    errors.password ? 'border-red-300' : 'border-gray-300'
                  }`}
                />
                {errors.password && <p className="mt-1 text-sm text-red-600">{errors.password}</p>}
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700">Confirm Password</label>
                <input
                  type="password"
                  value={formData.confirmPassword}
                  onChange={(e) => setFormData({ ...formData, confirmPassword: e.target.value })}
                  className={`mt-1 block w-full rounded-md shadow-sm sm:text-sm ${
                    errors.confirmPassword ? 'border-red-300' : 'border-gray-300'
                  }`}
                />
                {errors.confirmPassword && (
                  <p className="mt-1 text-sm text-red-600">{errors.confirmPassword}</p>
                )}
              </div>
            </>
          )}

          <div className="mt-5 sm:mt-6 sm:grid sm:grid-flow-row-dense sm:grid-cols-2 sm:gap-3">
            <button
              type="submit"
              disabled={isSubmitting}
              className="inline-flex w-full justify-center rounded-md border border-transparent bg-indigo-600 px-4 py-2 text-base font-medium text-white shadow-sm hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 sm:col-start-2 sm:text-sm disabled:opacity-50"
            >
              {isSubmitting ? 'Saving...' : user ? 'Update' : 'Create'}
            </button>
            <button
              type="button"
              onClick={onClose}
              className="mt-3 inline-flex w-full justify-center rounded-md border border-gray-300 bg-white px-4 py-2 text-base font-medium text-gray-700 shadow-sm hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 sm:col-start-1 sm:mt-0 sm:text-sm"
            >
              Cancel
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
