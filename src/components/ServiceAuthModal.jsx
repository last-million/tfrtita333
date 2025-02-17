import { Fragment, useState } from 'react'
import { Dialog, Transition } from '@headlessui/react'
import { XMarkIcon } from '@heroicons/react/24/outline'

export default function ServiceAuthModal({ service, isOpen, onClose, onAuth }) {
  const [credentials, setCredentials] = useState({})
  const [loading, setLoading] = useState(false)

  const serviceConfigs = {
    supabase: {
      title: 'Connect Supabase',
      fields: [
        { name: 'url', label: 'Project URL', type: 'text' },
        { name: 'apiKey', label: 'API Key', type: 'password' }
      ],
      description: 'Connect to your Supabase project to use as a vector store.'
    },
    airtable: {
      title: 'Connect Airtable',
      fields: [
        { name: 'apiKey', label: 'API Key', type: 'password' },
        { name: 'baseId', label: 'Base ID', type: 'text' }
      ],
      description: 'Connect your Airtable base for data storage and retrieval.'
    },
    twilio: {
      title: 'Configure Twilio',
      fields: [
        { name: 'accountSid', label: 'Account SID', type: 'text' },
        { name: 'authToken', label: 'Auth Token', type: 'password' },
        { name: 'phoneNumber', label: 'Phone Number', type: 'text' }
      ],
      description: 'Configure Twilio credentials for voice calls.'
    }
  }

  const handleOAuthService = (serviceName) => {
    const currentUrl = window.location.origin
    const popup = window.open(
      `/api/auth/${serviceName}?redirect_uri=${encodeURIComponent(currentUrl)}`,
      'Auth',
      'width=600,height=600'
    )

    window.addEventListener('message', (event) => {
      if (event.data.type === 'auth_success' && event.data.service === serviceName) {
        popup.close()
        onAuth(event.data.credentials)
        onClose()
      }
    })
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    setLoading(true)
    try {
      await onAuth(credentials)
      onClose()
    } catch (error) {
      console.error('Auth error:', error)
    } finally {
      setLoading(false)
    }
  }

  const config = serviceConfigs[service]
  const isOAuthService = ['google', 'gmail', 'calendar', 'drive'].includes(service)

  return (
    <Transition.Root show={isOpen} as={Fragment}>
      <Dialog as="div" className="relative z-10" onClose={onClose}>
        <Transition.Child
          as={Fragment}
          enter="ease-out duration-300"
          enterFrom="opacity-0"
          enterTo="opacity-100"
          leave="ease-in duration-200"
          leaveFrom="opacity-100"
          leaveTo="opacity-0"
        >
          <div className="fixed inset-0 bg-gray-500 bg-opacity-75 transition-opacity" />
        </Transition.Child>

        <div className="fixed inset-0 z-10 overflow-y-auto">
          <div className="flex min-h-full items-end justify-center p-4 text-center sm:items-center sm:p-0">
            <Transition.Child
              as={Fragment}
              enter="ease-out duration-300"
              enterFrom="opacity-0 translate-y-4 sm:translate-y-0 sm:scale-95"
              enterTo="opacity-100 translate-y-0 sm:scale-100"
              leave="ease-in duration-200"
              leaveFrom="opacity-100 translate-y-0 sm:scale-100"
              leaveTo="opacity-0 translate-y-4 sm:translate-y-0 sm:scale-95"
            >
              <Dialog.Panel className="relative transform overflow-hidden rounded-lg bg-white px-4 pb-4 pt-5 text-left shadow-xl transition-all sm:my-8 sm:w-full sm:max-w-lg sm:p-6">
                <div className="absolute right-0 top-0 hidden pr-4 pt-4 sm:block">
                  <button
                    type="button"
                    className="rounded-md bg-white text-gray-400 hover:text-gray-500 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2"
                    onClick={onClose}
                  >
                    <span className="sr-only">Close</span>
                    <XMarkIcon className="h-6 w-6" aria-hidden="true" />
                  </button>
                </div>

                <div className="sm:flex sm:items-start">
                  <div className="mt-3 text-center sm:mt-0 sm:text-left w-full">
                    <Dialog.Title as="h3" className="text-lg font-semibold leading-6 text-gray-900">
                      {isOAuthService ? `Connect ${service}` : config.title}
                    </Dialog.Title>
                    <div className="mt-2">
                      <p className="text-sm text-gray-500">
                        {isOAuthService 
                          ? `Connect your ${service} account to enable integration.`
                          : config.description}
                      </p>
                    </div>

                    {isOAuthService ? (
                      <div className="mt-5">
                        <button
                          type="button"
                          onClick={() => handleOAuthService(service)}
                          className="inline-flex w-full justify-center rounded-md bg-indigo-600 px-3 py-2 text-sm font-semibold text-white shadow-sm hover:bg-indigo-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-600"
                        >
                          Connect with {service}
                        </button>
                      </div>
                    ) : (
                      <form onSubmit={handleSubmit} className="mt-5 space-y-4">
                        {config.fields.map((field) => (
                          <div key={field.name}>
                            <label htmlFor={field.name} className="block text-sm font-medium text-gray-700">
                              {field.label}
                            </label>
                            <input
                              type={field.type}
                              name={field.name}
                              id={field.name}
                              onChange={(e) => setCredentials({
                                ...credentials,
                                [field.name]: e.target.value
                              })}
                              className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm"
                            />
                          </div>
                        ))}
                        <div className="mt-5 sm:mt-6">
                          <button
                            type="submit"
                            disabled={loading}
                            className="inline-flex w-full justify-center rounded-md bg-indigo-600 px-3 py-2 text-sm font-semibold text-white shadow-sm hover:bg-indigo-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-600"
                          >
                            {loading ? 'Connecting...' : 'Connect'}
                          </button>
                        </div>
                      </form>
                    )}
                  </div>
                </div>
              </Dialog.Panel>
            </Transition.Child>
          </div>
        </div>
      </Dialog>
    </Transition.Root>
  )
}
