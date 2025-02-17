import { useState, useMemo } from 'react'
import { Tab } from '@headlessui/react'
import { Switch } from '@headlessui/react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { toast } from 'react-toastify'
import MonacoEditor from '@monaco-editor/react'
import {
  CloudArrowUpIcon,
  CalendarIcon,
  EnvelopeIcon,
  GlobeAltIcon,
  KeyIcon,
  DocumentTextIcon,
  DocumentPlusIcon, // New icon for Google Drive Docs
  TableCellsIcon // New icon for Supabase Tables
} from '@heroicons/react/24/outline'
import api from '../lib/api'
import ServiceAuthModal from '../components/ServiceAuthModal'
import VectorizeDataModal from '../components/VectorizeDataModal'
import { useConfig } from '../lib/hooks/useConfig'
import { useSupabase } from '../lib/hooks/useSupabase'
import { useGoogleAuth } from '../lib/hooks/useGoogleAuth'
import { useTwilioConfig } from '../lib/hooks/useTwilioConfig'

function classNames(...classes) {
  return classes.filter(Boolean).join(' ')
}

const toolInstructions = {
  calendar: `\n\nCalendar Management:
- You can manage calendar events using the 'calendar' tool
- Use this to schedule meetings, check availability, and manage appointments
- Always confirm the time and date with the user before scheduling`,
  gmail: `\n\nEmail Capabilities:
- You can send emails using the 'gmail' tool
- Use this for follow-ups, confirmations, and sending information
- Always confirm the email content with the user before sending`,
  serp: `\n\nWeb Search:
- You can search the internet using the 'search' tool
- Use this to find current information and answer questions
- Always cite your sources when providing information from web searches`
}

const serviceFeatures = {
  supabase: "Use Supabase tables as knowledge base",
  drive: "Access and vectorize documents from Google Drive",
  airtable: "Access data from Airtable bases",
  calendar: "Schedule and manage calendar events",
  gmail: "Send emails via Gmail",
  serp: "Perform web searches using SERP API"
}


export default function Settings() {
  const queryClient = useQueryClient()
  const [activeTab, setActiveTab] = useState(0)
  const [showServiceModal, setShowServiceModal] = useState(null)
  const [showVectorizeModal, setShowVectorizeModal] = useState(false)
  const { config, updateConfig } = useConfig()
  const { tables, vectorizeTable } = useSupabase()
  const { initiateAuth } = useGoogleAuth()
  const { twilioConfig, toggleConfigSource, updateConfig: updateTwilioConfig } = useTwilioConfig()

  const handleToolToggle = async (toolName, enabled) => {
    await updateConfig({
      ...config,
      tools: {
        ...config.tools,
        [toolName]: {
          ...config.tools[toolName],
          enabled
        }
      }
    })
  }

  const handleServiceConnect = async (service, credentials) => {
    try {
      await api.post(`/api/auth/${service}/connect`, credentials)
      queryClient.invalidateQueries(['config'])
      toast.success(`${service} connected successfully. Features enabled: ${serviceFeatures[service] || 'N/A'}`) // Service Feature Feedback
    } catch (error) {
      toast.error(`Failed to connect ${service}`)
    }
  }

  const handleVectorize = async (selectedTables) => {
    try {
      await Promise.all(selectedTables.map(tableId => vectorizeTable(tableId)))
      queryClient.invalidateQueries(['config'])
      toast.success('Data vectorized successfully')
    } catch (error) {
      toast.error('Failed to vectorize data')
    }
  }

  const handleTwilioConfigUpdate = async (newConfig) => {
    try {
      await updateTwilioConfig(newConfig)
      toast.success('Twilio configuration updated')
    } catch (error) {
      toast.error('Failed to update Twilio configuration')
    }
  }

  const systemPrompt = useMemo(() => {
    let basePrompt = config?.systemPrompt || '';
    for (const tool in config?.tools) {
      if (config.tools[tool].enabled && toolInstructions[tool]) {
        basePrompt += toolInstructions[tool];
      }
    }
    return basePrompt;
  }, [config]);


  const tabs = [
    { name: 'System Prompt', icon: DocumentTextIcon },
    { name: 'Knowledge Base', icon: CloudArrowUpIcon },
    { name: 'Tools', icon: KeyIcon },
    { name: 'Twilio', icon: PhoneIcon }
  ]

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
      <div className="max-w-3xl mx-auto">
        <Tab.Group selectedIndex={activeTab} onChange={setActiveTab}>
          <Tab.List className="flex space-x-1 rounded-xl bg-blue-900/20 p-1">
            {tabs.map((tab) => (
              <Tab
                key={tab.name}
                className={({ selected }) =>
                  classNames(
                    'w-full rounded-lg py-2.5 text-sm font-medium leading-5',
                    'ring-white ring-opacity-60 ring-offset-2 ring-offset-blue-400 focus:outline-none focus:ring-2',
                    selected
                      ? 'bg-white shadow text-blue-700'
                      : 'text-blue-100 hover:bg-white/[0.12] hover:text-white'
                  )
                }
              >
                <div className="flex items-center justify-center space-x-2">
                  <tab.icon className="h-5 w-5" />
                  <span>{tab.name}</span>
                </div>
              </Tab>
            ))}
          </Tab.List>

          <Tab.Panels className="mt-2">
            {/* System Prompt Panel */}
            <Tab.Panel>
              <div className="bg-white shadow sm:rounded-lg">
                <div className="px-4 py-5 sm:p-6">
                  <h3 className="text-lg font-medium leading-6 text-gray-900">
                    System Prompt
                  </h3>
                  <div className="mt-2 max-w-xl text-sm text-gray-500">
                    <p>Configure the base system prompt for your AI agent.</p>
                  </div>
                  <div className="mt-5">
                    <MonacoEditor
                      height="400px"
                      language="markdown"
                      theme="vs-dark"
                      value={systemPrompt}
                      onChange={(value) => {
                        updateConfig({
                          ...config,
                          systemPrompt: value
                        })
                      }}
                      options={{
                        minimap: { enabled: false },
                        lineNumbers: 'on',
                        scrollBeyondLastLine: false,
                        wordWrap: 'on'
                      }}
                    />
                  </div>
                </div>
              </div>
            </Tab.Panel>

            {/* Knowledge Base Panel */}
            <Tab.Panel>
              <div className="space-y-6">
                {/* Supabase Connection */}
                <div className="bg-white shadow sm:rounded-lg">
                  <div className="px-4 py-5 sm:p-6">
                    <div className="flex items-center justify-between">
                      <div>
                        <h3 className="text-lg font-medium leading-6 text-gray-900">
                          Supabase Tables
                        </h3>
                        <div className="mt-2 max-w-xl text-sm text-gray-500">
                          <p>Connect your Supabase project and vectorize tables for knowledge.</p>
                        </div>
                      </div>
                      {config?.supabase?.connected ? (
                        <span className="inline-flex items-center px-3 py-0.5 rounded-full text-sm font-medium bg-green-100 text-green-800">
                          Connected
                        </span>
                      ) : (
                        <button
                          type="button"
                          onClick={() => setShowServiceModal('supabase')}
                          className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-indigo-600 hover:bg-indigo-700"
                        >
                          Connect
                        </button>
                      )}
                    </div>
                    {config?.supabase?.connected && (
                      <div className="mt-4">
                        <button
                          onClick={() => setShowVectorizeModal(true)}
                          className="inline-flex items-center px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 hover:bg-gray-50 dark:hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-indigo-500"
                        >
                          <TableCellsIcon className="-ml-1 mr-2 h-5 w-5 text-gray-500" aria-hidden="true" />
                          Vectorize Tables
                        </button>
                      </div>
                    )}
                  </div>
                </div>

                {/* Google Drive Connection */}
                <div className="bg-white shadow sm:rounded-lg">
                  <div className="px-4 py-5 sm:p-6">
                    <div className="flex items-center justify-between">
                      <div>
                        <h3 className="text-lg font-medium leading-6 text-gray-900">
                          Google Drive Documents
                        </h3>
                        <div className="mt-2 max-w-xl text-sm text-gray-500">
                          <p>Connect Google Drive to access and vectorize documents.</p>
                        </div>
                      </div>
                      {config?.googleDrive?.connected ? (
                        <span className="inline-flex items-center px-3 py-0.5 rounded-full text-sm font-medium bg-green-100 text-green-800">
                          Connected
                        </span>
                      ) : (
                        <button
                          type="button"
                          onClick={() => initiateAuth('drive')}
                          className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-indigo-600 hover:bg-indigo-700"
                        >
                          Connect with Google
                        </button>
                      )}
                    </div>
                    {config?.googleDrive?.connected && (
                      <div className="mt-4">
                        <button
                          onClick={() => alert('Google Drive Document Selection Coming Soon')} // Placeholder
                          className="inline-flex items-center px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 hover:bg-gray-50 dark:hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-indigo-500"
                        >
                          <DocumentPlusIcon className="-ml-1 mr-2 h-5 w-5 text-gray-500" aria-hidden="true" />
                          Select Documents to Vectorize
                        </button>
                      </div>
                    )}
                  </div>
                </div>

                {/* Airtable Connection */}
                <div className="bg-white shadow sm:rounded-lg">
                  <div className="px-4 py-5 sm:p-6">
                    <div className="flex items-center justify-between">
                      <div>
                        <h3 className="text-lg font-medium leading-6 text-gray-900">
                          Airtable
                        </h3>
                        <div className="mt-2 max-w-xl text-sm text-gray-500">
                          <p>Connect Airtable to access your bases.</p>
                        </div>
                      </div>
                      {config?.airtable?.connected ? (
                        <span className="inline-flex items-center px-3 py-0.5 rounded-full text-sm font-medium bg-green-100 text-green-800">
                          Connected
                        </span>
                      ) : (
                        <button
                          type="button"
                          onClick={() => initiateAuth('airtable')}
                          className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-indigo-600 hover:bg-indigo-700"
                        >
                          Connect with Google
                        </button>
                      )}
                    </div>
                     {config?.airtable?.connected && (
                      <div className="mt-4">
                        <button
                          onClick={() => alert('Airtable Base Selection Coming Soon')} // Placeholder
                          className="inline-flex items-center px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 hover:bg-gray-50 dark:hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-indigo-500"
                        >
                          <DocumentPlusIcon className="-ml-1 mr-2 h-5 w-5 text-gray-500" aria-hidden="true" />
                          Select Airtable Bases to Vectorize
                        </button>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            </Tab.Panel>

            {/* Tools Panel */}
            {/* Tools Panel - remains the same */}
             <Tab.Panel>
              <div className="space-y-6">
                {/* Google Calendar */}
                <div className="bg-white shadow sm:rounded-lg">
                  <div className="px-4 py-5 sm:p-6">
                    <div className="flex items-center justify-between">
                      <div className="flex-1">
                        <div className="flex items-center justify-between">
                          <div>
                            <h3 className="text-lg font-medium leading-6 text-gray-900">
                              Google Calendar
                            </h3>
                            <div className="mt-2 max-w-xl text-sm text-gray-500">
                              <p>Enable calendar management capabilities.</p>
                            </div>
                          </div>
                          <Switch
                            checked={config?.tools?.calendar?.enabled}
                            onChange={(enabled) => handleToolToggle('calendar', enabled)}
                            className={classNames(
                              config?.tools?.calendar?.enabled ? 'bg-indigo-600' : 'bg-gray-200',
                              'relative inline-flex flex-shrink-0 h-6 w-11 border-2 border-transparent rounded-full cursor-pointer transition-colors ease-in-out duration-200 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500'
                            )}
                          >
                            <span className="sr-only">Use setting</span>
                            <span
                              className={classNames(
                                config?.tools?.calendar?.enabled ? 'translate-x-5' : 'translate-x-0',
                                'pointer-events-none relative inline-block h-5 w-5 rounded-full bg-white shadow transform ring-0 transition ease-in-out duration-200'
                              )}
                            >
                              <span
                                className={classNames(
                                  config?.tools?.calendar?.enabled
                                    ? 'opacity-0 ease-out duration-100'
                                    : 'opacity-100 ease-in duration-200',
                                  'absolute inset-0 h-full w-full flex items-center justify-center transition-opacity'
                                )}
                                aria-hidden="true"
                              >
                                <CalendarIcon className="h-3 w-3 text-gray-400" />
                              </span>
                            </span>
                          </Switch>
                        </div>
                        {config?.tools?.calendar?.enabled && !config?.tools?.calendar?.connected && (
                          <div className="mt-4">
                            <button
                              type="button"
                              onClick={() => initiateAuth('calendar')}
                              className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-indigo-600 hover:bg-indigo-700"
                            >
                              Connect with Google Calendar
                            </button>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                </div>

                {/* Gmail */}
                <div className="bg-white shadow sm:rounded-lg">
                  <div className="px-4 py-5 sm:p-6">
                    <div className="flex items-center justify-between">
                      <div className="flex-1">
                        <div className="flex items-center justify-between">
                          <div>
                            <h3 className="text-lg font-medium leading-6 text-gray-900">
                              Gmail
                            </h3>
                            <div className="mt-2 max-w-xl text-sm text-gray-500">
                              <p>Enable email sending capabilities.</p>
                            </div>
                          </div>
                          <Switch
                            checked={config?.tools?.gmail?.enabled}
                            onChange={(enabled) => handleToolToggle('gmail', enabled)}
                            className={classNames(
                              config?.tools?.gmail?.enabled ? 'bg-indigo-600' : 'bg-gray-200',
                              'relative inline-flex flex-shrink-0 h-6 w-11 border-2 border-transparent rounded-full cursor-pointer transition-colors ease-in-out duration-200 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500'
                            )}
                          >
                            <span className="sr-only">Use setting</span>
                            <span
                              className={classNames(
                                config?.tools?.gmail?.enabled ? 'translate-x-5' : 'translate-x-0',
                                'pointer-events-none relative inline-block h-5 w-5 rounded-full bg-white shadow transform ring-0 transition ease-in-out duration-200'
                              )}
                            >
                              <span
                                className={classNames(
                                  config?.tools?.gmail?.enabled
                                    ? 'opacity-0 ease-out duration-100'
                                    : 'opacity-100 ease-in duration-200',
                                  'absolute inset-0 h-full w-full flex items-center justify-center transition-opacity'
                                )}
                                aria-hidden="true"
                              >
                                <EnvelopeIcon className="h-3 w-3 text-gray-400" />
                              </span>
                            </span>
                          </Switch>
                        </div>
                        {config?.tools?.gmail?.enabled && !config?.tools?.gmail?.connected && (
                          <div className="mt-4">
                            <button
                              type="button"
                              onClick={() => initiateAuth('gmail')}
                              className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-indigo-600 hover:bg-indigo-700"
                            >
                              Connect with Gmail
                            </button>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                </div>

                {/* SERP API */}
                <div className="bg-white shadow sm:rounded-lg">
                  <div className="px-4 py-5 sm:p-6">
                    <div className="flex items-center justify-between">
                      <div className="flex-1">
                        <div className="flex items-center justify-between">
                          <div>
                            <h3 className="text-lg font-medium leading-6 text-gray-900">
                              SERP API
                            </h3>
                            <div className="mt-2 max-w-xl text-sm text-gray-500">
                              <p>Enable web search capabilities.</p>
                            </div>
                          </div>
                          <Switch
                            checked={config?.tools?.serp?.enabled}
                            onChange={(enabled) => handleToolToggle('serp', enabled)}
                            className={classNames(
                              config?.tools?.serp?.enabled ? 'bg-indigo-600' : 'bg-gray-200',
                              'relative inline-flex flex-shrink-0 h-6 w-11 border-2 border-transparent rounded-full cursor-pointer transition-colors ease-in-out duration-200 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500'
                            )}
                          >
                            <span className="sr-only">Use setting</span>
                            <span
                              className={classNames(
                                config?.tools?.serp?.enabled ? 'translate-x-5' : 'translate-x-0',
                                'pointer-events-none relative inline-block h-5 w-5 rounded-full bg-white shadow transform ring-0 transition ease-in-out duration-200'
                              )}
                            >
                              <span
                                className={classNames(
                                  config?.tools?.serp?.enabled
                                    ? 'opacity-0 ease-out duration-100'
                                    : 'opacity-100 ease-in duration-200',
                                  'absolute inset-0 h-full w-full flex items-center justify-center transition-opacity'
                                )}
                                aria-hidden="true"
                              >
                                <GlobeAltIcon className="h-3 w-3 text-gray-400" />
                              </span>
                            </span>
                          </Switch>
                        </div>
                        {config?.tools?.serp?.enabled && !config?.tools?.serp?.connected && (
                          <div className="mt-4">
                            <button
                              type="button"
                              onClick={() => initiateAuth('serp')}
                              className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-indigo-600 hover:bg-indigo-700"
                            >
                              Connect with SERP API
                            </button>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </Tab.Panel>


            {/* Twilio Configuration Panel */}
            <Tab.Panel>
              <div className="bg-white shadow sm:rounded-lg">
                <div className="px-4 py-5 sm:p-6">
                  <h3 className="text-lg font-medium leading-6 text-gray-900">
                    Twilio Configuration
                  </h3>
                  <div className="mt-2 max-w-xl text-sm text-gray-500">
                    <p>Configure your Twilio credentials for voice calls.</p>
                  </div>
                  <div className="mt-5">
                    <Switch
                      checked={twilioConfig?.useEnvConfig}
                      onChange={toggleConfigSource}
                      className="relative inline-flex flex-shrink-0 h-6 w-11 border-2 border-transparent rounded-full cursor-pointer transition-colors ease-in-out duration-200 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
                    >
                      <span className="sr-only">Use environment variables</span>
                      <span
                        className={`pointer-events-none relative inline-block h-5 w-5 rounded-full bg-white shadow transform ring-0 transition ease-in-out duration-200 ${
                          twilioConfig?.useEnvConfig ? 'translate-x-5' : 'translate-x-0'
                        }`}
                      >
                        <span
                          aria-hidden="true"
                          className={`absolute inset-0 h-full w-full flex items-center justify-center transition-opacity duration-100 ease-out ${
                            twilioConfig?.useEnvConfig ? 'opacity-0' : 'opacity-100'
                          }`}
                        >
                          <KeyIcon className="h-3 w-3 text-gray-400" />
                        </span>
                      </span>
                    </Switch>
                    <p className="mt-2 text-sm text-gray-500">
                      {twilioConfig?.useEnvConfig
                        ? 'Using credentials from environment variables.'
                        : 'Using custom credentials.'}
                    </p>

                    {!twilioConfig?.useEnvConfig && (
                      <div className="mt-4">
                        <label htmlFor="twilio-account-sid" className="block text-sm font-medium text-gray-700">
                          Account SID
                        </label>
                        <input
                          type="text"
                          name="twilio-account-sid"
                          id="twilio-account-sid"
                          className="shadow-sm focus:ring-indigo-500 focus:border-indigo-500 block w-full sm:text-sm border-gray-300 rounded-md"
                          value={twilioConfig?.accountSid || ''}
                          onChange={(e) => handleTwilioConfigUpdate({
                            ...twilioConfig,
                            accountSid: e.target.value
                          })}
                        />
                        <label htmlFor="twilio-auth-token" className="block mt-4 text-sm font-medium text-gray-700">
                          Auth Token
                        </label>
                        <input
                          type="password"
                          name="twilio-auth-token"
                          id="twilio-auth-token"
                          className="shadow-sm focus:ring-indigo-500 focus:border-indigo-500 block w-full sm:text-sm border-gray-300 rounded-md"
                          value={twilioConfig?.authToken || ''}
                          onChange={(e) => handleTwilioConfigUpdate({
                            ...twilioConfig,
                            authToken: e.target.value
                          })}
                        />
                        <label htmlFor="twilio-phone-number" className="block mt-4 text-sm font-medium text-gray-700">
                          Phone Number
                        </label>
                        <input
                          type="text"
                          name="twilio-phone-number"
                          id="twilio-phone-number"
                          className="shadow-sm focus:ring-indigo-500 focus:border-indigo-500 block w-full sm:text-sm border-gray-300 rounded-md"
                          value={twilioConfig?.phoneNumber || ''}
                          onChange={(e) => handleTwilioConfigUpdate({
                            ...twilioConfig,
                            phoneNumber: e.target.value
                          })}
                        />
                      </div>
                    )}
                  </div>
                </div>
              </div>
            </Tab.Panel>
          </Tab.Panels>
        </Tab.Group>
      </div>

      {/* Modals */}
      {showServiceModal && (
        <ServiceAuthModal
          service={showServiceModal}
          isOpen={!!showServiceModal}
          onClose={() => setShowServiceModal(null)}
          onAuth={(credentials) => handleServiceConnect(showServiceModal, credentials)}
        />
      )}

      <VectorizeDataModal
        isOpen={showVectorizeModal}
        onClose={() => setShowVectorizeModal(false)}
        tables={tables || []}
        onVectorize={handleVectorize}
      />
    </div>
  )
}
