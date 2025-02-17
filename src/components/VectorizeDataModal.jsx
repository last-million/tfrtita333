import { Fragment, useState } from 'react'
import { Dialog, Transition } from '@headlessui/react'
import { XMarkIcon } from '@heroicons/react/24/outline'

export default function VectorizeDataModal({ isOpen, onClose, tables, onVectorize }) {
  const [selectedTables, setSelectedTables] = useState([])
  const [loading, setLoading] = useState(false)

  const handleVectorize = async () => {
    setLoading(true)
    try {
      await onVectorize(selectedTables)
      onClose()
    } catch (error) {
      console.error('Vectorization error:', error)
    } finally {
      setLoading(false)
    }
  }

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

                <div>
                  <div className="mt-3 text-center sm:mt-0 sm:text-left">
                    <Dialog.Title as="h3" className="text-lg font-semibold leading-6 text-gray-900">
                      Vectorize Data
                    </Dialog.Title>
                    <div className="mt-2">
                      <p className="text-sm text-gray-500">
                        Select the tables you want to vectorize for the knowledge base.
                      </p>
                    </div>

                    <div className="mt-4 space-y-2">
                      {tables.map((table) => (
                        <div key={table.id} className="flex items-center">
                          <input
                            type="checkbox"
                            id={table.id}
                            checked={selectedTables.includes(table.id)}
                            onChange={(e) => {
                              if (e.target.checked) {
                                setSelectedTables([...selectedTables, table.id])
                              } else {
                                setSelectedTables(selectedTables.filter(id => id !== table.id))
                              }
                            }}
                            className="h-4 w-4 rounded border-gray-300 text-indigo-600 focus:ring-indigo-500"
                          />
                          <label htmlFor={table.id} className="ml-2 block text-sm text-gray-900">
                            {table.name}
                            <span className="ml-2 text-xs text-gray-500">
                              ({table.rowCount} rows)
                            </span>
                          </label>
                        </div>
                      ))}
                    </div>

                    <div className="mt-5 sm:mt-6">
                      <button
                        type="button"
                        disabled={loading || selectedTables.length === 0}
                        onClick={handleVectorize}
                        className="inline-flex w-full justify-center rounded-md bg-indigo-600 px-3 py-2 text-sm font-semibold text-white shadow-sm hover:bg-indigo-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-600 disabled:opacity-50"
                      >
                        {loading ? 'Vectorizing...' : 'Vectorize Selected Tables'}
                      </button>
                    </div>
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
