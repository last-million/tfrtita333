export default function ServiceStatusCard({ name, status, icon: Icon }) {
  const getStatusColor = (status) => {
    switch (status) {
      case 'connected':
        return 'bg-green-100 text-green-800 dark:bg-green-800 dark:text-green-100'
      case 'disconnected':
        return 'bg-red-100 text-red-800 dark:bg-red-800 dark:text-red-100'
      default:
        return 'bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-100'
    }
  }

  return (
    <div className="bg-white dark:bg-gray-800 overflow-hidden shadow rounded-lg">
      <div className="p-5">
        <div className="flex items-center">
          <div className="flex-shrink-0">
            <Icon className="h-6 w-6 text-gray-400 dark:text-gray-300" aria-hidden="true" />
          </div>
          <div className="ml-5 w-0 flex-1">
            <dl>
              <dt className="truncate text-sm font-medium text-gray-500 dark:text-gray-400">
                {name}
              </dt>
              <dd>
                <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getStatusColor(status)}`}>
                  {status}
                </span>
              </dd>
            </dl>
          </div>
        </div>
      </div>
    </div>
  )
}
