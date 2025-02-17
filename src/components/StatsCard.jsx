export default function StatsCard({ title, value, icon: Icon, trend, trendColor = 'normal' }) {
  const getTrendColor = (trend, type) => {
    if (!trend) return ''
    
    const isPositive = trend > 0
    if (type === 'reverse') {
      return isPositive 
        ? 'text-red-500 dark:text-red-400'
        : 'text-green-500 dark:text-green-400'
    }
    return isPositive
      ? 'text-green-500 dark:text-green-400'
      : 'text-red-500 dark:text-red-400'
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
              <dt className="text-sm font-medium text-gray-500 dark:text-gray-400 truncate">
                {title}
              </dt>
              <dd className="flex items-baseline">
                <div className="text-2xl font-semibold text-gray-900 dark:text-white">
                  {value}
                </div>
                {trend !== undefined && (
                  <div className={`ml-2 flex items-baseline text-sm font-semibold ${getTrendColor(trend, trendColor)}`}>
                    {trend > 0 ? '↑' : '↓'} {Math.abs(trend)}%
                  </div>
                )}
              </dd>
            </dl>
          </div>
        </div>
      </div>
    </div>
  )
}
