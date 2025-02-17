import { useEffect } from 'react'
import { SunIcon, MoonIcon } from '@heroicons/react/24/outline'
import { useLocalStorage } from '../lib/hooks/useLocalStorage'

export default function DarkModeToggle() {
  const [darkMode, setDarkMode] = useLocalStorage('darkMode', false)

  useEffect(() => {
    if (darkMode) {
      document.documentElement.classList.add('dark')
    } else {
      document.documentElement.classList.remove('dark')
    }
  }, [darkMode])

  return (
    <button
      onClick={() => setDarkMode(!darkMode)}
      className="rounded-full p-1 text-gray-400 hover:text-gray-500 dark:text-gray-300 dark:hover:text-gray-200"
      aria-label="Toggle dark mode"
    >
      {darkMode ? (
        <SunIcon className="h-6 w-6" />
      ) : (
        <MoonIcon className="h-6 w-6" />
      )}
    </button>
  )
}
