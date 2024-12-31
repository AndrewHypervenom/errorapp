import React from 'react';
import { Sun, Moon } from 'lucide-react';
import { useTheme } from '../hooks/useTheme';

function ThemeToggle() {
  const { theme, toggleTheme } = useTheme();

  return (
    <button
      onClick={toggleTheme}
      className="p-2 rounded-lg bg-gray-800 hover:bg-gray-700 transition-colors duration-200"
      aria-label="Toggle theme"
    >
      {theme === 'dark' ? (
        <Sun className="h-6 w-6 text-yellow-400" />
      ) : (
        <Moon className="h-6 w-6 text-blue-400" />
      )}
    </button>
  );
}

export default ThemeToggle;