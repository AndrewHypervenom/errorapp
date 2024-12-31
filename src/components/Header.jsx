import React from 'react';
import ThemeToggle from './ThemeToggle';
import { Menu, Code2 } from 'lucide-react';

function Header({ setMenuOpen, menuOpen }) {
  return (
    <header className="bg-gray-900 dark:bg-gray-950 shadow-xl sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-4">
            <button
              onClick={() => setMenuOpen(!menuOpen)}
              className="p-2 rounded-lg bg-gray-800 hover:bg-gray-700 transition-colors duration-200 lg:hidden"
            >
              <Menu className="h-6 w-6 text-blue-400" />
            </button>
            <div className="flex items-center space-x-3">
              <div className="bg-gradient-to-r from-blue-500 to-purple-500 p-2 rounded-lg">
                <Code2 className="h-6 w-6 text-white" />
              </div>
              <h1 className="text-xl sm:text-2xl font-bold text-white">
                Errores de Navegador
              </h1>
            </div>
          </div>
          <ThemeToggle />
        </div>
      </div>
      <div className="h-1 bg-gradient-to-r from-blue-500 via-purple-500 to-pink-500"></div>
    </header>
  );
}

export default Header;