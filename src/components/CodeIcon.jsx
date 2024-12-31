import React from 'react';

function CodeIcon({ language }) {
  const getIconColor = (lang) => {
    const colors = {
      JavaScript: 'text-yellow-500',
      Python: 'text-blue-500',
      PHP: 'text-indigo-500',
      Java: 'text-red-500',
      Ruby: 'text-red-600',
      'C#': 'text-green-500',
      Go: 'text-blue-400',
      default: 'text-gray-500'
    };
    return colors[lang] || colors.default;
  };

  return (
    <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${getIconColor(language)} bg-opacity-20`}>
      <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <polyline points="16 18 22 12 16 6"></polyline>
        <polyline points="8 6 2 12 8 18"></polyline>
      </svg>
    </div>
  );
}

export default CodeIcon;