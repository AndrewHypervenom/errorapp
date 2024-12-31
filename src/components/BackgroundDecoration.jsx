import React from 'react';

function BackgroundDecoration() {
  return (
    <div className="fixed inset-0 overflow-hidden pointer-events-none">
      {/* Círculos decorativos animados */}
      <div className="absolute top-1/4 right-1/4 w-96 h-96 bg-blue-500/20 rounded-full filter blur-3xl animate-float"></div>
      <div className="absolute bottom-1/4 left-1/4 w-96 h-96 bg-purple-500/20 rounded-full filter blur-3xl animate-float" style={{ animationDelay: '-3s' }}></div>
      
      {/* Grid tecnológico */}
      <div className="absolute inset-0 tech-pattern opacity-5"></div>
      
      {/* Líneas de conexión */}
      <svg className="absolute inset-0 w-full h-full" xmlns="http://www.w3.org/2000/svg">
        <defs>
          <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
            <path d="M 40 0 L 0 0 0 40" fill="none" stroke="currentColor" strokeWidth="0.5" className="text-gray-300/10" />
          </pattern>
        </defs>
        <rect width="100%" height="100%" fill="url(#grid)" />
      </svg>
    </div>
  );
}

export default BackgroundDecoration;