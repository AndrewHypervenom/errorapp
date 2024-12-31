import React, { useState } from 'react';
import Header from './components/Header';
import Sidebar from './components/Sidebar';
import ErrorCard from './components/ErrorCard';
import BackgroundDecoration from './components/BackgroundDecoration';
import { erroresNavegador } from './data/errors';

function App() {
  const [selectedLanguage, setSelectedLanguage] = useState('todos');
  const [selectedErrorType, setSelectedErrorType] = useState('todos');
  const [menuOpen, setMenuOpen] = useState(false);

  const filteredErrors = erroresNavegador.filter(error => {
    const matchesLanguage = selectedLanguage === 'todos' || error.lenguajes.includes(selectedLanguage);
    const matchesType = selectedErrorType === 'todos' || 
      (selectedErrorType === 'cliente' && error.tipo === 'Cliente') ||
      (selectedErrorType === 'servidor' && error.tipo === 'Servidor');
    return matchesLanguage && matchesType;
  });

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-50 to-gray-100 dark:from-gray-900 dark:to-gray-800">
      <BackgroundDecoration />

      <div className="relative z-10 flex flex-col h-screen">
        <Header setMenuOpen={setMenuOpen} menuOpen={menuOpen} />
        
        <div className="flex flex-col lg:flex-row flex-1 overflow-hidden">
          <Sidebar 
            selectedLanguage={selectedLanguage}
            setSelectedLanguage={setSelectedLanguage}
            selectedErrorType={selectedErrorType}
            setSelectedErrorType={setSelectedErrorType}
            menuOpen={menuOpen}
            setMenuOpen={setMenuOpen}
          />
          
          <main className="flex-1 overflow-auto p-4 sm:p-6 lg:p-8">
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {filteredErrors.map((error, index) => (
                <ErrorCard 
                  key={error.codigo} 
                  error={error} 
                  index={index}
                />
              ))}
            </div>
          </main>
        </div>
      </div>
    </div>
  );
}

export default App;