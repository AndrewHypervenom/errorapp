import React, { useState } from 'react';
import { Code2, AlertTriangle, CheckCircle2, BookOpen, Link } from 'lucide-react';
import CodeIcon from './CodeIcon';

function ErrorCard({ error, index }) {
  const [activeTab, setActiveTab] = useState('general');
  const [expandedLanguage, setExpandedLanguage] = useState(null);

  const tabs = [
    { id: 'general', label: 'General', icon: AlertTriangle },
    { id: 'ejemplos', label: 'Ejemplos', icon: Code2 },
    { id: 'prevencion', label: 'Prevención', icon: CheckCircle2 },
    { id: 'recursos', label: 'Recursos', icon: BookOpen }
  ];

  return (
    <div 
      className="bg-white dark:bg-gray-800 rounded-xl shadow-lg overflow-hidden fade-in-up border border-gray-100 dark:border-gray-700"
      style={{ animationDelay: `${index * 0.1}s` }}
    >
      <div className="p-6 border-b border-gray-200 dark:border-gray-700">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center space-x-3">
            <h3 className="text-3xl font-bold text-gray-900 dark:text-white">
              {error.codigo}
            </h3>
            <span className={`px-3 py-1 text-sm rounded-full ${
              error.tipo === 'Cliente' 
                ? 'bg-red-100 text-red-800 dark:bg-red-900/80 dark:text-red-200' 
                : 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/80 dark:text-yellow-200'
            }`}>
              {error.tipo}
            </span>
          </div>
        </div>
        <h4 className="text-xl font-semibold text-gray-900 dark:text-white mb-2">
          {error.titulo}
        </h4>
        <p className="text-gray-600 dark:text-gray-300">
          {error.descripcion}
        </p>
      </div>

      {/* Tabs de navegación con scroll horizontal personalizado */}
      <div className="border-b border-gray-200 dark:border-gray-700">
        <div className="custom-horizontal-scroll overflow-x-auto">
          <div className="flex min-w-max">
            {tabs.map(tab => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center space-x-2 px-6 py-3 text-sm font-medium transition-colors duration-200
                  ${activeTab === tab.id
                    ? 'border-b-2 border-blue-500 text-blue-600 dark:text-blue-400'
                    : 'text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200'
                  }`}
              >
                <tab.icon className="w-4 h-4" />
                <span>{tab.label}</span>
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Contenido con scroll horizontal cuando sea necesario */}
      <div className="custom-horizontal-scroll">
        <div className="p-6 min-w-[300px]">
          {activeTab === 'general' && (
            <div className="space-y-4">
              <div>
                <h4 className="font-semibold text-gray-900 dark:text-white mb-2">
                  Solución
                </h4>
                <p className="text-gray-600 dark:text-gray-300">
                  {error.solucion}
                </p>
              </div>
              <div>
                <h4 className="font-semibold text-gray-900 dark:text-white mb-2">
                  Impacto
                </h4>
                <p className="text-gray-600 dark:text-gray-300">
                  {error.impacto}
                </p>
              </div>
              <div>
                <h4 className="font-semibold text-gray-900 dark:text-white mb-2">
                  Lenguajes Compatibles
                </h4>
                <div className="flex flex-wrap gap-2">
                  {error.lenguajes.map((lenguaje) => (
                    <span
                      key={lenguaje}
                      className="flex items-center space-x-1 px-3 py-1 text-sm rounded-full bg-blue-50 text-blue-700 dark:bg-blue-900/50 dark:text-blue-200"
                    >
                      <CodeIcon language={lenguaje} />
                      <span>{lenguaje}</span>
                    </span>
                  ))}
                </div>
              </div>
            </div>
          )}

          {activeTab === 'ejemplos' && (
            <div className="space-y-4">
              {Object.entries(error.ejemplos || {}).map(([lenguaje, codigo]) => (
                <div key={lenguaje} className="rounded-lg overflow-hidden">
                  <button
                    onClick={() => setExpandedLanguage(
                      expandedLanguage === lenguaje ? null : lenguaje
                    )}
                    className="w-full flex items-center justify-between p-3 bg-gray-100 dark:bg-gray-700 hover:bg-gray-200 dark:hover:bg-gray-600 transition-colors duration-200"
                  >
                    <div className="flex items-center space-x-2">
                      <CodeIcon language={lenguaje} />
                      <span className="font-medium text-gray-900 dark:text-white">
                        {lenguaje}
                      </span>
                    </div>
                    <span className="text-gray-500 dark:text-gray-400">
                      {expandedLanguage === lenguaje ? '−' : '+'}
                    </span>
                  </button>
                  {expandedLanguage === lenguaje && (
                    <div className="p-4 bg-gray-50 dark:bg-gray-900 overflow-x-auto custom-horizontal-scroll">
                      <pre className="text-sm text-gray-800 dark:text-gray-200 whitespace-pre-wrap">
                        <code>{codigo}</code>
                      </pre>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}

          {activeTab === 'prevencion' && (
            <div className="space-y-2">
              {error.preventivo?.map((item, index) => (
                <div 
                  key={index}
                  className="flex items-start space-x-3 p-3 rounded-lg bg-gray-50 dark:bg-gray-900"
                >
                  <CheckCircle2 className="w-5 h-5 text-green-500 flex-shrink-0 mt-0.5" />
                  <span className="text-gray-700 dark:text-gray-300">{item}</span>
                </div>
              ))}
            </div>
          )}

          {activeTab === 'recursos' && (
            <div className="space-y-3">
              {error.recursos?.map((recurso, index) => (
                <a
                  key={index}
                  href={recurso.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center space-x-3 p-4 rounded-lg bg-gray-50 dark:bg-gray-900 hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors duration-200 group"
                >
                  <Link className="w-5 h-5 text-blue-500 group-hover:text-blue-600 flex-shrink-0" />
                  <span className="text-gray-700 dark:text-gray-300 group-hover:text-gray-900 dark:group-hover:text-white">
                    {recurso.titulo}
                  </span>
                </a>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default ErrorCard;