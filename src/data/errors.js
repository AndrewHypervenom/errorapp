export const erroresNavegador = [
    {
      codigo: 404,
      tipo: 'Cliente',
      titulo: 'Not Found - Recurso no encontrado',
      descripcion: 'El servidor no pudo encontrar el contenido solicitado. Este error ocurre cuando el servidor no encuentra la página o recurso solicitado.',
      solucion: 'Verificar que la URL sea correcta. Implementar una página 404 personalizada. Redirigir a una página alternativa válida.',
      ejemplos: {
        JavaScript: `
  // Manejo de error 404 en fetch
  fetch('https://api.ejemplo.com/recurso')
    .then(response => {
      if (response.status === 404) {
        throw new Error('Recurso no encontrado');
      }
      return response.json();
    })
    .catch(error => {
      console.error('Error:', error);
      mostrarPagina404();
    });
  
  // Función para mostrar página 404 personalizada
  function mostrarPagina404() {
    document.getElementById('contenido').innerHTML = \`
      <div class="error-404">
        <h1>¡Oops! Página no encontrada</h1>
        <p>Lo sentimos, la página que buscas no existe.</p>
        <a href="/">Volver al inicio</a>
      </div>
    \`;
  }`,
        Python: `
  # Flask - Manejador de error 404
  from flask import Flask, render_template
  
  app = Flask(__name__)
  
  @app.errorhandler(404)
  def pagina_no_encontrada(error):
      return render_template('404.html'), 404
  
  # Django - Manejador de error 404
  # urls.py
  handler404 = 'miapp.views.error_404'
  
  # views.py
  def error_404(request, exception):
      return render(request, '404.html', status=404)`,
        PHP: `
  // PHP - Página de error 404 personalizada
  <?php
  header("HTTP/1.0 404 Not Found");
  ?>
  <!DOCTYPE html>
  <html>
  <head>
      <title>404 No Encontrado</title>
  </head>
  <body>
      <h1>Error 404</h1>
      <?php
      // Registrar el error
      error_log("Página no encontrada: " . $_SERVER['REQUEST_URI']);
      
      // Mostrar mensaje amigable
      echo "<p>Lo sentimos, la página solicitada no existe.</p>";
      ?>
  </body>
  </html>`,
      },
      preventivo: [
        'Implementar redirecciones 301/302 para URLs obsoletas',
        'Mantener un sitemap.xml actualizado',
        'Verificar regularmente enlaces rotos',
        'Implementar sistema de logs para rastrear 404s frecuentes'
      ],
      impacto: 'Alto en SEO y experiencia de usuario',
      lenguajes: ['JavaScript', 'Python', 'PHP', 'Java', 'Ruby', 'C#', 'Go'],
      recursos: [
        {
          titulo: 'MDN Web Docs - 404',
          url: 'https://developer.mozilla.org/es/docs/Web/HTTP/Status/404'
        },
        {
          titulo: 'Google Search Console - Errores 404',
          url: 'https://support.google.com/webmasters/answer/2409439'
        }
      ]
    },
    {
      codigo: 500,
      tipo: 'Servidor',
      titulo: 'Internal Server Error - Error interno del servidor',
      descripcion: 'Error genérico que ocurre cuando el servidor encuentra una condición inesperada que le impide completar la solicitud.',
      solucion: 'Revisar logs del servidor. Implementar manejo de errores adecuado. Verificar la configuración del servidor.',
      ejemplos: {
        Python: `
  # Django - Manejo de error 500
  from django.http import HttpResponseServerError
  from django.views.decorators.csrf import requires_csrf_token
  
  @requires_csrf_token
  def error_500(request):
      return HttpResponseServerError(
          render(request, '500.html', status=500)
      )
  
  # Flask - Manejo de error 500
  @app.errorhandler(500)
  def error_servidor(error):
      # Registrar el error
      app.logger.error(f'Error del servidor: {error}')
      return render_template('500.html'), 500`,
        Java: `
  // Spring Boot - Manejador de error 500
  @ControllerAdvice
  public class ErrorHandler extends ResponseEntityExceptionHandler {
      
      @ExceptionHandler(Exception.class)
      public ResponseEntity<Object> manejarErrorServidor(
          Exception ex, WebRequest request) {
          
          Map<String, Object> body = new HashMap<>();
          body.put("timestamp", LocalDateTime.now());
          body.put("mensaje", "Error interno del servidor");
          
          // Registrar el error
          logger.error("Error 500: ", ex);
          
          return new ResponseEntity<>(body, HttpStatus.INTERNAL_SERVER_ERROR);
      }
  }`,
        Go: `
  // Go - Middleware para manejar panic y error 500
  func recoveryMiddleware(next http.Handler) http.Handler {
      return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
          defer func() {
              if err := recover(); err != nil {
                  log.Printf("panic: %v", err)
                  http.Error(w, "Error interno del servidor", 
                      http.StatusInternalServerError)
              }
          }()
          next.ServeHTTP(w, r)
      })
  }
  
  func main() {
      mux := http.NewServeMux()
      mux.Handle("/", recoveryMiddleware(
          http.HandlerFunc(miHandler)))
      http.ListenAndServe(":8080", mux)
  }`
      },
      preventivo: [
        'Implementar logging exhaustivo',
        'Configurar monitoreo de recursos del servidor',
        'Implementar circuit breakers',
        'Realizar pruebas de carga',
        'Mantener backups actualizados'
      ],
      impacto: 'Crítico en disponibilidad del servicio',
      lenguajes: ['Python', 'PHP', 'Java', 'Ruby', 'C#', 'Go'],
      recursos: [
        {
          titulo: 'MDN Web Docs - 500',
          url: 'https://developer.mozilla.org/es/docs/Web/HTTP/Status/500'
        }
      ]
    }
  ,
    {
      codigo: 400,
      tipo: 'Cliente',
      titulo: 'Bad Request - Solicitud incorrecta',
      descripcion: 'El servidor no puede procesar la solicitud debido a un error del cliente, como sintaxis incorrecta, tamaño demasiado grande o solicitud malformada.',
      solucion: 'Validar los datos enviados antes de la solicitud. Verificar el formato y estructura de la solicitud. Implementar validación tanto en el cliente como en el servidor.',
      ejemplos: {
        JavaScript: `
  // Validación de formulario antes de enviar
  const validarFormulario = (datos) => {
    const errores = {};
    
    if (!datos.email || !/^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$/i.test(datos.email)) {
      errores.email = 'Email inválido';
    }
    
    if (!datos.password || datos.password.length < 8) {
      errores.password = 'La contraseña debe tener al menos 8 caracteres';
    }
    
    return Object.keys(errores).length === 0 ? null : errores;
  };
  
  // Uso con fetch
  const enviarDatos = async (datos) => {
    const errores = validarFormulario(datos);
    
    if (errores) {
      throw new Error('Datos inválidos: ' + JSON.stringify(errores));
    }
  
    const response = await fetch('/api/usuarios', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(datos),
    });
  
    if (response.status === 400) {
      const error = await response.json();
      throw new Error(error.mensaje);
    }
  
    return response.json();
  };`,
        Python: `
  # Django - Validación de datos
  from django.core.exceptions import ValidationError
  from django.http import JsonResponse
  
  def validar_usuario(request):
      try:
          datos = json.loads(request.body)
          
          if 'email' not in datos:
              raise ValidationError('Email es requerido')
              
          if 'password' not in datos or len(datos['password']) < 8:
              raise ValidationError('Contraseña inválida')
              
          # Más validaciones...
          
          return JsonResponse({
              'mensaje': 'Datos válidos'
          })
          
      except ValidationError as e:
          return JsonResponse({
              'error': str(e)
          }, status=400)
      except json.JSONDecodeError:
          return JsonResponse({
              'error': 'JSON inválido'
          }, status=400)`,
        PHP: `
  <?php
  // Validación de datos en PHP
  function validarDatos($datos) {
      $errores = [];
      
      if (!isset($datos['email']) || !filter_var($datos['email'], FILTER_VALIDATE_EMAIL)) {
          $errores[] = 'Email inválido';
      }
      
      if (!isset($datos['password']) || strlen($datos['password']) < 8) {
          $errores[] = 'La contraseña debe tener al menos 8 caracteres';
      }
      
      return $errores;
  }
  
  // Uso en una API
  try {
      $datos = json_decode(file_get_contents('php://input'), true);
      
      if (!$datos) {
          throw new Exception('JSON inválido');
      }
      
      $errores = validarDatos($datos);
      
      if (count($errores) > 0) {
          http_response_code(400);
          echo json_encode(['errores' => $errores]);
          exit;
      }
      
      // Procesar datos válidos...
      
  } catch (Exception $e) {
      http_response_code(400);
      echo json_encode(['error' => $e->getMessage()]);
      exit;
  }
  ?>`
      },
      preventivo: [
        'Implementar validación exhaustiva en el frontend',
        'Utilizar bibliotecas de validación de esquemas (como Joi, Yup, etc.)',
        'Documentar claramente el formato esperado de las solicitudes',
        'Implementar rate limiting para prevenir abuso',
        'Validar tipos de datos y rangos permitidos'
      ],
      impacto: 'Medio - Afecta la experiencia del usuario y puede causar frustración',
      lenguajes: ['JavaScript', 'Python', 'PHP', 'Java'],
      recursos: [
        {
          titulo: 'MDN Web Docs - 400',
          url: 'https://developer.mozilla.org/es/docs/Web/HTTP/Status/400'
        },
        {
          titulo: 'Guía de validación de datos',
          url: 'https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html'
        }
      ]
    },
    {
      codigo: 401,
      tipo: 'Cliente',
      titulo: 'Unauthorized - No autorizado',
      descripcion: 'El cliente debe autenticarse para obtener la respuesta solicitada. Similar a 403, pero específicamente para casos donde se requiere autenticación y ésta no se ha proporcionado o es inválida.',
      solucion: 'Implementar sistema de autenticación robusto. Manejar tokens de acceso correctamente. Implementar mecanismos de renovación de tokens.',
      ejemplos: {
        JavaScript: `
  // Cliente - Manejo de autenticación con JWT
  class AuthService {
    static async login(credentials) {
      try {
        const response = await fetch('/api/auth/login', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(credentials),
        });
  
        if (response.status === 401) {
          throw new Error('Credenciales inválidas');
        }
  
        const { token } = await response.json();
        localStorage.setItem('token', token);
        return token;
      } catch (error) {
        console.error('Error de autenticación:', error);
        throw error;
      }
    }
  
    static getAuthHeader() {
      const token = localStorage.getItem('token');
      return token ? { Authorization: \`Bearer \${token}\` } : {};
    }
  
    static async makeAuthenticatedRequest(url, options = {}) {
      const headers = {
        ...options.headers,
        ...this.getAuthHeader(),
      };
  
      const response = await fetch(url, { ...options, headers });
  
      if (response.status === 401) {
        // Token expirado o inválido
        localStorage.removeItem('token');
        window.location.href = '/login';
      }
  
      return response;
    }
  }`,
        Python: `
  # Flask - Sistema de autenticación
  from functools import wraps
  from flask import Flask, request, jsonify
  import jwt
  
  app = Flask(__name__)
  app.config['SECRET_KEY'] = 'tu_clave_secreta'
  
  def token_required(f):
      @wraps(f)
      def decorated(*args, **kwargs):
          token = request.headers.get('Authorization')
          
          if not token:
              return jsonify({'mensaje': 'Token faltante'}), 401
              
          try:
              token = token.split(' ')[1]
              data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
          except:
              return jsonify({'mensaje': 'Token inválido'}), 401
              
          return f(*args, **kwargs)
      
      return decorated
  
  @app.route('/api/protegido')
  @token_required
  def ruta_protegida():
      return jsonify({'mensaje': 'Acceso permitido'})
  
  @app.route('/api/login', methods=['POST'])
  def login():
      datos = request.get_json()
      
      # Verificar credenciales...
      
      token = jwt.encode({
          'user_id': user.id,
          'exp': datetime.utcnow() + timedelta(hours=24)
      }, app.config['SECRET_KEY'])
      
      return jsonify({'token': token})`
      },
      preventivo: [
        'Implementar HTTPS para todas las comunicaciones',
        'Usar tokens JWT con tiempo de expiración',
        'Implementar renovación automática de tokens',
        'Mantener una lista de tokens revocados',
        'Implementar autenticación de dos factores'
      ],
      impacto: 'Alto - Puede comprometer la seguridad de los datos',
      lenguajes: ['JavaScript', 'Python', 'PHP', 'Java', 'Ruby'],
      recursos: [
        {
          titulo: 'MDN Web Docs - 401',
          url: 'https://developer.mozilla.org/es/docs/Web/HTTP/Status/401'
        },
        {
          titulo: 'Guía de autenticación JWT',
          url: 'https://jwt.io/introduction'
        }
      ]
    },
    {
        codigo: 403,
        tipo: 'Cliente',
        titulo: 'Forbidden - Acceso Prohibido',
        descripcion: 'El servidor comprende la solicitud pero se niega a autorizarla. A diferencia del error 401, la autenticación no haría diferencia.',
        solucion: 'Verificar permisos de usuario. Implementar control de acceso basado en roles (RBAC). Revisar las políticas de seguridad.',
        ejemplos: {
          Python: `
    # Django - Control de acceso basado en roles
    from django.contrib.auth.decorators import permission_required
    from django.core.exceptions import PermissionDenied
    
    @permission_required('app.puede_acceder_admin', raise_exception=True)
    def vista_admin(request):
        try:
            # Lógica para administradores
            return render(request, 'admin_panel.html')
        except PermissionDenied:
            return render(request, '403.html', status=403)`,
          PHP: `
    // PHP - Control de acceso
    <?php
    class PermissionController {
        public function checkUserPermission($user, $resource) {
            if (!$user->hasPermission($resource)) {
                header('HTTP/1.1 403 Forbidden');
                echo json_encode([
                    'error' => 'No tienes permiso para acceder a este recurso',
                    'required_role' => $resource->getRequiredRole()
                ]);
                exit();
            }
        }
    }
    
    // Uso en un endpoint
    $controller = new PermissionController();
    $controller->checkUserPermission($currentUser, $protectedResource);
    ?>`,
          Java: `
    // Spring Security - Control de acceso
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin/panel")
    public ResponseEntity<?> adminPanel() {
        try {
            // Lógica para panel de administración
            return ResponseEntity.ok(adminService.getDashboardData());
        } catch (AccessDeniedException e) {
            return ResponseEntity
                .status(HttpStatus.FORBIDDEN)
                .body("Acceso denegado: Se requiere rol de administrador");
        }
    }`
        },
        preventivo: [
          'Implementar RBAC (Control de Acceso Basado en Roles)',
          'Mantener una política de mínimo privilegio',
          'Documentar claramente los requisitos de acceso',
          'Auditar intentos de acceso no autorizado',
          'Implementar tiempo de espera en intentos fallidos'
        ],
        impacto: 'Alto - Afecta la seguridad y el acceso a recursos críticos',
        lenguajes: ['Python', 'PHP', 'Java', 'C#'],
        recursos: [
          {
            titulo: 'MDN Web Docs - 403',
            url: 'https://developer.mozilla.org/es/docs/Web/HTTP/Status/403'
          }
        ]
      },
      {
        codigo: 502,
        tipo: 'Servidor',
        titulo: 'Bad Gateway - Puerta de enlace incorrecta',
        descripcion: 'El servidor, mientras actuaba como puerta de enlace o proxy, recibió una respuesta no válida del servidor ascendente.',
        solucion: 'Verificar la configuración del proxy/gateway. Revisar la conectividad con servicios upstream. Implementar reintentos automáticos.',
        ejemplos: {
          JavaScript: `
    // Cliente - Manejo de error 502 con reintentos
    const fetchWithRetry = async (url, options = {}, maxRetries = 3) => {
      let lastError;
      
      for (let i = 0; i < maxRetries; i++) {
        try {
          const response = await fetch(url, options);
          
          if (response.status === 502) {
            throw new Error('Bad Gateway');
          }
          
          return response;
        } catch (error) {
          lastError = error;
          
          // Esperar antes de reintentar (exponential backoff)
          await new Promise(resolve => 
            setTimeout(resolve, Math.pow(2, i) * 1000)
          );
        }
      }
      
      throw lastError;
    };`,
          Nginx: `
    # Configuración de Nginx como proxy inverso
    http {
        upstream backend_servers {
            server backend1.example.com:8080;
            server backend2.example.com:8080 backup;
            
            # Configuración de health checks
            check interval=3000 rise=2 fall=5 timeout=1000;
        }
        
        server {
            listen 80;
            server_name example.com;
            
            location / {
                proxy_pass http://backend_servers;
                proxy_next_upstream error timeout invalid_header http_502;
                proxy_connect_timeout 5s;
                proxy_read_timeout 60s;
                
                # Headers personalizados para debugging
                add_header X-Upstream-Status $upstream_status;
                add_header X-Upstream-Response-Time $upstream_response_time;
            }
        }
    }`,
          Go: `
    // Go - Proxy inverso con manejo de errores
    package main
    
    import (
        "log"
        "net/http"
        "net/http/httputil"
        "net/url"
        "time"
    )
    
    type ReverseProxy struct {
        proxy *httputil.ReverseProxy
        retries int
    }
    
    func NewReverseProxy(target string) (*ReverseProxy, error) {
        url, err := url.Parse(target)
        if err != nil {
            return nil, err
        }
        
        proxy := httputil.NewSingleHostReverseProxy(url)
        
        // Personalizar el manejo de errores
        proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
            log.Printf("Proxy error: %v", err)
            w.WriteHeader(http.StatusBadGateway)
        }
        
        return &ReverseProxy{
            proxy: proxy,
            retries: 3,
        }, nil
    }
    
    func (p *ReverseProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
        for i := 0; i < p.retries; i++ {
            sw := &statusWriter{ResponseWriter: w}
            p.proxy.ServeHTTP(sw, r)
            
            if sw.status != http.StatusBadGateway {
                return
            }
            
            // Esperar antes de reintentar
            time.Sleep(time.Duration(i+1) * time.Second)
        }
    }`
        },
        preventivo: [
          'Implementar monitoreo de servicios upstream',
          'Configurar timeouts apropiados',
          'Implementar circuit breakers',
          'Mantener servicios de backup',
          'Configurar alertas de latencia'
        ],
        impacto: 'Alto - Afecta la disponibilidad de servicios dependientes',
        lenguajes: ['JavaScript', 'Go', 'Nginx', 'Java'],
        recursos: [
          {
            titulo: 'MDN Web Docs - 502',
            url: 'https://developer.mozilla.org/es/docs/Web/HTTP/Status/502'
          }
        ]
      },
      {
        codigo: 503,
        tipo: 'Servidor',
        titulo: 'Service Unavailable - Servicio no disponible',
        descripcion: 'El servidor no está listo para manejar la solicitud. Causas comunes incluyen servidor en mantenimiento o sobrecargado.',
        solucion: 'Implementar balanceo de carga. Configurar auto-scaling. Mostrar página de mantenimiento personalizada.',
        ejemplos: {
          Nginx: `
    # Nginx - Página de mantenimiento
    http {
        server {
            listen 80;
            server_name example.com;
            
            # Archivo para activar/desactivar mantenimiento
            if (-f $document_root/maintenance.enable) {
                return 503;
            }
            
            # Página personalizada para 503
            error_page 503 @maintenance;
            
            location @maintenance {
                root /var/www/maintenance;
                rewrite ^(.*)$ /index.html break;
                add_header Retry-After 3600;
            }
        }
    }`,
          JavaScript: `
    // React - Componente de página de mantenimiento
    import React from 'react';
    
    class ErrorBoundary extends React.Component {
      state = { hasError: false, isMaintenanceMode: false };
    
      static getDerivedStateFromError(error) {
        if (error.response?.status === 503) {
          return { hasError: true, isMaintenanceMode: true };
        }
        return { hasError: true };
      }
    
      render() {
        if (this.state.isMaintenanceMode) {
          return (
            <div className="maintenance-page">
              <h1>🛠️ En Mantenimiento</h1>
              <p>
                Estamos realizando mejoras. 
                Por favor, vuelve a intentarlo en unos minutos.
              </p>
              <button onClick={() => window.location.reload()}>
                Reintentar
              </button>
            </div>
          );
        }
    
        if (this.state.hasError) {
          return <div>Algo salió mal.</div>;
        }
    
        return this.props.children;
      }
    }`,
          Python: `
    # FastAPI - Control de carga y mantenimiento
    from fastapi import FastAPI, Response, status
    from typing import Optional
    import asyncio
    from datetime import datetime
    
    app = FastAPI()
    
    class LoadController:
        def __init__(self):
            self.current_connections = 0
            self.max_connections = 100
            self.maintenance_mode = False
            
        async def check_load(self) -> Optional[Response]:
            if self.maintenance_mode:
                return Response(
                    content="Servidor en mantenimiento",
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    headers={"Retry-After": "3600"}
                )
                
            if self.current_connections >= self.max_connections:
                return Response(
                    content="Servidor sobrecargado",
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    headers={"Retry-After": "30"}
                )
            
            return None
    
    load_controller = LoadController()
    
    @app.middleware("http")
    async def load_control_middleware(request, call_next):
        load_controller.current_connections += 1
        try:
            load_response = await load_controller.check_load()
            if load_response:
                return load_response
            response = await call_next(request)
            return response
        finally:
            load_controller.current_connections -= 1`
        },
        preventivo: [
          'Implementar monitoreo de recursos',
          'Configurar auto-scaling',
          'Mantener página de mantenimiento actualizada',
          'Establecer políticas de control de carga',
          'Planificar ventanas de mantenimiento'
        ],
        impacto: 'Alto - Servicio completamente inaccesible',
        lenguajes: ['Python', 'JavaScript', 'Nginx', 'Go'],
        recursos: [
          {
            titulo: 'MDN Web Docs - 503',
            url: 'https://developer.mozilla.org/es/docs/Web/HTTP/Status/503'
          }
        ]
      },
      {
        codigo: 504,
        tipo: 'Servidor',
        titulo: 'Gateway Timeout - Tiempo de espera agotado',
        descripcion: 'El servidor, mientras actuaba como proxy o gateway, no recibió una respuesta oportuna del servidor ascendente para completar la solicitud.',
        solucion: 'Ajustar configuraciones de timeout. Optimizar servicios lentos. Implementar timeouts progresivos.',
        ejemplos: {
          Nginx: `
    # Nginx - Configuración de timeouts
    http {
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        
        upstream backend {
            server backend1.example.com:8080;
            server backend2.example.com:8080 backup;
            
            # Configuración de health checks
            check interval=3000 rise=2 fall=5 timeout=1000;
        }
        
        server {
            location / {
                proxy_pass http://backend;
                
                # Timeouts específicos para esta ubicación
                proxy_connect_timeout 60;
                proxy_send_timeout 60;
                proxy_read_timeout 60;
                
                # Headers informativos
                add_header X-Upstream-Status $upstream_status;
                add_header X-Upstream-Response-Time $upstream_response_time;
            }
        }
    }`,
          JavaScript: `
    // Cliente - Manejo de timeouts con axios
    import axios from 'axios';
    
    const api = axios.create({
      baseURL: 'https://api.ejemplo.com',
      timeout: 5000, // Timeout global de 5 segundos
    });
    
    const fetchWithProgressiveTimeout = async (url, maxRetries = 3) => {
      for (let i = 0; i < maxRetries; i++) {
        try {
          const timeout = Math.min(5000 * Math.pow(2, i), 30000);
          const response = await api.get(url, { timeout });
          return response.data;
        } catch (error) {
          if (error.code === 'ECONNABORTED' || error.response?.status === 504) {
            console.log(\`Intento \${i + 1} fallido, aumentando timeout...\`);
            continue;
          }
          throw error;
        }
      }
      throw new Error('Máximo de reintentos alcanzado');
    };`,
          Go: `
    // Go - Servidor con timeouts configurables
    package main
    
    import (
        "context"
        "net/http"
        "time"
    )
    
    type TimeoutMiddleware struct {
        handler http.Handler
        timeout time.Duration
    }
    
    func (tm *TimeoutMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
        ctx, cancel := context.WithTimeout(r.Context(), tm.timeout)
        defer cancel()
    
        done := make(chan bool)
        go func() {
            tm.handler.ServeHTTP(w, r.WithContext(ctx))
            done <- true
        }()
    
        select {
        case <-done:
            return
        case <-ctx.Done():
            w.WriteHeader(http.StatusGatewayTimeout)
            w.Write([]byte("Tiempo de espera agotado"))
        }
    }
    
    func main() {
        handler := &TimeoutMiddleware{
            handler: yourHandler,
            timeout: 30 * time.Second,
        }
        http.ListenAndServe(":8080", handler)
    }`
        },
        preventivo: [
          'Configurar timeouts apropiados en cada capa',
          'Implementar circuit breakers',
          'Monitorear latencia de servicios',
          'Mantener servicios de respaldo',
          'Implementar timeouts progresivos'
        ],
        impacto: 'Alto - Puede causar pérdida de datos o inconsistencias',
        lenguajes: ['JavaScript', 'Go', 'Nginx', 'Python'],
        recursos: [
          {
            titulo: 'MDN Web Docs - 504',
            url: 'https://developer.mozilla.org/es/docs/Web/HTTP/Status/504'
          }
        ]
      },
      {
        codigo: 405,
        tipo: 'Cliente',
        titulo: 'Method Not Allowed - Método no permitido',
        descripcion: 'El método solicitado es conocido por el servidor pero no está soportado por el recurso de destino.',
        solucion: 'Verificar el método HTTP usado. Implementar los métodos necesarios. Documentar los métodos permitidos.',
        ejemplos: {
          Python: `
    # Flask - Manejo de métodos permitidos
    from flask import Flask, request, jsonify
    
    app = Flask(__name__)
    
    @app.route('/api/recursos', methods=['GET', 'POST'])
    def manejar_recursos():
        if request.method == 'GET':
            return jsonify(obtener_recursos())
        elif request.method == 'POST':
            return jsonify(crear_recurso(request.json))
            
    @app.errorhandler(405)
    def metodo_no_permitido(error):
        return jsonify({
            'error': 'Método no permitido',
            'metodos_permitidos': error.valid_methods
        }), 405`,
          Express: `
    // Express - Middleware para métodos permitidos
    const methodMiddleware = (allowedMethods) => {
      return (req, res, next) => {
        if (!allowedMethods.includes(req.method)) {
          res.status(405)
             .set('Allow', allowedMethods.join(', '))
             .json({
               error: 'Método no permitido',
               metodosPermitidos: allowedMethods
             });
          return;
        }
        next();
      };
    };
    
    // Uso
    app.use('/api/usuarios', 
      methodMiddleware(['GET', 'POST']),
      (req, res) => {
        // Manejo normal de la ruta
      }
    );`,
          Java: `
    // Spring - Manejo de métodos permitidos
    @RestController
    @RequestMapping("/api/recursos")
    public class RecursoController {
        
        @GetMapping
        public ResponseEntity<?> obtenerRecursos() {
            return ResponseEntity.ok(servicio.obtenerTodos());
        }
        
        @PostMapping
        public ResponseEntity<?> crearRecurso(@RequestBody Recurso recurso) {
            return ResponseEntity.status(201).body(servicio.crear(recurso));
        }
        
        @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
        public ResponseEntity<?> handleMethodNotAllowed(
                HttpRequestMethodNotSupportedException ex) {
            return ResponseEntity
                .status(HttpStatus.METHOD_NOT_ALLOWED)
                .header("Allow", ex.getSupportedHttpMethods().toString())
                .body(Map.of(
                    "error", "Método no permitido",
                    "metodosPermitidos", ex.getSupportedHttpMethods()
                ));
        }
    }`
        },
        preventivo: [
          'Documentar claramente los métodos permitidos',
          'Implementar middleware de validación',
          'Usar los verbos HTTP correctamente',
          'Incluir header Allow en respuestas',
          'Mantener consistencia en la API'
        ],
        impacto: 'Medio - Afecta la usabilidad de la API',
        lenguajes: ['Python', 'JavaScript', 'Java', 'PHP'],
        recursos: [
          {
            titulo: 'MDN Web Docs - 405',
            url: 'https://developer.mozilla.org/es/docs/Web/HTTP/Status/405'
          }
        ]
      },
      {
        codigo: 429,
        tipo: 'Cliente',
        titulo: 'Too Many Requests - Demasiadas peticiones',
        descripcion: 'El usuario ha enviado demasiadas solicitudes en un período de tiempo determinado ("limitación de velocidad").',
        solucion: 'Implementar rate limiting. Usar cola de solicitudes. Informar límites mediante headers.',
        ejemplos: {
          Python: `
    # FastAPI - Rate limiting
    from fastapi import FastAPI, Request
    from fastapi.responses import JSONResponse
    import time
    from collections import defaultdict
    
    app = FastAPI()
    
    # Control de rate limiting simple
    RATE_LIMIT = 10  # solicitudes
    TIME_WINDOW = 60  # segundos
    
    class RateLimiter:
        def __init__(self):
            self.requests = defaultdict(list)
        
        def is_allowed(self, client_ip: str) -> bool:
            now = time.time()
            self.requests[client_ip] = [
                req_time for req_time in self.requests[client_ip]
                if now - req_time < TIME_WINDOW
            ]
            
            if len(self.requests[client_ip]) >= RATE_LIMIT:
                return False
                
            self.requests[client_ip].append(now)
            return True
    
    rate_limiter = RateLimiter()
    
    @app.middleware("http")
    async def rate_limit_middleware(request: Request, call_next):
        client_ip = request.client.host
        
        if not rate_limiter.is_allowed(client_ip):
            return JSONResponse(
                status_code=429,
                content={
                    "error": "Demasiadas solicitudes",
                    "retry_after": TIME_WINDOW
                },
                headers={"Retry-After": str(TIME_WINDOW)}
            )
            
        response = await call_next(request)
        return response`,
          Node: `
    // Express - Rate limiting con Redis
    const express = require('express');
    const Redis = require('ioredis');
    const rateLimit = require('express-rate-limit');
    const RedisStore = require('rate-limit-redis');
    
    const app = express();
    const redis = new Redis();
    
    const limiter = rateLimit({
      store: new RedisStore({
        client: redis,
        prefix: 'rate_limit:',
        // Método personalizado para generar la clave
        getCurrentKey: function(req) {
          return \`\${req.ip}:\${req.path}\`;
        }
      }),
      windowMs: 15 * 60 * 1000, // 15 minutos
      max: 100, // límite por ventana
      message: {
        error: 'Demasiadas solicitudes',
        retry_after: '15 minutos'
      },
      headers: true,
      handler: function (req, res) {
        res.status(429).json({
          error: 'Demasiadas solicitudes',
          retry_after: Math.ceil(res.getHeader('Retry-After') / 60) + ' minutos'
        });
      }
    });
    
    // Aplicar a todas las rutas
    app.use(limiter);
    
    // O a rutas específicas
    app.use('/api/', limiter);`,
          Nginx: `
    # Nginx - Rate limiting
    http {
        # Definir zonas de limitación
        limit_req_zone $binary_remote_addr zone=api_limit:10m rate=10r/s;
        limit_req_zone $binary_remote_addr zone=login_limit:10m rate=1r/s;
        
        # Configurar respuesta personalizada
        limit_req_status 429;
        
        server {
            location /api/ {
                limit_req zone=api_limit burst=20 nodelay;
                
                # Headers informativos
                add_header X-RateLimit-Limit 10;
                add_header X-RateLimit-Remaining $upstream_response_time;
                add_header Retry-After 60;
                
                proxy_pass http://backend;
            }
            
            location /login {
                limit_req zone=login_limit;
                proxy_pass http://auth_backend;
            }
            
            # Página personalizada para 429
            error_page 429 /rate_limit.html;
            location = /rate_limit.html {
                internal;
                root /var/www/error_pages;
            }
        }
    }`
        },
        preventivo: [
          'Implementar rate limiting por IP/usuario',
          'Usar almacenamiento distribuido para límites',
          'Proporcionar headers informativos',
          'Implementar backoff exponencial',
          'Documentar límites de uso'
        ],
        impacto: 'Medio - Protege recursos pero puede afectar usuarios legítimos',
        lenguajes: ['Python', 'JavaScript', 'Nginx', 'Go'],
        recursos: [
          {
            titulo: 'MDN Web Docs - 429',
            url: 'https://developer.mozilla.org/es/docs/Web/HTTP/Status/429'
          }
        ]
      },
      {
        codigo: 413,
        tipo: 'Cliente',
        titulo: 'Payload Too Large - Carga útil demasiado grande',
        descripcion: 'La solicitud es más grande de lo que el servidor está dispuesto o puede procesar.',
        solucion: 'Limitar tamaño de archivos. Implementar carga fragmentada. Comprimir datos cuando sea posible.',
        ejemplos: {
          JavaScript: `
    // Cliente - Validación y compresión de archivos
    const validarYComprimirArchivo = async (file) => {
      const MAX_SIZE = 5 * 1024 * 1024; // 5MB
      
      if (file.size > MAX_SIZE) {
        throw new Error(\`Archivo demasiado grande. Máximo: \${MAX_SIZE/1024/1024}MB\`);
      }
      
      // Si es una imagen, comprimir antes de enviar
      if (file.type.startsWith('image/')) {
        const compressedFile = await compressImage(file, {
          quality: 0.8,
          maxWidth: 1920,
          maxHeight: 1080
        });
        return compressedFile;
      }
      
      return file;
    };
    
    // Subida de archivo con progress y chunks
    const subirArchivo = async (file) => {
      const CHUNK_SIZE = 1024 * 1024; // 1MB
      const chunks = Math.ceil(file.size / CHUNK_SIZE);
      
      for (let i = 0; i < chunks; i++) {
        const chunk = file.slice(
          i * CHUNK_SIZE,
          Math.min((i + 1) * CHUNK_SIZE, file.size)
        );
        
        const formData = new FormData();
        formData.append('chunk', chunk);
        formData.append('chunk_number', i);
        formData.append('total_chunks', chunks);
        
        await fetch('/api/upload', {
          method: 'POST',
          body: formData
        });
      }
    };`,
    Python: `
    # FastAPI - Límites de tamaño y validación
    from fastapi import FastAPI, File, UploadFile, HTTPException
    from fastapi.responses import JSONResponse
    import shutil
    import os
    
    app = FastAPI()
    
    # Configurar límites
    MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB
    ALLOWED_TYPES = ['image/jpeg', 'image/png', 'application/pdf']
    
    @app.post("/upload/")
    async def upload_file(file: UploadFile = File(...)):
        # Validar tipo de archivo
        if file.content_type not in ALLOWED_TYPES:
            raise HTTPException(
                status_code=413,
                detail="Tipo de archivo no permitido"
            )
        
        # Validar tamaño
        file_size = 0
        temp_file = os.path.join("/tmp", file.filename)
        
        with open(temp_file, "wb") as buffer:
            while True:
                chunk = await file.read(1024)
                if not chunk:
                    break
                file_size += len(chunk)
                if file_size > MAX_FILE_SIZE:
                    os.remove(temp_file)
                    raise HTTPException(
                        status_code=413,
                        detail=f"Archivo demasiado grande. Máximo: {MAX_FILE_SIZE/1024/1024}MB"
                    )
                buffer.write(chunk)
        
        return {"filename": file.filename, "size": file_size}`,
          PHP: `
    <?php
    // PHP - Configuración y manejo de archivos grandes
    ini_set('upload_max_filesize', '5M');
    ini_set('post_max_size', '6M');
    ini_set('memory_limit', '128M');
    ini_set('max_execution_time', 300);
    
    class FileUploadHandler {
        private $maxSize = 5242880; // 5MB
        private $allowedTypes = ['image/jpeg', 'image/png', 'application/pdf'];
        private $uploadDir = '/var/www/uploads';
        
        public function handleUpload($file) {
            try {
                $this->validateFile($file);
                $this->processChunkedUpload($file);
                return [
                    'success' => true,
                    'message' => 'Archivo subido correctamente'
                ];
            } catch (Exception $e) {
                header('HTTP/1.1 413 Payload Too Large');
                return [
                    'success' => false,
                    'error' => $e->getMessage()
                ];
            }
        }
        
        private function validateFile($file) {
            if ($file['size'] > $this->maxSize) {
                throw new Exception(
                    'Archivo demasiado grande. Máximo: ' . 
                    ($this->maxSize/1024/1024) . 'MB'
                );
            }
            
            if (!in_array($file['type'], $this->allowedTypes)) {
                throw new Exception('Tipo de archivo no permitido');
            }
        }
        
        private function processChunkedUpload($file) {
            $chunk = isset($_REQUEST["chunk"]) ? intval($_REQUEST["chunk"]) : 0;
            $chunks = isset($_REQUEST["chunks"]) ? intval($_REQUEST["chunks"]) : 0;
            
            $tempFile = "{$this->uploadDir}/temp_{$file['name']}.part";
            
            // Escribir chunk
            $out = @fopen($tempFile . ".part", $chunk == 0 ? "wb" : "ab");
            if ($out) {
                $in = @fopen($file['tmp_name'], "rb");
                if ($in) {
                    while ($buff = fread($in, 4096)) {
                        fwrite($out, $buff);
                    }
                }
                @fclose($in);
                @fclose($out);
                @unlink($file['tmp_name']);
            }
            
            // Verificar si es el último chunk
            if (!$chunks || $chunk == $chunks - 1) {
                rename($tempFile . ".part", $tempFile);
            }
        }
    }
    ?>`,
          Nginx: `
    # Nginx - Configuración para subida de archivos
    http {
        # Configuración general
        client_max_body_size 5M;
        client_body_buffer_size 128k;
        client_body_timeout 60s;
        
        # Configuración para uploads
        server {
            location /upload {
                # Aumentar timeout para subidas grandes
                proxy_read_timeout 600;
                proxy_connect_timeout 600;
                proxy_send_timeout 600;
                
                # Configurar límites por ubicación
                client_max_body_size 5M;
                
                # Headers personalizados
                add_header X-Maximum-Upload-Size 5M;
                
                # Manejar error 413
                error_page 413 /413.json;
                
                # Proxy al backend
                proxy_pass http://backend;
            }
            
            # Respuesta personalizada para 413
            location = /413.json {
                return 413 '{"error": "Archivo demasiado grande", "max_size": "5MB"}';
                default_type application/json;
            }
        }
    }`
        },
        preventivo: [
          'Configurar límites en todas las capas',
          'Implementar validación en el cliente',
          'Usar carga fragmentada para archivos grandes',
          'Comprimir datos cuando sea posible',
          'Documentar límites claramente'
        ],
        impacto: 'Medio - Afecta la capacidad de subir contenido',
        lenguajes: ['JavaScript', 'Python', 'PHP', 'Nginx'],
        recursos: [
          {
            titulo: 'MDN Web Docs - 413',
            url: 'https://developer.mozilla.org/es/docs/Web/HTTP/Status/413'
          }
        ]
      },
      {
        codigo: 408,
        tipo: 'Cliente',
        titulo: 'Request Timeout - Tiempo de espera de solicitud agotado',
        descripcion: 'El servidor cerró la conexión porque el navegador no completó la solicitud dentro del tiempo límite.',
        solucion: 'Optimizar el tiempo de solicitud. Implementar reintentos automáticos. Manejar timeouts en el cliente.',
        ejemplos: {
          JavaScript: `
    // Cliente - Manejo de timeout con retries
    const fetchWithTimeout = async (
      url,
      options = {},
      timeout = 5000,
      maxRetries = 3
    ) => {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), timeout);
      
      const fetchWithRetry = async (retriesLeft) => {
        try {
          const response = await fetch(url, {
            ...options,
            signal: controller.signal
          });
          clearTimeout(timeoutId);
          return response;
        } catch (error) {
          if (error.name === 'AbortError') {
            if (retriesLeft > 0) {
              console.log(\`Reintentando, \${retriesLeft} intentos restantes...\`);
              return fetchWithRetry(retriesLeft - 1);
            }
            throw new Error('Tiempo de espera agotado después de varios intentos');
          }
          throw error;
        }
      };
      
      return fetchWithRetry(maxRetries);
    };
    
    // Uso con async/await
    try {
      const response = await fetchWithTimeout(
        'https://api.ejemplo.com/datos',
        {
          method: 'POST',
          body: JSON.stringify(data)
        },
        5000, // 5 segundos
        3     // 3 intentos
      );
      const data = await response.json();
    } catch (error) {
      console.error('Error:', error);
      // Manejar el error de timeout
    }`,
          Python: `
    # FastAPI - Manejo de timeout
    from fastapi import FastAPI, HTTPException
    from fastapi.responses import JSONResponse
    import asyncio
    from typing import Optional
    
    app = FastAPI()
    
    async def proceso_largo(tiempo_maximo: int) -> dict:
        try:
            async with asyncio.timeout(tiempo_maximo):
                # Simular proceso largo
                await asyncio.sleep(10)
                return {"status": "completado"}
        except asyncio.TimeoutError:
            raise HTTPException(
                status_code=408,
                detail="Tiempo de espera agotado"
            )
    
    @app.get("/proceso-largo/")
    async def ejecutar_proceso(timeout: Optional[int] = 5):
        try:
            resultado = await proceso_largo(timeout)
            return resultado
        except HTTPException as e:
            if e.status_code == 408:
                return JSONResponse(
                    status_code=408,
                    content={
                        "error": "Tiempo de espera agotado",
                        "retry_after": 5
                    },
                    headers={"Retry-After": "5"}
                )
            raise e`,
          PHP: `
    <?php
    // PHP - Control de timeout en scripts largos
    set_time_limit(30); // 30 segundos máximo
    
    class TimeoutHandler {
        private $startTime;
        private $maxExecutionTime;
        
        public function __construct($maxExecutionTime = 30) {
            $this->startTime = time();
            $this->maxExecutionTime = $maxExecutionTime;
        }
        
        public function checkTimeout() {
            if (time() - $this->startTime > $this->maxExecutionTime) {
                header('HTTP/1.1 408 Request Timeout');
                echo json_encode([
                    'error' => 'Tiempo de espera agotado',
                    'retry_after' => 5
                ]);
                exit();
            }
        }
    }
    
    // Uso en un proceso largo
    $handler = new TimeoutHandler(30);
    
    foreach ($largeDataset as $item) {
        $handler->checkTimeout();
        procesarItem($item);
    }
    ?>`
        },
        preventivo: [
          'Implementar timeouts apropiados',
          'Usar procesamiento asíncrono',
          'Implementar reintentos automáticos',
          'Monitorear tiempos de respuesta',
          'Optimizar operaciones lentas'
        ],
        impacto: 'Medio - Puede afectar operaciones largas',
        lenguajes: ['JavaScript', 'Python', 'PHP', 'Node.js'],
        recursos: [
          {
            titulo: 'MDN Web Docs - 408',
            url: 'https://developer.mozilla.org/es/docs/Web/HTTP/Status/408'
          }
        ]
      },
      {
        codigo: 406,
        tipo: 'Cliente',
        titulo: 'Not Acceptable - No aceptable',
        descripcion: 'El servidor no puede producir una respuesta que coincida con las características requeridas por el cliente en sus headers de Accept.',
        solucion: 'Implementar content negotiation. Soportar múltiples formatos de respuesta. Validar headers Accept.',
        ejemplos: {
          Express: `
    // Express - Content negotiation
    app.get('/api/datos', (req, res) => {
      const data = obtenerDatos();
      
      res.format({
        'application/json': () => {
          res.json(data);
        },
        'application/xml': () => {
          res.type('application/xml');
          res.send(convertToXML(data));
        },
        'text/html': () => {
          res.render('datos', { data });
        },
        default: () => {
          res.status(406).json({
            error: 'Formato no soportado',
            formatos_soportados: ['application/json', 'application/xml', 'text/html']
          });
        }
      });
    });
    
    // Función helper para convertir a XML
    const convertToXML = (data) => {
      let xml = '<?xml version="1.0" encoding="UTF-8"?>';
      xml += '<root>';
      for (const [key, value] of Object.entries(data)) {
        xml += \`<\${key}>\${value}</\${key}>\`;
      }
      xml += '</root>';
      return xml;
    };`,
          Python: `
    # FastAPI - Content negotiation
    from fastapi import FastAPI, Response, Request
    from fastapi.responses import JSONResponse, HTMLResponse, XMLResponse
    from typing import Union
    
    app = FastAPI()
    
    class CustomXMLResponse(Response):
        media_type = "application/xml"
    
    @app.get("/api/datos", response_class=Union[JSONResponse, HTMLResponse, CustomXMLResponse])
    async def get_datos(request: Request):
        data = obtener_datos()
        accept = request.headers.get("accept", "application/json")
        
        if "application/json" in accept:
            return JSONResponse(data)
        elif "application/xml" in accept:
            xml_content = convertir_a_xml(data)
            return CustomXMLResponse(content=xml_content)
        elif "text/html" in accept:
            return HTMLResponse(generar_html(data))
        else:
            return JSONResponse(
                status_code=406,
                content={
                    "error": "Formato no soportado",
                    "formatos_soportados": [
                        "application/json",
                        "application/xml",
                        "text/html"
                    ]
                }
            )`,
          Java: `
    // Spring Boot - Content negotiation
    @RestController
    @RequestMapping("/api/datos")
    public class ContentNegotiationController {
    
        @GetMapping(produces = {
            MediaType.APPLICATION_JSON_VALUE,
            MediaType.APPLICATION_XML_VALUE,
            MediaType.TEXT_HTML_VALUE
        })
        public ResponseEntity<?> getDatos(
                @RequestHeader("Accept") String acceptHeader) {
            
            Datos data = obtenerDatos();
            
            if (acceptHeader.contains(MediaType.APPLICATION_JSON_VALUE)) {
                return ResponseEntity.ok(data);
            } else if (acceptHeader.contains(MediaType.APPLICATION_XML_VALUE)) {
                String xml = convertToXML(data);
                return ResponseEntity
                    .ok()
                    .contentType(MediaType.APPLICATION_XML)
                    .body(xml);
            } else if (acceptHeader.contains(MediaType.TEXT_HTML_VALUE)) {
                String html = generateHTML(data);
                return ResponseEntity
                    .ok()
                    .contentType(MediaType.TEXT_HTML)
                    .body(html);
            }
            
            return ResponseEntity
                .status(HttpStatus.NOT_ACCEPTABLE)
                .body("Formato no soportado");
        }
    }`
        },
        preventivo: [
          'Documentar formatos soportados',
          'Implementar content negotiation',
          'Validar headers Accept',
          'Proporcionar conversión entre formatos',
          'Mantener consistencia en las respuestas'
        ],
        impacto: 'Medio - Afecta la interoperabilidad entre sistemas',
        lenguajes: ['JavaScript', 'Python', 'Java', 'PHP'],
        recursos: [
          {
            titulo: 'MDN Web Docs - 406',
            url: 'https://developer.mozilla.org/es/docs/Web/HTTP/Status/406'
          }
        ]
      },
      {
        codigo: 409,
        tipo: 'Cliente',
        titulo: 'Conflict - Conflicto',
        descripcion: 'La solicitud del cliente entra en conflicto con el estado actual del servidor, como un conflicto de versiones o recursos duplicados.',
        solucion: 'Implementar control de concurrencia. Manejar versiones de recursos. Detectar y resolver conflictos.',
        ejemplos: {
          JavaScript: `
    // Cliente - Manejo de conflictos de edición
    class DocumentEditor {
      constructor(documentId) {
        this.documentId = documentId;
        this.version = null;
      }
    
      async loadDocument() {
        const response = await fetch(\`/api/documents/\${this.documentId}\`);
        const data = await response.json();
        this.version = data.version;
        return data;
      }
    
      async saveDocument(content) {
        try {
          const response = await fetch(\`/api/documents/\${this.documentId}\`, {
            method: 'PUT',
            headers: {
              'Content-Type': 'application/json',
              'If-Match': this.version
            },
            body: JSON.stringify({
              content,
              version: this.version
            })
          });
    
          if (response.status === 409) {
            const currentDoc = await this.loadDocument();
            throw new Error('Conflicto de versiones. El documento ha sido modificado.');
          }
    
          const updatedDoc = await response.json();
          this.version = updatedDoc.version;
          return updatedDoc;
        } catch (error) {
          console.error('Error al guardar:', error);
          throw error;
        }
      }
    }`,
          Python: `
    # FastAPI - Control de concurrencia optimista
    from fastapi import FastAPI, HTTPException, Header
    from typing import Optional
    from datetime import datetime
    import hashlib
    
    app = FastAPI()
    
    class Document:
        def __init__(self, id: str, content: str):
            self.id = id
            self.content = content
            self.version = self._calculate_version()
            self.last_modified = datetime.utcnow()
        
        def _calculate_version(self) -> str:
            return hashlib.md5(
                f"{self.content}{self.last_modified}".encode()
            ).hexdigest()
        
        def update(self, content: str):
            self.content = content
            self.last_modified = datetime.utcnow()
            self.version = self._calculate_version()
    
    documents = {}  # Simulación de BD
    
    @app.put("/documents/{doc_id}")
    async def update_document(
        doc_id: str,
        content: dict,
        if_match: Optional[str] = Header(None)
    ):
        if doc_id not in documents:
            raise HTTPException(status_code=404, detail="Documento no encontrado")
        
        doc = documents[doc_id]
        
        if if_match and if_match != doc.version:
            raise HTTPException(
                status_code=409,
                detail={
                    "error": "Conflicto de versiones",
                    "current_version": doc.version,
                    "your_version": if_match
                }
            )
        
        doc.update(content["content"])
        return {
            "id": doc.id,
            "content": doc.content,
            "version": doc.version,
            "last_modified": doc.last_modified
        }`,
          Java: `
    // Spring Boot - Manejo de conflictos
    @RestController
    @RequestMapping("/api/productos")
    public class ProductoController {
    
        @PutMapping("/{id}")
        public ResponseEntity<?> actualizarProducto(
                @PathVariable Long id,
                @RequestBody Producto producto,
                @RequestHeader(value = "If-Match", required = false) String ifMatch) {
            
            try {
                Optional<Producto> existente = 
                    productoService.obtenerPorId(id);
                
                if (existente.isEmpty()) {
                    return ResponseEntity.notFound().build();
                }
                
                Producto productoExistente = existente.get();
                
                // Verificar versión
                if (ifMatch != null && 
                    !ifMatch.equals(productoExistente.getVersion())) {
                    
                    return ResponseEntity
                        .status(HttpStatus.CONFLICT)
                        .body(new ConflictoDTO(
                            "Conflicto de versiones",
                            productoExistente.getVersion(),
                            ifMatch
                        ));
                }
                
                // Actualizar producto
                producto.setId(id);
                producto.setVersion(UUID.randomUUID().toString());
                Producto actualizado = 
                    productoService.actualizar(producto);
                
                return ResponseEntity
                    .ok()
                    .eTag(actualizado.getVersion())
                    .body(actualizado);
                    
            } catch (OptimisticLockingFailureException e) {
                return ResponseEntity
                    .status(HttpStatus.CONFLICT)
                    .body("El recurso ha sido modificado por otro usuario");
            }
        }
    }`
        },
        preventivo: [
          'Implementar control de concurrencia optimista',
          'Usar ETags y headers If-Match',
          'Mantener historial de versiones',
          'Implementar mecanismo de merge',
          'Proporcionar feedback claro al usuario'
        ],
        impacto: 'Alto - Puede resultar en pérdida de datos',
        lenguajes: ['JavaScript', 'Python', 'Java', 'Go'],
        recursos: [
          {
            titulo: 'MDN Web Docs - 409',
            url: 'https://developer.mozilla.org/es/docs/Web/HTTP/Status/409'
          }
        ]
      },
      {
        codigo: 451,
        tipo: 'Cliente',
        titulo: 'Unavailable For Legal Reasons - No disponible por razones legales',
        descripcion: 'El recurso solicitado no está disponible debido a razones legales, como contenido bloqueado por DMCA o restricciones geográficas.',
        solucion: 'Implementar sistema de bloqueo geográfico. Mantener registro de contenido restringido. Proporcionar información legal.',
        ejemplos: {
          Python: `
    # FastAPI - Bloqueo geográfico y legal
    from fastapi import FastAPI, Request, HTTPException
    from typing import Optional
    import geoip2.database
    import datetime
    
    app = FastAPI()
    
    # Base de datos de contenido restringido
    restricted_content = {
        'video123': {
            'restricted_regions': ['US', 'CA'],
            'legal_reason': 'DMCA Takedown Notice',
            'reference': 'DMCA-2023-123456',
            'expires': datetime.datetime(2024, 12, 31)
        }
    }
    
    def get_country_code(ip_address: str) -> str:
        reader = geoip2.database.Reader('GeoLite2-Country.mmdb')
        try:
            response = reader.country(ip_address)
            return response.country.iso_code
        except Exception:
            return None
        finally:
            reader.close()
    
    @app.get("/content/{content_id}")
    async def get_content(
        content_id: str,
        request: Request,
        bypass_code: Optional[str] = None
    ):
        # Verificar si el contenido está restringido
        if content_id in restricted_content:
            restriction = restricted_content[content_id]
            
            # Verificar expiración
            if restriction['expires'] > datetime.datetime.now():
                # Verificar región
                country_code = get_country_code(request.client.host)
                if country_code in restriction['restricted_regions']:
                    raise HTTPException(
                        status_code=451,
                        detail={
                            "error": "Contenido no disponible",
                            "reason": restriction['legal_reason'],
                            "reference": restriction['reference'],
                            "authority": "DMCA",
                            "expires": restriction['expires'].isoformat()
                        },
                        headers={
                            "Link": "</legal-notice>; rel=\"blocked-by\""
                        }
                    )
        
        return {"content": "Contenido solicitado"}`,
          Express: `
    // Express - Middleware de restricción legal
    const express = require('express');
    const geoip = require('geoip-lite');
    
    const app = express();
    
    const restrictedContent = new Map([
      ['article123', {
        restrictedRegions: ['CN', 'RU'],
        legalReason: 'Content restricted by local regulations',
        authority: 'Local Government',
        expires: new Date('2024-12-31')
      }]
    ]);
    
    const legalRestrictionMiddleware = async (req, res, next) => {
      const contentId = req.params.id;
      const restriction = restrictedContent.get(contentId);
      
      if (restriction) {
        const ip = req.ip;
        const geo = geoip.lookup(ip);
        
        if (geo && restriction.restrictedRegions.includes(geo.country)) {
          res.status(451).json({
            error: 'Contenido no disponible en su región',
            reason: restriction.legalReason,
            authority: restriction.authority,
            expires: restriction.expires,
            link: '/legal-notice'
          });
          return;
        }
      }
      
      next();
    };
    
    app.get('/content/:id', legalRestrictionMiddleware, (req, res) => {
      // Servir contenido
      res.json({ content: 'Contenido solicitado' });
    });`,
          PHP: `
    <?php
    // PHP - Sistema de restricción de contenido
    class ContentRestrictionManager {
        private $db;  // Conexión a la base de datos
        private $geoip;  // Servicio de GeoIP
        
        public function __construct($db, $geoip) {
            $this->db = $db;
            $this->geoip = $geoip;
        }
        
        public function checkRestrictions($contentId, $userIp) {
            $restriction = $this->getContentRestriction($contentId);
            
            if ($restriction) {
                $country = $this->geoip->getCountry($userIp);
                
                if (in_array($country, $restriction['restricted_regions'])) {
                    http_response_code(451);
                    header('Link: </legal>; rel="blocked-by"');
                    
                    echo json_encode([
                        'error' => 'Contenido no disponible',
                        'reason' => $restriction['legal_reason'],
                        'authority' => $restriction['authority'],
                'expires' => $restriction['expires']
            ]);
            exit();
        }
    }
    return true;
}

private function getContentRestriction($contentId) {
    $stmt = $this->db->prepare(
        "SELECT * FROM content_restrictions 
         WHERE content_id = ? AND expires > NOW()"
    );
    $stmt->execute([$contentId]);
    return $stmt->fetch();
}
}

// Uso
$manager = new ContentRestrictionManager($db, $geoip);
$manager->checkRestrictions($_GET['content_id'], $_SERVER['REMOTE_ADDR']);
?>`,
    },
    preventivo: [
      'Mantener base de datos de restricciones actualizada',
      'Implementar sistema robusto de geolocalización',
      'Documentar razones legales',
      'Mantener registros de bloqueos',
      'Revisar periódicamente restricciones expiradas'
    ],
    impacto: 'Alto - Implicaciones legales y de cumplimiento',
    lenguajes: ['Python', 'JavaScript', 'PHP', 'Java'],
    recursos: [
      {
        titulo: 'MDN Web Docs - 451',
        url: 'https://developer.mozilla.org/es/docs/Web/HTTP/Status/451'
      }
    ]
  },
  {
    codigo: 426,
    tipo: 'Cliente',
    titulo: 'Upgrade Required - Actualización Requerida',
    descripcion: 'El servidor se niega a realizar la solicitud utilizando el protocolo actual, pero podría estar dispuesto a hacerlo después de que el cliente se actualice a un protocolo diferente.',
    solucion: 'Implementar actualización de protocolo. Manejar transición de HTTP a HTTPS. Gestionar versiones de API.',
    ejemplos: {
      Nginx: `
# Nginx - Forzar HTTPS y versiones de protocolo
server {
    listen 80;
    server_name example.com;

    # Redireccionar todo el tráfico HTTP a HTTPS
    location / {
        return 301 https://$server_name$request_uri;
    }
}

server {
    listen 443 ssl http2;
    server_name example.com;

    # Configuración SSL
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    # Forzar HTTP/2
    location / {
        if ($http2 = "") {
            return 426 '{"error": "Upgrade Required", "message": "Este servidor requiere HTTP/2"}';
        }
        proxy_pass http://backend;
    }
}`,
      Python: `
# FastAPI - Manejo de versiones de API
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from typing import Optional
import semver

app = FastAPI()

MIN_API_VERSION = "2.0.0"

@app.middleware("http")
async def check_api_version(request: Request, call_next):
    api_version = request.headers.get("X-API-Version")
    
    if not api_version:
        return JSONResponse(
            status_code=426,
            content={
                "error": "Versión de API requerida",
                "min_version": MIN_API_VERSION,
                "upgrade_to": "https://api.ejemplo.com/v2"
            },
            headers={"Upgrade": "TLS/1.2, HTTP/2"}
        )
    
    try:
        if semver.compare(api_version, MIN_API_VERSION) < 0:
            return JSONResponse(
                status_code=426,
                content={
                    "error": "Versión de API obsoleta",
                    "current_version": api_version,
                    "required_version": MIN_API_VERSION,
                    "upgrade_to": "https://api.ejemplo.com/v2"
                }
            )
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="Versión de API inválida"
        )
    
    return await call_next(request)

@app.get("/api/data")
async def get_data(request: Request):
    return {"data": "Contenido de la API v2"}`,
      Java: `
// Spring Boot - Protocolo y versión de API
@Component
public class ProtocolUpgradeInterceptor implements HandlerInterceptor {
    
    private static final String MIN_TLS_VERSION = "TLSv1.2";
    private static final String MIN_API_VERSION = "2.0.0";
    
    @Override
    public boolean preHandle(
            HttpServletRequest request,
            HttpServletResponse response,
            Object handler) throws Exception {
        
        // Verificar protocolo SSL/TLS
        String protocol = request.getProtocol();
        if (!isSecureProtocol(protocol)) {
            response.setStatus(HttpServletResponse.SC_UPGRADE_REQUIRED);
            response.setHeader("Upgrade", "TLS/1.2");
            response.getWriter().write(
                "Se requiere una conexión segura (TLS 1.2+)"
            );
            return false;
        }
        
        // Verificar versión de API
        String apiVersion = request.getHeader("X-API-Version");
        if (apiVersion == null || !isValidApiVersion(apiVersion)) {
            response.setStatus(HttpServletResponse.SC_UPGRADE_REQUIRED);
            response.setContentType("application/json");
            response.getWriter().write(String.format(
                "{\\"error\\": \\"Actualización requerida\\", " +
                "\\"min_version\\": \\"%s\\", " +
                "\\"upgrade_url\\": \\"https://api.ejemplo.com/v2\\"}", 
                MIN_API_VERSION
            ));
            return false;
        }
        
        return true;
    }
    
    private boolean isSecureProtocol(String protocol) {
        return protocol != null && 
               protocol.startsWith("TLS") &&
               protocol.compareTo(MIN_TLS_VERSION) >= 0;
    }
    
    private boolean isValidApiVersion(String version) {
        try {
            return SemanticVersion.compare(version, MIN_API_VERSION) >= 0;
        } catch (Exception e) {
            return false;
        }
    }
}`
    },
    preventivo: [
      'Mantener documentación de versiones actualizada',
      'Implementar detección de protocolo',
      'Proporcionar guías de migración',
      'Monitorear uso de versiones obsoletas',
      'Planificar deprecación de versiones'
    ],
    impacto: 'Medio - Afecta la compatibilidad del cliente',
    lenguajes: ['Python', 'Java', 'Nginx', 'Node.js'],
    recursos: [
      {
        titulo: 'MDN Web Docs - 426',
        url: 'https://developer.mozilla.org/es/docs/Web/HTTP/Status/426'
      }
    ]
  },
  {
    codigo: 415,
    tipo: 'Cliente',
    titulo: 'Unsupported Media Type - Tipo de medio no soportado',
    descripcion: 'El servidor rechaza la solicitud porque el formato del contenido de la solicitud no es soportado.',
    solucion: 'Validar tipos de contenido. Documentar formatos soportados. Implementar conversión de formatos.',
    ejemplos: {
      Express: `
// Express - Validación de tipos de contenido
const express = require('express');
const multer = require('multer');
const app = express();

// Configurar tipos de contenido permitidos
const ALLOWED_TYPES = [
  'application/json',
  'multipart/form-data',
  'application/x-www-form-urlencoded'
];

const ALLOWED_FILE_TYPES = [
  'image/jpeg',
  'image/png',
  'application/pdf'
];

// Middleware para validar Content-Type
const validateContentType = (req, res, next) => {
  const contentType = req.header('Content-Type');
  
  if (!contentType || !ALLOWED_TYPES.some(type => 
    contentType.includes(type)
  )) {
    return res.status(415).json({
      error: 'Tipo de contenido no soportado',
      allowed_types: ALLOWED_TYPES
    });
  }
  
  next();
};

// Configuración de multer para archivos
const upload = multer({
  fileFilter: (req, file, cb) => {
    if (ALLOWED_FILE_TYPES.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Tipo de archivo no permitido'), false);
    }
  }
});

// Manejo de error de multer
app.use((error, req, res, next) => {
  if (error instanceof multer.MulterError) {
    return res.status(415).json({
      error: 'Error en la carga de archivo',
      details: error.message,
      allowed_types: ALLOWED_FILE_TYPES
    });
  }
  next(error);
});

// Rutas con validación
app.post('/api/data', 
  validateContentType, 
  (req, res) => {
    res.json({ success: true });
});

app.post('/api/upload',
  upload.single('file'),
  (req, res) => {
    res.json({ 
      success: true,
      file: req.file 
    });
});`,
      Python: `
# FastAPI - Validación de tipos de contenido
from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.responses import JSONResponse
from typing import List
import magic

app = FastAPI()

ALLOWED_MIME_TYPES = {
    'image/jpeg': '.jpg',
    'image/png': '.png',
    'application/pdf': '.pdf'
}

def validate_file_type(file_content: bytes) -> str:
    mime = magic.Magic(mime=True)
    file_type = mime.from_buffer(file_content)
    
    if file_type not in ALLOWED_MIME_TYPES:
        raise HTTPException(
            status_code=415,
            detail={
                "error": "Tipo de archivo no soportado",
                "allowed_types": list(ALLOWED_MIME_TYPES.keys())
            }
        )
    
    return ALLOWED_MIME_TYPES[file_type]

@app.post("/upload/")
async def upload_file(file: UploadFile = File(...)):
    content = await file.read()
    try:
        extension = validate_file_type(content)
        # Procesar archivo...
        return {
            "filename": file.filename,
            "extension": extension,
            "size": len(content)
        }
    except HTTPException as e:
        return JSONResponse(
            status_code=415,
            content=e.detail
        )

@app.post("/api/data")
async def create_data(
    request: Request,
    content_type: str = Header(None)
):
    if content_type != "application/json":
        raise HTTPException(
            status_code=415,
            detail={
                "error": "Solo se acepta application/json",
                "received": content_type
            }
        )
    
    try:
        data = await request.json()
        return {"data": data}
    except JSONDecodeError:
        raise HTTPException(
            status_code=400,
            detail="JSON inválido"
        )`
    },
    preventivo: [
      'Validar tipos MIME',
      'Documentar formatos aceptados',
      'Implementar conversión de formatos',
      'Verificar contenido real vs Content-Type',
      'Manejar errores de parsing'
    ],
    impacto: 'Medio - Afecta la capacidad de procesar datos',
    lenguajes: ['JavaScript', 'Python', 'PHP', 'Java'],
    recursos: [
      {
        titulo: 'MDN Web Docs - 415',
        url: 'https://developer.mozilla.org/es/docs/Web/HTTP/Status/415'
      }
    ]
  },
  {
    codigo: 410,
    tipo: 'Cliente',
    titulo: 'Gone - Ya no disponible',
    descripcion: 'El recurso solicitado ya no está disponible en el servidor y no se conoce dirección de reenvío. Esta condición es permanente.',
    solucion: 'Mantener registro de recursos eliminados. Implementar redirecciones permanentes cuando sea posible. Informar alternativas.',
    ejemplos: {
      Express: `
// Express - Manejo de recursos eliminados
const express = require('express');
const router = express.Router();

// Base de datos de recursos eliminados
const removedResources = new Map();

// Middleware para verificar recursos eliminados
const checkGoneResource = (req, res, next) => {
  const resourceId = req.params.id;
  
  if (removedResources.has(resourceId)) {
    const info = removedResources.get(resourceId);
    return res.status(410).json({
      error: 'Recurso no disponible permanentemente',
      details: info.reason,
      removed_at: info.timestamp,
      alternatives: info.alternatives
    });
  }
  
  next();
};

// Marcar un recurso como eliminado
router.delete('/resources/:id', (req, res) => {
  const { id } = req.params;
  const { reason, alternatives } = req.body;
  
  removedResources.set(id, {
    reason,
    alternatives,
    timestamp: new Date().toISOString()
  });
  
  res.status(200).json({ message: 'Recurso marcado como eliminado' });
});

// Intentar acceder a un recurso
router.get('/resources/:id',
  checkGoneResource,
  (req, res) => {
    // Lógica normal para recursos activos
});`,
      Python: `
# Django - Manejo de recursos eliminados
from django.http import JsonResponse
from django.views import View
from django.utils import timezone
from functools import wraps

class GoneResource:
    def __init__(self, reason, alternatives=None, timestamp=None):
        self.reason = reason
        self.alternatives = alternatives or []
        self.timestamp = timestamp or timezone.now()

# Registro de recursos eliminados
removed_resources = {}

def check_gone_resource(view_func):
    @wraps(view_func)
    def wrapper(request, resource_id, *args, **kwargs):
        if resource_id in removed_resources:
            info = removed_resources[resource_id]
            return JsonResponse({
                'error': 'Recurso eliminado permanentemente',
                'reason': info.reason,
                'removed_at': info.timestamp.isoformat(),
                'alternatives': info.alternatives
            }, status=410)
        return view_func(request, resource_id, *args, **kwargs)
    return wrapper

class ResourceView(View):
    @check_gone_resource
    def get(self, request, resource_id):
        # Lógica normal para recursos activos
        pass
    
    def delete(self, request, resource_id):
        # Marcar como eliminado permanentemente
        removed_resources[resource_id] = GoneResource(
            reason=request.POST.get('reason'),
            alternatives=request.POST.getlist('alternatives')
        )
        
        return JsonResponse({
            'message': 'Recurso marcado como eliminado permanentemente'
        })`,
      Java: `
// Spring Boot - Manejo de recursos eliminados
@Service
public class GoneResourceService {
    private final Map<String, GoneResourceInfo> removedResources = new ConcurrentHashMap<>();
    
    @Data
    @AllArgsConstructor
    public class GoneResourceInfo {
        private String reason;
        private List<String> alternatives;
        private LocalDateTime removedAt;
    }
    
    public void markAsGone(String resourceId, String reason, List<String> alternatives) {
        removedResources.put(resourceId, new GoneResourceInfo(
            reason,
            alternatives,
            LocalDateTime.now()
        ));
    }
    
    public Optional<GoneResourceInfo> getGoneInfo(String resourceId) {
        return Optional.ofNullable(removedResources.get(resourceId));
    }
}

@RestController
@RequestMapping("/api/resources")
public class ResourceController {
    @Autowired
    private GoneResourceService goneService;
    
    @GetMapping("/{id}")
    public ResponseEntity<?> getResource(@PathVariable String id) {
        Optional<GoneResourceInfo> goneInfo = goneService.getGoneInfo(id);
        
        if (goneInfo.isPresent()) {
            GoneResourceInfo info = goneInfo.get();
            return ResponseEntity
                .status(HttpStatus.GONE)
                .body(Map.of(
                    "error", "Recurso eliminado permanentemente",
                    "reason", info.getReason(),
                    "removedAt", info.getRemovedAt(),
                    "alternatives", info.getAlternatives()
                ));
        }
        
        // Lógica normal para recursos activos
        return ResponseEntity.ok(resourceService.getResource(id));
    }
}`
    },
    preventivo: [
      'Mantener registro histórico de recursos eliminados',
      'Implementar redirecciones cuando sea posible',
      'Documentar razones de eliminación',
      'Proporcionar alternativas cuando existan',
      'Mantener limpio el registro de recursos eliminados'
    ],
    impacto: 'Medio - Afecta acceso a recursos históricos',
    lenguajes: ['JavaScript', 'Python', 'Java', 'PHP'],
    recursos: [
      {
        titulo: 'MDN Web Docs - 410',
        url: 'https://developer.mozilla.org/es/docs/Web/HTTP/Status/410'
      }
    ]
  },
  {
    codigo: 414,
    tipo: 'Cliente',
    titulo: 'URI Too Long - URI demasiado larga',
    descripcion: 'La URI solicitada por el cliente es más larga de lo que el servidor está dispuesto a interpretar.',
    solucion: 'Optimizar parámetros de URL. Usar métodos POST para datos extensos. Implementar paginación.',
    ejemplos: {
      Nginx: `
# Nginx - Configuración de límites de URI
http {
    # Limitar tamaño de URI
    large_client_header_buffers 4 16k;
    
    server {
        # Configurar límite específico para esta ubicación
        location /api {
            # Limitar longitud de URI
            if ($request_uri ~* "^.{2048,}$") {
                return 414 '{"error": "URI demasiado larga"}';
            }
            
            proxy_pass http://backend;
        }
    }
}`,
      Python: `
# FastAPI - Manejo de URIs largas
from fastapi import FastAPI, Request, HTTPException
from typing import Optional

app = FastAPI()

MAX_URI_LENGTH = 2048

@app.middleware("http")
async def check_uri_length(request: Request, call_next):
    if len(str(request.url)) > MAX_URI_LENGTH:
        return JSONResponse(
            status_code=414,
            content={
                "error": "URI demasiado larga",
                "max_length": MAX_URI_LENGTH,
                "suggestion": "Utilizar método POST o paginación"
            }
        )
    return await call_next(request)

@app.get("/api/search")
async def search(
    q: str,
    filters: Optional[str] = None,
    page: int = 1,
    page_size: int = 10
):
    # Implementar búsqueda con paginación
    return {
        "results": search_results[
            (page-1)*page_size:page*page_size
        ],
        "total": len(search_results),
        "page": page,
        "page_size": page_size
    }

@app.post("/api/advanced-search")
async def advanced_search(search_params: SearchParams):
    # Manejar búsquedas complejas vía POST
    return {"results": perform_search(search_params)}`,
      Express: `
// Express - Manejo de URIs largas
const express = require('express');
const app = express();

const MAX_URI_LENGTH = 2048;

// Middleware para verificar longitud de URI
app.use((req, res, next) => {
  const uriLength = req.originalUrl.length;
  
  if (uriLength > MAX_URI_LENGTH) {
    return res.status(414).json({
      error: 'URI demasiado larga',
      current_length: uriLength,
      max_length: MAX_URI_LENGTH,
      suggestions: [
        'Usar método POST para consultas complejas',
        'Implementar paginación',
        'Reducir número de parámetros'
      ]
    });
  }
  
  next();
});

// Ejemplo de implementación con paginación
app.get('/api/search', (req, res) => {
  const { query, page = 1, pageSize = 10 } = req.query;
  const start = (page - 1) * pageSize;
  const end = start + pageSize;
  
  const results = performSearch(query);
  
  res.json({
    data: results.slice(start, end),
    pagination: {
      total: results.length,
      page: parseInt(page),
      pageSize: parseInt(pageSize),
      totalPages: Math.ceil(results.length / pageSize)
    }
  });
});

// Alternativa POST para búsquedas complejas
app.post('/api/advanced-search', (req, res) => {
  const searchCriteria = req.body;
  const results = performAdvancedSearch(searchCriteria);
  
  res.json({ results });
});`
    },
    preventivo: [
      'Establecer límites claros de longitud URI',
      'Implementar paginación',
      'Usar POST para datos extensos',
      'Comprimir parámetros cuando sea posible',
      'Documentar límites y alternativas'
    ],
    impacto: 'Medio - Afecta funcionalidad de búsquedas y filtros',
    lenguajes: ['Python', 'JavaScript', 'Nginx', 'PHP'],
    recursos: [
      {
        titulo: 'MDN Web Docs - 414',
        url: 'https://developer.mozilla.org/es/docs/Web/HTTP/Status/414'
      }
    ]
  },
  {
    codigo: 431,
    tipo: 'Cliente',
    titulo: 'Request Header Fields Too Large - Campos de encabezado demasiado grandes',
    descripcion: 'El servidor no está dispuesto a procesar la solicitud porque sus campos de encabezado son demasiado grandes.',
    solucion: 'Limitar tamaño de headers. Optimizar cookies. Implementar limpieza de headers.',
    ejemplos: {
      Nginx: `
# Nginx - Configuración de límites de headers
http {
    # Configurar límites de headers
    large_client_header_buffers 4 8k;
    client_header_buffer_size 1k;
    
    # Configuración específica para servidor
    server {
        location / {
            # Verificar tamaño de cookies
            if ($http_cookie ~* "(.{4096,})") {
                return 431 '{"error": "Headers demasiado grandes"}';
            }
            
            proxy_pass http://backend;
        }
    }
}`,
      Node: `
// Express - Middleware para limitar headers
const MAX_HEADER_SIZE = 8192; // 8KB
const MAX_COOKIE_SIZE = 4096; // 4KB

const headerSizeLimit = (req, res, next) => {
  // Calcular tamaño total de headers
  const headerSize = Object.entries(req.headers)
    .reduce((total, [key, value]) => {
      return total + key.length + value.length;
    }, 0);
  
  // Verificar tamaño de cookies
  const cookies = req.headers.cookie || '';
  const cookieSize = cookies.length;
  
  if (headerSize > MAX_HEADER_SIZE) {
    return res.status(431).json({
      error: 'Headers demasiado grandes',
      current_size: headerSize,
      max_size: MAX_HEADER_SIZE,
      suggestion: 'Reducir número o tamaño de headers'
    });
  }
  
  if (cookieSize > MAX_COOKIE_SIZE) {
    return res.status(431).json({
      error: 'Cookies demasiado grandes',
      current_size: cookieSize,
      max_size: MAX_COOKIE_SIZE,
      suggestion: 'Limpiar cookies antiguas'
    });
  }
  
  next();
};

// Ejemplo de limpieza de cookies
const cleanOldCookies = (req, res) => {
  const cookies = req.cookies;
  const oneMonthAgo = new Date();
  oneMonthAgo.setMonth(oneMonthAgo.getMonth() - 1);
  
  Object.keys(cookies).forEach(name => {
    if (cookies[name].lastAccessed < oneMonthAgo) {
      res.clearCookie(name);
    }
  });
};`,
      Python: `
# FastAPI - Control de tamaño de headers
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse

app = FastAPI()

MAX_HEADER_SIZE = 8192  # 8KB
MAX_COOKIE_SIZE = 4096  # 4KB

@app.middleware("http")
async def check_header_size(request: Request, call_next):
    # Calcular tamaño de headers
    header_size = sum(
        len(key) + len(value)
        for key, value in request.headers.items()
    )
    
    # Verificar cookies
    cookies = request.headers.get('cookie', '')
    cookie_size = len(cookies)
    
    if header_size > MAX_HEADER_SIZE:
        return JSONResponse(
            status_code=431,
            content={
                "error": "Headers demasiado grandes",
                "current_size": header_size,
                "max_size": MAX_HEADER_SIZE
            }
        )
    
    if cookie_size > MAX_COOKIE_SIZE:
        return JSONResponse(
            status_code=431,
            content={
                "error": "Cookies demasiado grandes",
                "current_size": cookie_size,
                "max_size": MAX_COOKIE_SIZE
            }
        )
    
    response = await call_next(request)
    return response

def clean_cookies(request: Request, response):
    """Limpiar cookies antiguas u obsoletas"""
    cookies = request.cookies
    for name, cookie in cookies.items():
        if is_obsolete(cookie):
            response.delete_cookie(name)
    return response`
    },
    preventivo: [
      'Establecer límites de tamaño de headers',
      'Implementar limpieza periódica de cookies',
      'Monitorear tamaño de headers',
      'Optimizar uso de cookies',
      'Documentar límites de headers'
    ],
    impacto: 'Medio - Afecta funcionalidad de autenticación y sesiones',
    lenguajes: ['Python', 'JavaScript', 'Nginx', 'PHP'],
    recursos: [
      {
        titulo: 'MDN Web Docs - 431',
        url: 'https://developer.mozilla.org/es/docs/Web/HTTP/Status/431'
      }
    ]
  }, {
    codigo: 416,
    tipo: 'Cliente',
    titulo: 'Range Not Satisfiable - Rango no satisfactible',
    descripcion: 'El servidor no puede proporcionar la parte del archivo solicitada. El cliente especificó un rango inválido en el header Range.',
    solucion: 'Validar rangos de bytes solicitados. Implementar streaming correcto. Manejar descargas parciales.',
    ejemplos: {
        Express: `
// Express - Manejo de rangos de bytes
const express = require('express');
const fs = require('fs');

app.get('/download/:file', (req, res) => {
    const filePath = \`./files/\${req.params.file}\`;
    const fileSize = fs.statSync(filePath).size;

    const range = req.headers.range;
    if (!range) {
        // Enviar archivo completo si no hay header Range
        return res.sendFile(filePath);
    }

    const parts = range.replace(/bytes=/, "").split("-");
    const start = parseInt(parts[0], 10);
    const end = parts[1] ? parseInt(parts[1], 10) : fileSize - 1;

    // Validar rango
    if (start >= fileSize || end >= fileSize || start > end) {
        res.status(416).json({
            error: 'Rango solicitado no satisfactible',
            fileSize: fileSize,
            requestedRange: range
        });
        return;
    }

    const chunkSize = end - start + 1;
    const file = fs.createReadStream(filePath, { start, end });

    res.writeHead(206, {
        'Content-Range': \`bytes \${start}-\${end}/\${fileSize}\`,
        'Accept-Ranges': 'bytes',
        'Content-Length': chunkSize,
        'Content-Type': 'application/octet-stream'
    });

    file.pipe(res);
});`,
        Python: `
# FastAPI - Streaming de archivos con rangos
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import StreamingResponse
import os

app = FastAPI()

def generate_file_chunks(path: str, start: int, end: int):
    with open(path, 'rb') as f:
        f.seek(start)
        remaining = end - start + 1
        while remaining:
            chunk_size = min(8192, remaining)
            data = f.read(chunk_size)
            if not data:
                break
            yield data
            remaining -= len(data)

@app.get("/files/{filename}")
async def get_file(request: Request, filename: str):
    file_path = f"./files/{filename}"
    file_size = os.path.getsize(file_path)
    
    range_header = request.headers.get('range')
    
    if not range_header:
        return StreamingResponse(
            generate_file_chunks(file_path, 0, file_size - 1),
            media_type='application/octet-stream'
        )
    
    try:
        start_str, end_str = range_header.replace('bytes=', '').split('-')
        start = int(start_str)
        end = int(end_str) if end_str else file_size - 1
        
        if start >= file_size or end >= file_size or start > end:
            raise HTTPException(
                status_code=416,
                detail={
                    "error": "Rango no satisfactible",
                    "file_size": file_size,
                    "requested_range": range_header
                }
            )
        
        headers = {
            'Content-Range': f'bytes {start}-{end}/{file_size}',
            'Accept-Ranges': 'bytes',
            'Content-Length': str(end - start + 1)
        }
        
        return StreamingResponse(
            generate_file_chunks(file_path, start, end),
            status_code=206,
            headers=headers,
            media_type='application/octet-stream'
        )
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="Formato de rango inválido"
        )`
    },
    preventivo: [
        'Validar rangos antes de procesar',
        'Implementar streaming eficiente',
        'Manejar headers Range correctamente',
        'Verificar tamaño de archivo',
        'Implementar caché de rangos comunes'
    ],
    impacto: 'Medio - Afecta descargas y streaming',
    lenguajes: ['JavaScript', 'Python', 'PHP', 'Go'],
    recursos: [
        {
            titulo: 'MDN Web Docs - 416',
            url: 'https://developer.mozilla.org/es/docs/Web/HTTP/Status/416'
        }
    ]
},
{
    codigo: 417,
    tipo: 'Cliente',
    titulo: 'Expectation Failed - Expectativa fallida',
    descripcion: 'El servidor no puede cumplir con los requisitos del header Expect en la solicitud.',
    solucion: 'Validar headers Expect. Implementar manejo de expectativas. Documentar requisitos soportados.',
    ejemplos: {
        Express: `
// Express - Manejo de header Expect
const express = require('express');

// Middleware para validar expectativas
const validateExpectations = (req, res, next) => {
    const expectHeader = req.header('Expect');
    
    if (expectHeader && expectHeader.toLowerCase() !== '100-continue') {
        return res.status(417).json({
            error: 'Expectativa no soportada',
            detail: 'Solo se soporta 100-continue',
            received: expectHeader
        });
    }
    
    if (expectHeader === '100-continue') {
        // Validar si podemos procesar la solicitud
        const contentLength = parseInt(req.header('Content-Length'));
        if (contentLength > 1024 * 1024 * 100) { // 100MB
            return res.status(417).json({
                error: 'Archivo demasiado grande',
                maxSize: '100MB'
            });
        }
        
        res.writeContinue();
    }
    
    next();
};

app.post('/upload',
    validateExpectations,
    (req, res) => {
        // Procesar la carga del archivo
        res.json({ success: true });
    }
);`,
        Python: `
# FastAPI - Manejo de expectativas
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import Response
import asyncio

app = FastAPI()

@app.middleware("http")
async def handle_expectations(request: Request, call_next):
    expect = request.headers.get("Expect")
    
    if expect and expect.lower() != "100-continue":
        return Response(
            status_code=417,
            content={
                "error": "Expectativa no soportada",
                "detail": "Solo se soporta 100-continue",
                "received": expect
            }
        )
    
    if expect == "100-continue":
        try:
            content_length = int(request.headers.get("Content-Length", 0))
            if content_length > 100 * 1024 * 1024:  # 100MB
                return Response(
                    status_code=417,
                    content={
                        "error": "Archivo demasiado grande",
                        "maxSize": "100MB"
                    }
                )
            
            # Enviar 100 Continue
            await request.send_push_promise(
                "100 Continue",
                headers={"Connection": "keep-alive"}
            )
        except ValueError:
            return Response(
                status_code=400,
                content={"error": "Content-Length inválido"}
            )
    
    return await call_next(request)`
    },
    preventivo: [
        'Documentar expectativas soportadas',
        'Validar headers Expect',
        'Implementar 100-continue',
        'Manejar límites de tamaño',
        'Validar capacidades del servidor'
    ],
    impacto: 'Bajo - Afecta operaciones específicas',
    lenguajes: ['JavaScript', 'Python', 'PHP', 'Java'],
    recursos: [
        {
            titulo: 'MDN Web Docs - 417',
            url: 'https://developer.mozilla.org/es/docs/Web/HTTP/Status/417'
        }
    ]
},
{
    codigo: 418,
    tipo: 'Cliente',
    titulo: "I'm a teapot - Soy una tetera",
    descripcion: 'Este código es un error de broma del 1 de abril. Indica que el servidor se niega a preparar café porque es una tetera.',
    solucion: 'Usado principalmente como huevo de pascua o para errores personalizados creativos.',
    ejemplos: {
        Express: `
// Express - Implementación creativa de error 418
const express = require('express');

app.get('/coffee', (req, res) => {
    res.status(418).json({
        error: "I'm a teapot",
        message: "Este servidor solo sirve té",
        suggestion: "Prueba /tea en su lugar"
    });
});

app.get('/tea', (req, res) => {
    res.json({
        message: "¡Aquí tienes tu té! 🫖",
        type: "Earl Grey",
        temperature: "Caliente"
    });
});

// Uso creativo para feature flags
const featureFlags = {
    newFeature: false
};

app.get('/api/new-feature', (req, res) => {
    if (!featureFlags.newFeature) {
        res.status(418).json({
            error: "Feature not ready",
            message: "Esta característica está aún cocinándose",
            available: "Próximamente"
        });
        return;
    }
    
    res.json({ data: "Nueva característica" });
});`,
        Python: `
# FastAPI - Error personalizado divertido
from fastapi import FastAPI, HTTPException
from enum import Enum

app = FastAPI()

class DrinkType(Enum):
    COFFEE = "coffee"
    TEA = "tea"

class TeapotException(HTTPException):
    def __init__(self):
        super().__init__(
            status_code=418,
            detail="I'm a teapot - No puedo preparar café"
        )

@app.get("/brew/{drink_type}")
async def brew_drink(drink_type: DrinkType):
    if drink_type == DrinkType.COFFEE:
        raise TeapotException()
    
    return {
        "message": "Sirviendo té caliente",
        "type": "Earl Grey",
        "temperature": "85°C"
    }

# Uso creativo para mantenimiento
@app.get("/api/data")
async def get_data(system: str):
    maintenance_systems = ["legacy", "old-api"]
    
    if system in maintenance_systems:
        raise HTTPException(
            status_code=418,
            detail={
                "error": "System is having a tea break",
                "message": "Sistema en mantenimiento",
                "retry_after": "2 hours"
            }
        )`
    },
    preventivo: [
        'Usar creativamente para errores personalizados',
        'Implementar mensajes divertidos',
        'Mantener profesionalismo',
        'Documentar usos especiales',
        'Considerar el contexto de uso'
    ],
    impacto: 'Bajo - Error no estándar/creativo',
    lenguajes: ['JavaScript', 'Python', 'PHP', 'Ruby'],
    recursos: [
        {
            titulo: 'MDN Web Docs - 418',
            url: 'https://developer.mozilla.org/es/docs/Web/HTTP/Status/418'
        },
        {
            titulo: 'IETF - HTCPCP',
            url: 'https://tools.ietf.org/html/rfc2324'
        }
    ]
},
{
    codigo: 422,
    tipo: 'Cliente',
    titulo: 'Unprocessable Entity - Entidad no procesable',
    descripcion: 'La solicitud está bien formada pero tiene errores semánticos que impiden su procesamiento.',
    solucion: 'Validar datos de entrada. Implementar validación semántica. Proporcionar mensajes de error claros.',
    ejemplos: {
        Express: `
// Express - Validación semántica
const express = require('express');

// Middleware de validación
const validateUser = (req, res, next) => {
    const { email, password, birthDate } = req.body;
    const errors = [];

    // Validaciones semánticas
    if (email?.includes('@admin')) {
        errors.push('No se permiten emails con @admin');
    }

    if (password?.length >= 8 && !/[A-Z]/.test(password)) {
        errors.push('La contraseña debe contener al menos una mayúscula');
    }

    if (birthDate) {
        const age = new Date().getFullYear() - new Date(birthDate).getFullYear();
        if (age < 18) {
            errors.push('Debe ser mayor de 18 años');
        }
    }

    if (errors.length > 0) {
        return res.status(422).json({
            error: 'Validación semántica fallida',
            details: errors
        });
    }

    next();
};

app.post('/users',
    validateUser,
    (req, res) => {
        res.json({ message: 'Usuario creado' });
    }
);`,
        Python: `
# FastAPI - Validación avanzada
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, validator
from datetime import date, datetime
from typing import List

app = FastAPI()

class User(BaseModel):
    email: str
    password: str
    birth_date: date
    roles: List[str]

    @validator('email')
    def validate_email(cls, v):
        if '@admin' in v:
            raise ValueError('No se permiten emails con @admin')
        return v

    @validator('password')
    def validate_password(cls, v):
        if len(v) >= 8 and not any(c.isupper() for c in v):
            raise ValueError('La contraseña debe contener mayúsculas')
        return v

    @validator('birth_date')
    def validate_age(cls, v):
        age = (datetime.now().date() - v).days / 365
        if age < 18:
            raise ValueError('Debe ser mayor de 18 años')
        return v

    @validator('roles')
    def validate_roles(cls, v):
        if 'admin' in v and len(v) > 1:
            raise ValueError('Admin no puede tener roles adicionales')
        return v

@app.post("/users/")
async def create_user(user: User):
    try:
        # Validaciones adicionales
        if user.roles:
            existing_user = await find_user_by_email(user.email)
            if existing_user and 'admin' in user.roles:
                raise HTTPException(
                    status_code=422,
                    detail={
                        "error": "Validación semántica fallida",
                        "message": "Usuario existente no puede ser admin"
                    }
                )
        
        return {"email": user.email, "roles": user.roles}
    except ValueError as e:
        raise HTTPException(
            status_code=422,
            detail={"error": "Error de validación", "message": str(e)}
        )`,
        Java: `
// Spring Boot - Validación semántica
@RestController
@RequestMapping("/api/users")
public class UserController {

    @PostMapping
    public ResponseEntity<?> createUser(@RequestBody User user) {
        List<String> errors = new ArrayList<>();

        // Validaciones semánticas
        if (user.getEmail().contains("@admin")) {
            errors.add("No se permiten emails con @admin");
        }

        if (user.getPassword().length() >= 8 && 
            !user.getPassword().matches(".*[A-Z].*")) {
            errors.add("La contraseña debe contener mayúsculas");
        }

        if (user.getBirthDate() != null) {
            int age = Period.between(
                user.getBirthDate(), 
                LocalDate.now()
            ).getYears();
            if (age < 18) {
                errors.add("Debe ser mayor de 18 años");
            }
        }

        if (!errors.isEmpty()) {
            return ResponseEntity
                .status(HttpStatus.UNPROCESSABLE_ENTITY)
                .body(Map.of(
                    "error", "Validación semántica fallida",
                    "details", errors
                ));
        }

        return ResponseEntity.ok(userService.createUser(user));
    }
}`
    },
    preventivo: [
        'Implementar validaciones exhaustivas',
        'Separar validación sintáctica y semántica',
        'Proporcionar mensajes de error claros',
        'Validar reglas de negocio',
        'Documentar requerimientos de datos'
    ],
    impacto: 'Alto - Afecta la integridad de datos',
    lenguajes: ['JavaScript', 'Python', 'Java', 'PHP'],
    recursos: [
        {
            titulo: 'MDN Web Docs - 422',
            url: 'https://developer.mozilla.org/es/docs/Web/HTTP/Status/422'
        }
    ]
},
{
    codigo: 423,
    tipo: 'Cliente',
    titulo: 'Locked - Bloqueado',
    descripcion: 'El recurso al que se intenta acceder está bloqueado.',
    solucion: 'Implementar sistema de bloqueos. Manejar concurrencia. Proporcionar información de estado.',
    ejemplos: {
        Python: `
# FastAPI - Sistema de bloqueo de recursos
from fastapi import FastAPI, HTTPException
from datetime import datetime, timedelta
import asyncio
from typing import Dict, Optional

app = FastAPI()

class LockManager:
    def __init__(self):
        self.locks: Dict[str, Dict] = {}

    async def acquire_lock(
        self, 
        resource_id: str, 
        user_id: str, 
        timeout: int = 300
    ) -> bool:
        if resource_id in self.locks:
            lock_info = self.locks[resource_id]
            if (datetime.now() - lock_info['timestamp']) < timedelta(seconds=timeout):
                if lock_info['user_id'] != user_id:
                    return False
            else:
                # El bloqueo expiró
                del self.locks[resource_id]

        self.locks[resource_id] = {
            'user_id': user_id,
            'timestamp': datetime.now()
        }
        return True

    def release_lock(self, resource_id: str, user_id: str) -> bool:
        if (resource_id in self.locks and 
            self.locks[resource_id]['user_id'] == user_id):
            del self.locks[resource_id]
            return True
        return False

    def get_lock_info(self, resource_id: str) -> Optional[Dict]:
        return self.locks.get(resource_id)

lock_manager = LockManager()

@app.post("/resources/{resource_id}/lock")
async def lock_resource(resource_id: str, user_id: str):
    if await lock_manager.acquire_lock(resource_id, user_id):
        return {"message": "Recurso bloqueado exitosamente"}
    
    lock_info = lock_manager.get_lock_info(resource_id)
    raise HTTPException(
        status_code=423,
        detail={
            "error": "Recurso bloqueado",
            "locked_by": lock_info['user_id'],
            "locked_at": lock_info['timestamp'].isoformat(),
            "retry_after": "300 seconds"
        }
    )`,
        Express: `
// Express - Control de bloqueos
const express = require('express');
const LockManager = require('./LockManager');

const lockManager = new LockManager();

// Middleware de bloqueo
const checkLock = async (req, res, next) => {
    const resourceId = req.params.resourceId;
    const userId = req.header('User-Id');

    const lockInfo = lockManager.getLockInfo(resourceId);
    if (lockInfo && lockInfo.userId !== userId) {
        const timeLeft = 300 - 
            Math.floor((Date.now() - lockInfo.timestamp) / 1000);

        if (timeLeft > 0) {
            return res.status(423).json({
                error: 'Recurso bloqueado',
                lockedBy: lockInfo.userId,
                lockedAt: lockInfo.timestamp,
                timeLeft: \`\${timeLeft} segundos\`,
                retryAfter: timeLeft
            });
        }

        // El bloqueo expiró, eliminarlo
        lockManager.releaseLock(resourceId, lockInfo.userId);
    }

    next();
};

app.post('/resources/:resourceId/lock',
    async (req, res) => {
        const { resourceId } = req.params;
        const userId = req.header('User-Id');

        try {
            await lockManager.acquireLock(resourceId, userId);
            res.json({ message: 'Recurso bloqueado exitosamente' });
        } catch (error) {
            res.status(423).json({
                error: 'No se pudo bloquear el recurso',
                message: error.message
            });
        }
    }
);

app.put('/resources/:resourceId',
    checkLock,
    async (req, res) => {
        // Modificar el recurso
        res.json({ message: 'Recurso actualizado' });
    }
);`,
        Java: `
// Spring Boot - Sistema de bloqueos
@Service
public class LockService {
    private final Map<String, LockInfo> locks = new ConcurrentHashMap<>();

    @Data
    @AllArgsConstructor
    public class LockInfo {
        private String userId;
        private LocalDateTime timestamp;
    }

    public boolean acquireLock(String resourceId, String userId) {
        LockInfo existingLock = locks.get(resourceId);
        
        if (existingLock != null) {
            if (Duration.between(
                existingLock.getTimestamp(), 
                LocalDateTime.now()
            ).getSeconds() < 300) {
                return existingLock.getUserId().equals(userId);
            }
            // El bloqueo expiró
            locks.remove(resourceId);
        }

        locks.put(resourceId, new LockInfo(
            userId, 
            LocalDateTime.now()
        ));
        return true;
    }

    public boolean releaseLock(String resourceId, String userId) {
        LockInfo lockInfo = locks.get(resourceId);
        if (lockInfo != null && 
            lockInfo.getUserId().equals(userId)) {
            locks.remove(resourceId);
            return true;
        }
        return false;
    }
}

@RestController
@RequestMapping("/api/resources")
public class ResourceController {
    @Autowired
    private LockService lockService;

    @PostMapping("/{resourceId}/lock")
    public ResponseEntity<?> lockResource(
            @PathVariable String resourceId,
            @RequestHeader("User-Id") String userId) {
        
        if (lockService.acquireLock(resourceId, userId)) {
            return ResponseEntity.ok()
                .body(Map.of("message", "Recurso bloqueado"));
        }

        return ResponseEntity
            .status(HttpStatus.LOCKED)
            .body(Map.of(
                "error", "Recurso bloqueado",
                "message", "Intente más tarde"
            ));
    }
}`
    },
    preventivo: [
        'Implementar timeouts en bloqueos',
        'Manejar expiración automática',
        'Implementar cola de espera',
        'Registrar intentos de acceso',
        'Mantener estado de bloqueos'
    ],
    impacto: 'Alto - Afecta acceso concurrente',
    lenguajes: ['Python', 'JavaScript', 'Java', 'Go'],
    recursos: [
        {
            titulo: 'MDN Web Docs - 423',
            url: 'https://developer.mozilla.org/es/docs/Web/HTTP/Status/423'
        }
    ]
},
{
    codigo: 424,
    tipo: 'Cliente',
    titulo: 'Failed Dependency - Dependencia fallida',
    descripcion: 'La solicitud falló debido a que una solicitud previa falló.',
    solucion: 'Manejar dependencias entre solicitudes. Implementar rollback. Mantener consistencia.',
    ejemplos: {
        Express: `
// Express - Manejo de dependencias
const express = require('express');

// Servicio de órdenes
class OrderService {
    async createOrder(userId, items) {
        // Verificar inventario
        const inventoryCheck = await checkInventory(items);
        if (!inventoryCheck.success) {
            throw new DependencyError(
                'No hay suficiente inventario',
                'inventory'
            );
        }

        // Verificar pago
        const paymentCheck = await processPayment(userId, items);
        if (!paymentCheck.success) {
            // Revertir reserva de inventario
            await releaseInventory(items);
            throw new DependencyError(
                'Fallo en el procesamiento del pago',
                'payment'
            );
        }

        // Crear orden
        return await createOrderRecord(userId, items);
    }
}

class DependencyError extends Error {
    constructor(message, dependency) {
        super(message);
        this.dependency = dependency;
    }
}

app.post('/orders', async (req, res) => {
    const { userId, items } = req.body;
    const orderService = new OrderService();

    try {
        const order = await orderService.createOrder(userId, items);
        res.json(order);
    } catch (error) {
        if (error instanceof DependencyError) {
            res.status(424).json({
                error: 'Fallo de dependencia',
                dependency: error.dependency,
                message: error.message,
                status: 'rolled_back'
            });
            return;
        }
        res.status(500).json({ error: 'Error interno' });
    }
});`,
        Python: `
# FastAPI - Manejo de dependencias en microservicios
from fastapi import FastAPI, HTTPException
from typing import List
import httpx

app = FastAPI()

class DependencyError(Exception):
    def __init__(self, message: str, dependency: str):
        self.message = message
        self.dependency = dependency

async def check_service_health(service: str) -> bool:
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(
                f"http://{service}/health",
                timeout=5.0
            )
            return response.status_code == 200
        except:
            return False

@app.post("/orders/")
async def create_order(order: dict):
    # Verificar servicios dependientes
    services = ["inventory", "payment", "shipping"]
    failed_services = []

    for service in services:
        if not await check_service_health(service):
            failed_services.append(service)

    if failed_services:
        raise HTTPException(
            status_code=424,
            detail={
                "error": "Servicios dependientes no disponibles",
                "failed_services": failed_services,
                "retry_after": 300
            }
        )

    # Proceso de creación de orden
    try:
        # 1. Reservar inventario
        inventory_result = await reserve_inventory(order)
        if not inventory_result["success"]:
            raise DependencyError(
                "Fallo al reservar inventario",
                "inventory"
            )

        # 2. Procesar pago
        payment_result = await process_payment(order)
        if not payment_result["success"]:
            # Rollback inventario
            await release_inventory(order)
            raise DependencyError(
                "Fallo en el pago",
                "payment"
            )

        # 3. Crear envío
        shipping_result = await create_shipping(order)
        if not shipping_result["success"]:
            # Rollback pago e inventario
            await refund_payment(order)
            await release_inventory(order)
            raise DependencyError(
                "Fallo al crear envío",
                "shipping"
            )

        return {"order_id": order["id"], "status": "created"}

    except DependencyError as e:
        raise HTTPException(
            status_code=424,
            detail={
                "error": "Fallo de dependencia",
                "dependency": e.dependency,
                "message": e.message,
                "status": "rolled_back"
            }
        )`
    },
    preventivo: [
        'Verificar dependencias antes de procesar',
        'Implementar circuit breakers',
        'Mantener logs de dependencias',
        'Implementar rollback automático',
        'Monitorear servicios dependientes'
    ],
    impacto: 'Alto - Afecta operaciones encadenadas',
    lenguajes: ['JavaScript', 'Python', 'Java', 'Go'],
    recursos: [
        {
            titulo: 'MDN Web Docs - 424',
            url: 'https://developer.mozilla.org/es/docs/Web/HTTP/Status/424'
        }
    ]
},
{
    codigo: 428,
    tipo: 'Cliente',
    titulo: 'Precondition Required - Precondición requerida',
    descripcion: 'El servidor requiere que la solicitud sea condicional para evitar conflictos.',
    solucion: 'Implementar condiciones previas. Usar headers If-Match/If-None-Match. Prevenir conflictos.',
    ejemplos: {
        Express: `
// Express - Manejo de precondiciones
const express = require('express');

// Middleware para verificar precondiciones
const requirePreconditions = (req, res, next) => {
    const ifMatch = req.header('If-Match');
    const ifNoneMatch = req.header('If-None-Match');

    if (!ifMatch && !ifNoneMatch) {
    return res.status(428).json({
            error: 'Precondición requerida',
            message: 'Se requiere header If-Match o If-None-Match',
            example: 'If-Match: "etag123"'
        });
    }
    next();
};

// Middleware para verificar versión del recurso
const checkResourceVersion = async (req, res, next) => {
    const resourceId = req.params.id;
    const ifMatch = req.header('If-Match');
    
    const resource = await getResource(resourceId);
    if (!resource) {
        return res.status(404).json({ error: 'Recurso no encontrado' });
    }
    
    if (ifMatch !== resource.etag) {
        return res.status(412).json({
            error: 'Precondición fallida',
            message: 'La versión del recurso ha cambiado',
            currentVersion: resource.etag
        });
    }
    
    next();
};

app.put('/resources/:id',
    requirePreconditions,
    checkResourceVersion,
    async (req, res) => {
        // Actualizar recurso
        const updated = await updateResource(req.params.id, req.body);
        res.json(updated);
    }
);`,
        Python: `
# FastAPI - Control de precondiciones
from fastapi import FastAPI, Request, HTTPException, Header
from typing import Optional
import hashlib

app = FastAPI()

class Resource:
    def __init__(self, id: str, data: dict):
        self.id = id
        self.data = data
        self.etag = self._calculate_etag()
    
    def _calculate_etag(self) -> str:
        # Generar ETag basado en los datos
        content = str(self.data).encode()
        return hashlib.md5(content).hexdigest()
    
    def update(self, new_data: dict):
        self.data.update(new_data)
        self.etag = self._calculate_etag()

resources = {}  # Simulación de BD

@app.put("/resources/{resource_id}")
async def update_resource(
    resource_id: str,
    request: Request,
    if_match: Optional[str] = Header(None),
    if_none_match: Optional[str] = Header(None)
):
    if not if_match and not if_none_match:
        raise HTTPException(
            status_code=428,
            detail={
                "error": "Precondición requerida",
                "message": "Se requiere header If-Match o If-None-Match",
                "example": 'If-Match: "etag123"'
            }
        )
    
    resource = resources.get(resource_id)
    if not resource:
        raise HTTPException(
            status_code=404,
            detail="Recurso no encontrado"
        )
    
    if if_match and if_match != resource.etag:
        raise HTTPException(
            status_code=412,
            detail={
                "error": "Precondición fallida",
                "current_version": resource.etag
            }
        )
    
    new_data = await request.json()
    resource.update(new_data)
    
    return {
        "id": resource.id,
        "data": resource.data,
        "etag": resource.etag
    }`,
        Java: `
// Spring Boot - Control de precondiciones
@RestController
@RequestMapping("/api/resources")
public class ResourceController {
    
    @PutMapping("/{id}")
    public ResponseEntity<?> updateResource(
            @PathVariable String id,
            @RequestBody ResourceDTO resource,
            @RequestHeader(value = "If-Match", required = false) String ifMatch,
            @RequestHeader(value = "If-None-Match", required = false) String ifNoneMatch) {
        
        if (ifMatch == null && ifNoneMatch == null) {
            return ResponseEntity
                .status(HttpStatus.PRECONDITION_REQUIRED)
                .body(Map.of(
                    "error", "Precondición requerida",
                    "message", "Se requiere header If-Match o If-None-Match",
                    "example", "If-Match: \"etag123\""
                ));
        }
        
        Resource existingResource = resourceService.findById(id)
            .orElseThrow(() -> new ResourceNotFoundException(id));
        
        if (ifMatch != null && !ifMatch.equals(existingResource.getEtag())) {
            return ResponseEntity
                .status(HttpStatus.PRECONDITION_FAILED)
                .body(Map.of(
                    "error", "Precondición fallida",
                    "currentVersion", existingResource.getEtag()
                ));
        }
        
        Resource updated = resourceService.update(id, resource);
        return ResponseEntity
            .ok()
            .eTag(updated.getEtag())
            .body(updated);
    }
}`
    },
    preventivo: [
        'Implementar manejo de ETags',
        'Validar precondiciones',
        'Mantener versiones de recursos',
        'Detectar conflictos potenciales',
        'Documentar headers requeridos'
    ],
    impacto: 'Medio - Previene conflictos de actualización',
    lenguajes: ['JavaScript', 'Python', 'Java', 'PHP'],
    recursos: [
        {
            titulo: 'MDN Web Docs - 428',
            url: 'https://developer.mozilla.org/es/docs/Web/HTTP/Status/428'
        }
    ]
}

];