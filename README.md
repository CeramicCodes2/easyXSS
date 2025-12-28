# Descripción
easyXSS es una herramienta CLI escrita en Python para analizar formularios web y realizar fuzzing automatizado de XSS Blind (Cross-Site Scripting a Ciegas). Utiliza BeautifulSoup para extraer campos de formularios, Flask para crear endpoints dinámicos de captura, y un sistema de observadores para manejar payloads desde una wordlist. Ideal para pruebas de seguridad éticas en entornos controlados.

Advertencia: Esta herramienta es solo para fines educativos y de testing de seguridad. No la uses para actividades ilegales. Siempre obtén permiso antes de probar en sistemas ajenos.

Características
Análisis automático de formularios web (GET/POST).
Fuzzing con payloads personalizables.
Soporte para proxies (ej. Burp Suite).
Manejo de CSRF tokens.
Servidor Flask integrado para capturar datos exfiltrados.
Logging detallado y salida JSON.
Instalación
Clona el repositorio:


git clone https://github.com/tu-usuario/easyXSS.gitcd easyXSS
Instala dependencias:


pip install -r requirements.txt
(Crea requirements.txt con: flask, requests, beautifulsoup4)

Uso
Analizar un formulario

python easyXSS.py analyze -u https://ejemplo.com/formulario -a analisis.json --start-server --port 5000
Extrae campos y opcionalmente inicia un servidor para capturar logs.
Fuzzing para XSS Blind

python easyXSS.py fuzz -u https://ejemplo.com/formulario -r analisis.json -X POST -w payloads.txt --csrf --refresh 10
Inyecta payloads y monitorea respuestas.
Opciones
-H: Agregar headers (ej. -H "User-Agent: Mozilla/5.0").
-p: Proxies (ej. -p '{"http":"127.0.0.1:8080"}').
-i: Ignorar campos específicos.
Ejemplos
Analizar y fuzzing básico: Verifica payloads que envíen cookies a tu servidor.
Con proxies: Usa Burp para interceptar requests.
Contribuciones
¡Bienvenidas! Abre issues o pull requests en GitHub.

Licencia
MIT License. Ver LICENSE para detalles.
