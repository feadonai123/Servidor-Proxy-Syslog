import socket
import threading
import hashlib
import logging
import logging.handlers

SYSLOG_SERVER = 'syslog_server'
SYSLOG_PORT = 514
PROXY_HOST = '0.0.0.0'
PROXY_PORT = 8888

logger = logging.getLogger('SyslogLogger')
logger.setLevel(logging.INFO)

syslog_handler = logging.handlers.SysLogHandler(address=(SYSLOG_SERVER, SYSLOG_PORT))
logger.addHandler(syslog_handler)

def verificar_integridade():
    hasher = hashlib.sha256()
    with open(__file__, 'rb') as f:
        buf = f.read()
        hasher.update(buf)
    return hasher.hexdigest()

def interpret_http_request(request):
    http_methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']
    try:
        request_lines = request.split(b'\r\n')
        first_line = request_lines[0].split(b' ')
        
        method = first_line[0].decode()
        path = first_line[1]
        protocol = first_line[2]

        if method not in http_methods:
            return False, None, None, None, None, None

        host_line = [line for line in request_lines if line.startswith(b'Host:')]
        if not host_line:
            return False, None, None, None, None, None

        host_line = host_line[0].decode().split(': ')
        host = host_line[1].split(':')[0]
        
        port = 80
        if ':' in host_line[1]:
            port = int(host_line[1].split(':')[1])

        return True, method, path, protocol, host, port

    except Exception as e:
        print(f"Erro ao interpretar a requisicao: {e}")
        return False, None, None, None, None, None

def handle_client(client_socket, client_address):
    try:
        request = client_socket.recv(4096)
        is_http, method, path, protocol, host, port = interpret_http_request(request)
        client_ip = client_address[0]
        client_port = client_address[1]
        response_code = None
        
        if not is_http:
            response = b"HTTP/1.1 400 Bad Request\r\nContent-Type: text/html\r\n\r\n"
            response += b"<html><body><h1>Requisicao invalida!</h1></body></html>"
            response_code = 400
            client_socket.sendall(response)
        # Bloqueia acesso ao próprio proxy
        if host in ["localhost", "127.0.0.1", PROXY_HOST] and port == PROXY_PORT:
            response = b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\n\r\n"
            response += b"<html><body><h1>Acesso nao autorizado!</h1></body></html>"
            client_socket.sendall(response)
            response_code = 403
        # Bloqueia acesso a URLs contendo "monitorando"
        elif b'monitorando' in path:
            response = b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\n\r\n"
            response += b"<html><body><h1>Acesso nao autorizado!</h1></body></html>"
            client_socket.sendall(response)
            response_code = 403
        # Conecta ao servidor de destino
        else:
          with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
              server_socket.connect((host, port))
              server_socket.sendall(request)
              # Recebe a resposta do servidor e envia para o cliente
              while True:
                  response = server_socket.recv(4096)
                  if not response:
                      break
                  response_code = int(response.split(b' ')[1])
                  client_socket.sendall(response)
        
        if(is_http):
          logger.info(f"{client_ip}:{client_port} - {method} {path.decode()} {protocol.decode()} | Resposta {response_code}")
          print(f"{client_ip}:{client_port} | {method} {path.decode()} {protocol.decode()} | {response_code}")

    except Exception as e:
        print(f"Erro: {e}")
    finally:
        client_socket.close()

def start_proxy():
    integridade = verificar_integridade()
    print(f"Integridade do proxy: {integridade}")
    logger.info(f"Integridade do proxy: {integridade}")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((PROXY_HOST, PROXY_PORT))
    server.listen(5)
    print(f"Proxy escutando em {PROXY_HOST}:{PROXY_PORT}")

    while True:
        client_socket, client_address = server.accept()
        client_handler = threading.Thread(
            target=handle_client,
            args=(client_socket, client_address)
        )
        client_handler.start()

if __name__ == "__main__":
    start_proxy()
