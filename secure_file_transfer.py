#!/usr/bin/env python3
"""
Advanced Secure File Transfer System
Implements encrypted file transfer with low-level IP processing
and network performance analysis.
"""

import socket
import threading
import hashlib
import os
import time
import json
from datetime import datetime
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import struct
from scapy.all import *

class SecureFileTransfer:
    """Main class for secure file transfer system"""
    
    def __init__(self, host='localhost', port=8888):
        self.host = host
        self.port = port
        self.buffer_size = 1024
        self.fragment_size = 512
        self.rsa_key = None
        self.performance_data = []
        
        # Generate RSA key pair
        self.generate_rsa_keys()
        
    def generate_rsa_keys(self):
        """Generate RSA key pair for encryption"""
        self.rsa_key = RSA.generate(2048)
        self.public_key = self.rsa_key.publickey()
        print("[+] RSA key pair generated successfully")
        
    def calculate_checksum(self, data):
        """Calculate IP checksum for data integrity"""
        checksum = 0
        # Make sure data length is even
        if len(data) % 2:
            data += b'\x00'
        
        # Sum all 16-bit words
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + data[i + 1]
            checksum += word
            
        # Add carry bits
        while checksum >> 16:
            checksum = (checksum & 0xFFFF) + (checksum >> 16)
            
        # One's complement
        return ~checksum & 0xFFFF
    
    def create_custom_ip_header(self, src_ip, dst_ip, payload_len, ttl=64, flags=0):
        """Create custom IP header with manual field manipulation"""
        version = 4
        ihl = 5  # Internet Header Length
        tos = 0  # Type of Service
        total_len = 20 + payload_len  # IP header + payload
        identification = get_random_bytes(2)
        flags_frag = (flags << 13) | 0  # flags and fragment offset
        protocol = 6  # TCP
        header_checksum = 0  # Will be calculated later
        
        # Pack header without checksum
        header = struct.pack('!BBHHHBBH4s4s',
                           (version << 4) + ihl,  # Version and IHL
                           tos,
                           total_len,
                           int.from_bytes(identification, 'big'),
                           flags_frag,
                           ttl,
                           protocol,
                           header_checksum,
                           socket.inet_aton(src_ip),
                           socket.inet_aton(dst_ip))
        
        # Calculate and update checksum
        checksum = self.calculate_checksum(header)
        header = header[:10] + struct.pack('!H', checksum) + header[12:]
        
        return header
    
    def fragment_data(self, data, fragment_size=None):
        """Fragment large data into smaller chunks"""
        if fragment_size is None:
            fragment_size = self.fragment_size
            
        fragments = []
        for i in range(0, len(data), fragment_size):
            fragment = {
                'id': len(fragments),
                'data': data[i:i + fragment_size],
                'is_last': i + fragment_size >= len(data),
                'total_fragments': (len(data) + fragment_size - 1) // fragment_size
            }
            fragments.append(fragment)
        
        print(f"[+] Data fragmented into {len(fragments)} chunks")
        return fragments
    
    def reassemble_fragments(self, fragments):
        """Reassemble fragmented data"""
        fragments.sort(key=lambda x: x['id'])
        data = b''.join([frag['data'] for frag in fragments])
        print(f"[+] {len(fragments)} fragments reassembled successfully")
        return data
    
    def encrypt_file(self, file_path):
        """Encrypt file using AES encryption"""
        start_time = time.time()
        
        # Generate AES key
        aes_key = get_random_bytes(32)  # 256-bit key
        cipher_aes = AES.new(aes_key, AES.MODE_CBC)
        
        # Read and encrypt file
        with open(file_path, 'rb') as file:
            file_data = file.read()
            
        # Pad data to AES block size
        padded_data = pad(file_data, AES.block_size)
        encrypted_data = cipher_aes.encrypt(padded_data)
        
        # Encrypt AES key with RSA
        cipher_rsa = PKCS1_OAEP.new(self.public_key)
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)
        
        # Create encrypted package
        encrypted_package = {
            'encrypted_key': encrypted_aes_key,
            'iv': cipher_aes.iv,
            'encrypted_data': encrypted_data,
            'original_filename': os.path.basename(file_path),
            'file_hash': hashlib.sha256(file_data).hexdigest()
        }
        
        encryption_time = time.time() - start_time
        print(f"[+] File encrypted in {encryption_time:.3f} seconds")
        
        return encrypted_package
    
    def decrypt_file(self, encrypted_package, output_path):
        """Decrypt file using AES/RSA decryption"""
        start_time = time.time()
        
        # Decrypt AES key with RSA
        cipher_rsa = PKCS1_OAEP.new(self.rsa_key)
        aes_key = cipher_rsa.decrypt(encrypted_package['encrypted_key'])
        
        # Decrypt file data with AES
        cipher_aes = AES.new(aes_key, AES.MODE_CBC, encrypted_package['iv'])
        decrypted_data = cipher_aes.decrypt(encrypted_package['encrypted_data'])
        
        # Remove padding
        file_data = unpad(decrypted_data, AES.block_size)
        
        # Verify file integrity
        file_hash = hashlib.sha256(file_data).hexdigest()
        if file_hash != encrypted_package['file_hash']:
            raise ValueError("File integrity verification failed!")
        
        # Save decrypted file
        with open(output_path, 'wb') as file:
            file.write(file_data)
        
        decryption_time = time.time() - start_time
        print(f"[+] File decrypted and saved in {decryption_time:.3f} seconds")
        print(f"[+] File integrity verified successfully")
        
        return file_data

class FileTransferServer:
    """Server component for file transfer"""
    
    def __init__(self, host='localhost', port=8888):
        self.host = host
        self.port = port
        self.secure_transfer = SecureFileTransfer(host, port)
        
    def start_server(self):
        """Start the file transfer server"""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.host, self.port))
        server_socket.listen(5)
        
        print(f"[+] Server started on {self.host}:{self.port}")
        print("[+] Waiting for connections...")
        
        while True:
            client_socket, client_address = server_socket.accept()
            print(f"[+] Connection from {client_address}")
            
            # Handle client in separate thread
            client_thread = threading.Thread(
                target=self.handle_client,
                args=(client_socket, client_address)
            )
            client_thread.daemon = True
            client_thread.start()
    
    def handle_client(self, client_socket, client_address):
        """Handle individual client connections"""
        try:
            # Send public key to client
            public_key_pem = self.secure_transfer.public_key.export_key()
            client_socket.send(len(public_key_pem).to_bytes(4, 'big'))
            client_socket.send(public_key_pem)
            
            # Receive file data
            data_size = int.from_bytes(client_socket.recv(4), 'big')
            received_data = b''
            
            while len(received_data) < data_size:
                chunk = client_socket.recv(min(1024, data_size - len(received_data)))
                if not chunk:
                    break
                received_data += chunk
            
            # Process received encrypted package
            encrypted_package = json.loads(received_data.decode())
            
            # Convert base64 back to bytes
            import base64
            encrypted_package['encrypted_key'] = base64.b64decode(encrypted_package['encrypted_key'])
            encrypted_package['iv'] = base64.b64decode(encrypted_package['iv'])
            encrypted_package['encrypted_data'] = base64.b64decode(encrypted_package['encrypted_data'])
            
            # Decrypt and save file
            output_path = f"received_{encrypted_package['original_filename']}"
            self.secure_transfer.decrypt_file(encrypted_package, output_path)
            
            # Send confirmation
            client_socket.send(b"File received and decrypted successfully!")
            
        except Exception as e:
            print(f"[-] Error handling client {client_address}: {str(e)}")
        finally:
            client_socket.close()

class FileTransferClient:
    """Client component for file transfer"""
    
    def __init__(self, server_host='localhost', server_port=8888):
        self.server_host = server_host
        self.server_port = server_port
        self.secure_transfer = SecureFileTransfer()
        
    def send_file(self, file_path):
        """Send file to server"""
        start_time = time.time()
        
        try:
            # Connect to server
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((self.server_host, self.server_port))
            print(f"[+] Connected to server {self.server_host}:{self.server_port}")
            
            # Receive server's public key
            key_size = int.from_bytes(client_socket.recv(4), 'big')
            public_key_pem = client_socket.recv(key_size)
            server_public_key = RSA.import_key(public_key_pem)
            
            # Update secure transfer with server's public key
            self.secure_transfer.public_key = server_public_key
            
            # Encrypt file
            encrypted_package = self.secure_transfer.encrypt_file(file_path)
            
            # Convert binary data to base64 for JSON serialization
            import base64
            json_package = {
                'encrypted_key': base64.b64encode(encrypted_package['encrypted_key']).decode(),
                'iv': base64.b64encode(encrypted_package['iv']).decode(),
                'encrypted_data': base64.b64encode(encrypted_package['encrypted_data']).decode(),
                'original_filename': encrypted_package['original_filename'],
                'file_hash': encrypted_package['file_hash']
            }
            
            # Send encrypted package
            package_data = json.dumps(json_package).encode()
            client_socket.send(len(package_data).to_bytes(4, 'big'))
            client_socket.send(package_data)
            
            # Receive confirmation
            response = client_socket.recv(1024).decode()
            print(f"[+] Server response: {response}")
            
            total_time = time.time() - start_time
            file_size = os.path.getsize(file_path)
            transfer_rate = file_size / total_time / 1024  # KB/s
            
            print(f"[+] File transfer completed in {total_time:.3f} seconds")
            print(f"[+] Transfer rate: {transfer_rate:.2f} KB/s")
            
        except Exception as e:
            print(f"[-] Error sending file: {str(e)}")
        finally:
            client_socket.close()

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage:")
        print("  Server mode: python secure_file_transfer.py server")
        print("  Client mode: python secure_file_transfer.py client <file_path>")
        sys.exit(1)
    
    if sys.argv[1] == "server":
        server = FileTransferServer()
        server.start_server()
    elif sys.argv[1] == "client" and len(sys.argv) == 3:
        client = FileTransferClient()
        client.send_file(sys.argv[2])
    else:
        print("Invalid arguments") 