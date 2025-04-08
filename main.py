import socket
import json
import hashlib
import threading
import queue

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives import serialization 
from os import urandom



HOST, PORT = "100.111.207.45", 9999

stop_threads = False

def send_message(sock, command, message, key):
    """Send a message to the server."""
    res = json.dumps({"command": command,"message": message}, separators=(',', ':'))
    #res = encrypt_message(key, res)
    sock.sendall(res)

def encrypt_message(key, plaintext):
    """Encrypt a message using AES."""
    iv = urandom(16)  # Generate a random IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext  # Prepend IV to ciphertext

def decrypt_message(key, ciphertext):
    """Decrypt a message using AES."""
    iv = ciphertext[:16]  # Extract the IV
    actual_ciphertext = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    unpadder = PKCS7(algorithms.AES.block_size).unpadder()
    padded_plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext.decode()

# Perform DH key exchange
def check_file(parameters):
    try:
        private = open("private.pem","rb")
    except OSError:
        print("Private key not found, generating new one.")
        # Generate a new private key
        private_key = parameters.generate_private_key()
        public_key = private_key.public_key()
        # Save the private key to a file
        with open("private.pem", "wb") as privte:
            privte.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
    else:
        with private:
            private_key = serialization.load_pem_private_key(private.read(), password=None)
    try:
        public = open("public.pem","rb")
    except OSError:
        print("Public key not found, generating new one.")
        # Generate a new public key
        public_key = private_key.public_key()
        # Save the public key to a file
        with open("public.pem", "wb") as pub:
            pub.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
    else:
        with public:
            public_key = serialization.load_pem_public_key(public.read())

    
    return private_key, public_key


def sending_message(sock, aes_key):
    global stop_threads
    while not stop_threads:
        try:
            ## Get message from user
            usr = input("\nEnter username to write to: ")
            while True:
                message = input()
                ## Check if user wants to quit
                if message.lower() == 'quit':
                    send_message(sock, "logout","ZERO", aes_key)
                    print("Closing connection...")
                    stop_threads = True
                    break
                ## Send message
                send_message(sock, "send_msg", {"to":usr,"message":message}, aes_key)
        except Exception as e:
            print(f"Error sending message: {e}")
            stop_threads = True
            break
def recv_message(sock, aes_key):
    global stop_threads
    while not stop_threads:
        ## Get message from user
        try:
            encrypted_data = sock.recv(4096)
            if not encrypted_data:
                print("Server closed the connection.")
                stop_threads = True
                break
            #decrypted_msg = decrypt_message(aes_key, encrypted_data)
            decrypted_msg = encrypted_data
            strct = json.loads(decrypted_msg)
            if strct["command"] == "receive_msg":
                print(f"( {strct['from']} ): {strct['message']}")
            elif strct["command"] == "error":
                print(f"\nError: {strct['message']}",flush=True)
        except Exception as e:
            print(f"Error receiving message: {e}")
            stop_threads = True
            break

message_queue = queue.Queue()

# Create a socket (SOCK_STREAM means a TCP socket)
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    try:
        # Connect to server and send data
        sock.connect((HOST, PORT))

        server_public_key = sock.recv(4096).rstrip()
        server_public_key = serialization.load_pem_public_key(server_public_key)

        private_key, public_key = check_file(server_public_key.parameters())

        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        sock.sendall(public_bytes)

        shared_key = private_key.exchange(server_public_key)
        print(f"Shared secret is {shared_key.hex()}")

        aes_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # 256-bit AES key
            salt=None,
            info=b'handshake data',
        ).derive(shared_key)

        opt = input("\nReguister or login? (r/l): ")
        if opt.lower() == 'r':
            name = input("\nEnter name: ")
            send_message(sock, "check_name", "", aes_key)
            password = input("Enter password: ")
            password = hashlib.sha256(password.encode("utf-8")).hexdigest()
            send_message(sock, "register", {"username": name, "password":password}, aes_key)
        elif opt.lower() == 'l':
            name = input("\nEnter name: ")
            password = input("Enter password: ")
            password = hashlib.sha256(password.encode("utf-8")).hexdigest()
            send_message(sock, "login", {"username": name, "password":password}, aes_key)
        else:
            print("Invalid input, please enter 'r' or 'l'.")

        threading.Thread(target=recv_message, args=(sock, aes_key), daemon=True).start()
        threading.Thread(target=sending_message, args=(sock, aes_key), daemon=True).start()

        while not stop_threads:
            pass

    except Exception as e:
        print(f"Error: {e}")
    finally:
        stop_threads = True
        sock.close()
        print("Socket closed.")