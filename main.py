import socket
import json

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives import serialization 
from os import urandom



HOST, PORT = "192.168.0.4", 9999

def send_message(sock, command, message, key):
    """Send a message to the server."""
    res = json.dumps({"command": command,"message": message}, separators=(',', ':'))
    res = encrypt_message(key, res)
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
#parameters = dh.generate_parameters(generator=2, key_size=2048)
#private_key = parameters.generate_private_key()
#public_key = private_key.public_key()

# Perform DH key exchange
def check_file(parameters):
    try:
        private = open("private.pem","rb")
    except OSError:
        print("Private key not found, generating new one.")
        # Generate a new private key
        parameters = dh.generate_parameters(generator=2, key_size=2048)
        with open("dh_parameters.pem", "wb") as f:
            f.write(
               parameters.parameter_bytes(
                   encoding=serialization.Encoding.PEM,
                   format=serialization.ParameterFormat.PKCS3  # PKCS3 is the standard format
               )
            )

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

# Create a socket (SOCK_STREAM means a TCP socket)
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
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

    while True:
        ## Get message from user

        message = input("\nEnter message to send (or 'quit' to exit): ")
        ## Check if user wants to quit
        if message.lower() == 'quit':
            print("Closing connection...")
            send_message(sock, "exit", "closing connection", aes_key)
            break
        ## Send message
        send_message(sock, "send_msg", message, aes_key)

        ## Receive response
        #response = sock.recv(1024)
        #print(f"Response from server: {response.decode()}")
    #sock.sendall(bytes(data, "utf-8"))
    #sock.sendall(b"\n")

    # Receive data from the server and shut down
    #received = str(sock.recv(1024), "utf-8")