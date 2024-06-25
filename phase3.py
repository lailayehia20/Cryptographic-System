
from Crypto.Cipher import AES, DES3, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA, ECC
from Crypto.Hash import SHA256
import hashlib
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import ec, padding as asymmetric_padding
import json
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes



# Key Management Module
class KeyManager:
    def __init__(self):
        self.keys = {}

    def generate_and_save_key(self, key_name, key_type):
        if key_type == 'AES' or key_type == 'DES':
            key = get_random_bytes(16)
        elif key_type == 'RSA':
            key_pair = RSA.generate(2048)
            private_key = key_pair.export_key().decode('utf-8')
            public_key = key_pair.publickey().export_key().decode('utf-8')
            key = {
                'private_key': private_key,
                'public_key': public_key
            }
        elif key_type == 'ECC':
            private_key, public_key = generate_ecc_keypair()
            key = {
                'private_key': private_key,
                'public_key': public_key
            }
        else:
            raise ValueError("Invalid key type")

        # Serialize bytes data before storing
        if isinstance(key, bytes):
            key = key.hex()

        self.keys[key_name] = key

    def save_keys_to_file(self, filename):
        with open(filename, 'w') as f:
            json.dump(self.keys, f)

    def load_keys_from_file(self, filename):
        with open(filename, 'r') as f:
            self.keys = json.load(f)

    def get_key(self, key_name):
        return self.keys.get(key_name)


# block cipher module
# block cipher module in AES
class BlockCipher:
    def __init__(self, key):
        self.key = key
        self.cipher = AES.new(self.key, AES.MODE_ECB)

    def encrypt(self, plaintext):
        # Adding padding to the plaintext to be a multiple of 16 bytes (AES block size)
        plaintext = self._pad(plaintext)
        ciphertext = self.cipher.encrypt(plaintext)
        return ciphertext

    def decrypt(self, ciphertext):
        plaintext = self.cipher.decrypt(ciphertext)
        # Removing padding from decrypted plaintext
        plaintext = self._unpad(plaintext)
        return plaintext

    def _pad(self, data):
        # get the number of bytes to pad
        padding_size = AES.block_size - len(data) % AES.block_size
        # Padding with the required number of bytes
        padding = bytes([padding_size] * padding_size)
        return data + padding

    def _unpad(self, data):
        # Removing padding 
        padding_size = data[-1]
        return data[:-padding_size]
    
# Block Cipher Module In DES
class DESCipher:
    def __init__(self, key):
        if len(key) != 16 and len(key) != 24:
            raise ValueError("Triple DES key length must be 16 or 24 bytes")
        self.key = key
        self.cipher = DES3.new(self.key, DES3.MODE_ECB)

    def encrypt(self, plaintext):
        # Padding the plaintext to be a multiple of 8 bytes (DES block size)
        plaintext = self._pad(plaintext)
        ciphertext = self.cipher.encrypt(plaintext)
        return ciphertext

    def decrypt(self, ciphertext):
        plaintext = self.cipher.decrypt(ciphertext)
        # Removing padding from decrypted plaintext
        plaintext = self._unpad(plaintext)
        return plaintext

    def _pad(self, data):
        # Calculate the number of bytes to pad
        padding_size = 8 - len(data) % 8
        # Padding with the required number of bytes
        padding = bytes([padding_size] * padding_size)
        return data + padding

    def _unpad(self, data):
        # Removing padding from the data
        padding_size = data[-1]
        return data[:-padding_size]

    
# Public Key Cryptosystem
# Public Key Cryptosystem Module In RSA
class RSACryptosystem:
    def __init__(self, key_pair):
        self.key_pair = RSA.import_key(key_pair)
        
    def encrypt(self, plaintext):
        cipher_rsa = PKCS1_OAEP.new(self.key_pair)
        ciphertext = cipher_rsa.encrypt(plaintext)
        return ciphertext

    def decrypt(self, ciphertext):
        cipher_rsa = PKCS1_OAEP.new(self.key_pair)
        try:
            plaintext = cipher_rsa.decrypt(ciphertext)
            return plaintext
        except ValueError as e:
            print("Error during decryption:", e)
            return None

    

# Public Key Cryptosystem in ECC
class BlockCipherECC:
    def __init__(self, private_key, public_key):
        self.private_key = serialization.load_pem_private_key(
            private_key.encode(), password=None, backend=default_backend()
        )
        self.public_key = serialization.load_pem_public_key(
            public_key.encode(), backend=default_backend()
        )

    def generate_shared_key(self, peer_public_key):
        shared_key = self.private_key.exchange(ec.ECDH(), peer_public_key)
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
            backend=default_backend()
        ).derive(shared_key)

    def encrypt(self, plaintext):
        shared_key = self.generate_shared_key(self.public_key)
        # Perform encryption using shared key
        iv = get_random_bytes(16)
        cipher = Cipher(algorithms.AES(shared_key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return iv + ciphertext

    def decrypt(self, ciphertext):
        shared_key = self.generate_shared_key(self.public_key)
        # Perform decryption using shared key
        iv = ciphertext[:16]
        ciphertext = ciphertext[16:]
        cipher = Cipher(algorithms.AES(shared_key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext

def generate_ecc_keypair():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    return private_key_pem, public_key_pem




# Hashing module 
# Hashing module in SHA-256
class HashingModule:
    def __init__(self):
        pass

    def calculate_hash(self, data):
        # Creating a hash object (SHA-256)
        sha256_hash = hashlib.sha256()
        # Update the hash object with the data
        sha256_hash.update(data)
        # Calculate the hash value of the data
        digest = sha256_hash.digest()
        return digest.hex()


# # Hashing module in MD5
class HashingModuleMD5:
    def __init__(self):
        pass

    def calculate_hash(self, data):
        # Creating a hash object (MD5)
        md5_hash = hashlib.md5()
        # Update the hash object with the data
        md5_hash.update(data)
        # Calculate the hash value of the data
        digest = md5_hash.digest()
        return digest.hex()


# Authentication Module
class AuthenticationModule:
    def __init__(self):
        self.credentials = {}

    def load_credentials(self, filename):
        with open(filename, 'r') as f:
            self.credentials = json.load(f)

    def save_credentials(self, filename):
        with open(filename, 'w') as f:
            json.dump(self.credentials, f)

    def register_user(self, username, password):
        if username in self.credentials:
            print("User already exists.")
            return False
        else:
            self.credentials[username] = password
            print("User registered successfully.")
            return True

    def authenticate_user(self, username, password):
        if username in self.credentials and self.credentials[username] == password:
            print("Authentication successful.")
            print("................................................\n")
            return True
        else:
            #print("Invalid username or password.")
            return False

   
if __name__ == "__main__":

    # Authentication Module
    auth_module = AuthenticationModule()

    # Load existing credentials or create a new file if it doesn't exist
    try:
        auth_module.load_credentials('credentials.json')
    except FileNotFoundError:
        print("No existing credentials file found.")
        print("Creating a new one.")
        auth_module.save_credentials('credentials.json')

    while True:
        print("\nWelcome to the Authentication Module")
        print("1. Register")
        print("2. Login")
        print("3. Exit")

        choice = input("Enter your choice: ")

        if choice == '1':
            username = input("Enter username: ")
            password = input("Enter password: ")
            auth_module.register_user(username, password)
            auth_module.save_credentials('credentials.json')

        elif choice == '2':
            username = input("Enter username: ")
            password = input("Enter password: ")
            if auth_module.authenticate_user(username, password):
                break  
            else:
                print("Invalid username or password. Please try again.")

        elif choice == '3':
            print("Exiting...")
            break  

        else:
            print("Invalid choice. Please try again.")

    # If user chose to exit, don't continue to the other modules
    if choice != '3':
        # Key Management Module
        # Initialize KeyManager
        key_manager = KeyManager()

        # Generate and save keys
        key_manager.generate_and_save_key('aes_key', 'AES')
        key_manager.generate_and_save_key('des_key', 'DES')
        key_manager.generate_and_save_key('rsa_key', 'RSA')
        key_manager.generate_and_save_key('ecc_key', 'ECC')
        key_manager.save_keys_to_file('keys.json')

        # Loading keys
        key_manager.load_keys_from_file('keys.json')
        aes_key = key_manager.get_key('aes_key')
        des_key = key_manager.get_key('des_key')
        rsa_key = key_manager.get_key('rsa_key')
        ecc_key = key_manager.get_key('ecc_key')


        plaintext = input("Enter the plaintext: ").encode('utf-8')

        # Block cipher module 
        # Block Cipher Module in AES
        # Initialize the block cipher with the AES key
        cipher_aes = BlockCipher(bytes.fromhex(aes_key))
        # Encrypt a plaintext
        ciphertext_aes = cipher_aes.encrypt(plaintext)
        decrypted_text_aes = cipher_aes.decrypt(ciphertext_aes)

        print("Block Cipher Module in AES:")
        print("Plaintext:", plaintext)
        print("Ciphertext:", ciphertext_aes)
        print("Decrypted text:", decrypted_text_aes.decode('utf-8'))
        print("................................................\n")

        # Block Cipher Module in DES
        # Initialize the block cipher with the DES key
        cipher_des = DESCipher(bytes.fromhex(des_key))
        # Encrypt a plaintext
        ciphertext_des = cipher_des.encrypt(plaintext)
        decrypted_text_des = cipher_des.decrypt(ciphertext_des)

        print("Block Cipher Module in DES:")
        print("Plaintext:", plaintext)
        print("Ciphertext:", ciphertext_des)
        print("Decrypted text:", decrypted_text_des.decode('utf-8'))
        print("................................................\n")

        # Public Key Cryptosystem Module
        # Public Key Cryptosystem Module In RSA
        rsa_system = RSACryptosystem(rsa_key['private_key'])  # Using private key for decryption
        ciphertext_rsa = rsa_system.encrypt(plaintext)
        decrypted_text_rsa = rsa_system.decrypt(ciphertext_rsa)
        if decrypted_text_rsa:
            print("Public Key Cryptosystem Module In RSA:")
            print("Plaintext:", plaintext)
            print("Ciphertext:", ciphertext_rsa)
            print("Decrypted text:", decrypted_text_rsa.decode('utf-8'))
        else:
            print("Decryption failed.")
        print("................................................\n")

        # Public Key Cryptosystem Module in ECC
        ecc_cipher = BlockCipherECC(ecc_key['private_key'], ecc_key['public_key'])
        ciphertext_ecc = ecc_cipher.encrypt(plaintext)
        decryptedtext_ecc = ecc_cipher.decrypt(ciphertext_ecc)
        print("Public Key Cryptosystem Module In ECC (ECC for key exchange, AES for encryption):")
        print("Plaintext:", plaintext)
        print("Ciphertext:", ciphertext_ecc)
        print("Decrypted Text:", decryptedtext_ecc)
        print("................................................\n")


        # Hashing Module
        # Hashing module in SHA-256
        # Initialize the hashing module
        hashing_module = HashingModule()
        print("Hashing Module in SHA-256")
        # Calculate the hash of the plaintext
        hash_value = hashing_module.calculate_hash(plaintext)
        print("SHA-256 Hash:", hash_value)
        print("................................................\n")

        # Hashing module in MD5
        # Initialize the hashing module
        hashing_module = HashingModuleMD5()
        print("Hashing Module in MD-5")
        # Calculate the MD5 hash of the data
        hash_value = hashing_module.calculate_hash(plaintext)
        print("MD5 Hash:", hash_value)
        print("................................................\n")
