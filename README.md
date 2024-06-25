#Key Management Module:
The creation, storing, and retrieval of cryptographic keys for use in different encryption algorithms are managed by this module. It contains techniques for creating random keys for both symmetric (AES, DES) and asymmetric (RSA, ECC) encryption algorithms. Keys can be loaded from a file when needed and saved to a file for later use. The module makes sure that keys are kept safely and are available for use in encryption and decryption processes.

#Authentication:
This module handles user authentication by managing user credentials and verifying user identity. It allows users to register with a username and password, stores these credentials securely, and verifies them during login. The module ensures that only registered users with correct credentials can access the system. It provides methods for registering users, authenticating users, and loading/saving credentials from/to a file. Users can register, log in, and exit the system based on their choice.

#Block Cypher Module In AES: 
This module is a symmetric block cypher that uses the Advanced Encryption Standard (AES) method to be implemented. AES provides key sizes of 128, 192, or 256 bits and operates on fixed-size data blocks (128 bits, or 16 bytes). A supplied key is used to initialise the BlockCipher class. In the encrypt method, plaintext is padded to ensure its length is a multiple of the block size (16 bytes for AES). This padding guarantees that the plaintext can be divided into equal-sized blocks for encryption. AES is used in Electronic Codebook (ECB) mode to generate the ciphertext. In order to decrypt the plaintext, the decrypt method is used. It reverses the encryption process by utilising the same AES key to decode the ciphertext and eliminating the padding from the decrypted plaintext. Since AES uses fixed-size blocks, padding makes sure the plaintext occupies the full block. 

#Block Cypher Module In DES:
The Block Cipher Module in DES implements the Data Encryption Standard (DES), which is a symmetric encryption algorithm operating on 64-bit blocks of data with a 56-bit key. The DESCipher class in the code uses a supplied key of 16 or 24 bytes (equivalent to 128-bit or 192-bit keys) to initialize a DES cypher object. This class eases encryption and decryption in Electronic Codebook (ECB) mode. The initialized DES cypher is used to encrypt the plaintext once it has been padded to a multiple of 8 bytes (DES block size). Next, the ciphertext is generated. The process of decryption entails taking out the padding from the encrypted plaintext and using the same DES cypher to decrypt the ciphertext.

#Public Key Cryptosystem Module In RSA:
This module implements the RSA public-key cryptosystem, a widely used encryption algorithm for secure communication and digital signatures. It includes methods for encrypting and decrypting data using RSA keys. The RSACryptosystem class initializes with an RSA key pair, comprising a public key for encryption and a private key for decryption. It utilizes the PKCS1 OAEP padding scheme, which adds randomness to the plaintext before encryption, enhancing security against chosen ciphertext attacks. RSA encryption is used to securely transmit data to a recipient who possesses the corresponding private key for decryption.

#Public Key Cryptosystem Module In ECC:
The Elliptic Curve Cryptography (ECC) module implements a public-key cryptosystem that provides strong security with smaller key sizes compared to RSA. It includes methods for generating ECC key pairs and performing key exchange for shared secret generation. The BlockCipherECC class initializes with private and public ECC keys. It utilizes ECC for key exchange and AES for encryption, combining the strengths of both algorithms. ECC key exchange is performed using the ECDH algorithm, which allows two parties to derive a shared secret without transmitting their private keys directly. The shared secret is then used to derive encryption keys using the HKDF algorithm, ensuring secure communication between the parties.

#Hashing Module In SHA-256:
Cryptographic techniques known as hash functions, such SHA-256 (Secure Hash Algorithm 256-bit), produce a fixed-size hash result from input data of any size. 
The SHA-256 hash of the input data can be computed using the HashingModule class. 
Hash functions have a number of characteristics, such as collision resistance (it's hard to find two different inputs that produce the same hash value), preimage resistance (it's computationally impossible to find the input given a hash value), and determinism (the same input always produces the same output). 
Hashing is frequently used for digital signatures, password hashing, data integrity checking, and other purposes. Hashes are one-way functions, which implies that obtaining the original data cannot be achieved by reversing the process.

#Hashing Module In MD5:
The Hashing Module in MD5 provides a way to calculate the MD5 hash of input data. A popular hash algorithm that generates a 128-bit hash value is MD5. The class HashingModuleMD5 implements the calculate_hash function and initializes itself without any parameters. This technique uses the hashlib.md5 function to calculate the MD5 hash of the input data. Hexadecimal representation of the hash value is provided as a result. Hashing ensures data integrity by creating a fixed-size hash value that represents the input data. Even small changes in the input data produce significantly different hash values, making it suitable for verifying data integrity and authenticity.


#Text cases:
##Test User Registration:
<img src="C:\Users\Laila\Desktop\senior 2.2\security\project images\s1">
User 1 added successfully to the credentials file
<img src="C:\Users\Laila\Desktop\senior 2.2\security\project images\s2">
 
##Test User Login:
Entering wrong password for username: user1 => invalid login
<img src="C:\Users\Laila\Desktop\senior 2.2\security\project images\s3">
 
Entering correct username and password => valid login and entering the plaintext
<img src="C:\Users\Laila\Desktop\senior 2.2\security\project images\s4">
 
##Test AES Encryption and Decryption:
<img src="C:\Users\Laila\Desktop\senior 2.2\security\project images\s5">
 
##Test DES Encryption and Decryption:
<img src="C:\Users\Laila\Desktop\senior 2.2\security\project images\s6">
 
##Test RSA Encryption and Decryption:
<img src="C:\Users\Laila\Desktop\senior 2.2\security\project images\s7">
 
##Test ECC Key Generation and Key Exchange:
<img src="C:\Users\Laila\Desktop\senior 2.2\security\project images\s8">
 
##Test Hashing:
<img src="C:\Users\Laila\Desktop\senior 2.2\security\project images\s9">
 
##Test Key Generation and Storage:
<img src="C:\Users\Laila\Desktop\senior 2.2\security\project images\s10">
