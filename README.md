# Cryptographic System

## Key Management Module
The Key Management Module handles the creation, storing, and retrieval of cryptographic keys for various encryption algorithms. It supports the generation of random keys for symmetric (AES, DES) and asymmetric (RSA, ECC) encryption algorithms. Keys can be loaded from a file when needed and saved for future use, ensuring they are kept safe and available for encryption and decryption processes.

## Authentication
The Authentication module manages user credentials and verifies user identity. It allows users to:
- Register with a username and password.
- Store these credentials securely.
- Verify credentials during login.

This module ensures that only registered users with correct credentials can access the system. It provides methods for registering users, authenticating users, and loading/saving credentials to/from a file.

## Block Cipher Module In AES
The AES module implements a symmetric block cipher using the Advanced Encryption Standard (AES) algorithm. Key features include:
- Support for key sizes of 128, 192, or 256 bits.
- Operation on 128-bit data blocks.
- Padding of plaintext to ensure its length is a multiple of the block size.
- Use of Electronic Codebook (ECB) mode for encryption and decryption.

## Block Cipher Module In DES
The DES module implements the Data Encryption Standard (DES), which is a symmetric encryption algorithm operating on 64-bit data blocks with a 56-bit key. Features include:
- Initialization with 16 or 24 byte keys.
- Padding of plaintext to a multiple of 8 bytes.
- Encryption and decryption in ECB mode.

## Public Key Cryptosystem Module In RSA
The RSA module implements the RSA public-key cryptosystem for secure communication and digital signatures. It includes methods for:
- Encrypting and decrypting data using RSA keys.
- Initialization with an RSA key pair.
- Utilization of the PKCS1 OAEP padding scheme for added security.

## Public Key Cryptosystem Module In ECC
The ECC module implements Elliptic Curve Cryptography (ECC), providing strong security with smaller key sizes compared to RSA. It includes methods for:
- Generating ECC key pairs.
- Performing key exchange for shared secret generation.
- Combining ECC key exchange with AES for encryption.

## Hashing Module In SHA-256
The SHA-256 module provides cryptographic hashing, producing a 256-bit hash result from input data of any size. Features include:
- Collision resistance.
- Preimage resistance.
- Determinism.

Hashing is used for digital signatures, password hashing, and data integrity checking.

## Hashing Module In MD5
The MD5 module calculates the MD5 hash of input data, producing a 128-bit hash value. Features include:
- Use of the hashlib.md5 function for hash calculation.
- Provision of hash value in hexadecimal format.

## Test Cases
### Test User Registration
![User Registration](C:\Users\Laila\Desktop\senior 2.2\security\project images\s1.png)
User 1 added successfully to the credentials file.

### Test User Login
- Entering wrong password for username: user1 => invalid login
  ![Invalid Login](C:\Users\Laila\Desktop\senior 2.2\security\project images\s3.png)
- Entering correct username and password => valid login and entering the plaintext
  ![Valid Login](C:\Users\Laila\Desktop\senior 2.2\security\project images\s4.png)

### Test AES Encryption and Decryption
![AES Encryption and Decryption](C:\Users\Laila\Desktop\senior 2.2\security\project images\s5.png)

### Test DES Encryption and Decryption
![DES Encryption and Decryption](C:\Users\Laila\Desktop\senior 2.2\security\project images\s6.png)

### Test RSA Encryption and Decryption
![RSA Encryption and Decryption](C:\Users\Laila\Desktop\senior 2.2\security\project images\s7.png)

### Test ECC Key Generation and Key Exchange
![ECC Key Generation and Key Exchange](C:\Users\Laila\Desktop\senior 2.2\security\project images\s8.png)

### Test Hashing
![Hashing](C:\Users\Laila\Desktop\senior 2.2\security\project images\s9.png)

### Test Key Generation and Storage
![Key Generation and Storage](C:\Users\Laila\Desktop\senior 2.2\security\project images\s10.png)

