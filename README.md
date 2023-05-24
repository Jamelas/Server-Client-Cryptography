# Server-Client-Cryptography
TCP Server/Client using RSA algorithm with Cipher Block Chaining.

This program was created as part of an assignment for a third year Computer Science paper at Massey University. 

## About the Assignment

The source code for a server and client was provided by the teacher (this has been cited in the .cpp files). In the source code provided, the client is able to send messages to the server and the server will reply back to the client with the sent message. These messages are left in a plain state.

The purpose of the assignment was to implement RSA encryption with cipher block chaining, as well as the subsequent decryption. 
Additionally suitable public and private keys for both the Server and Certificate Authority need to be created for use in the encryption/decryption.

## Requirements (summarized from the assignment specifications)

Server:
1. Print on screen the secure server’s: Public key (e, n), Private key (d, n), Certificate issued by a Certification Authority (CA) – make your own dCA(e,n)
2. Print on screen the received encrypted NONCE e(NONCE).
3. Print on screen the decrypted NONCE d(e(NONCE)).
4. Once the NONCE is correctly decrypted, print on screen the ACK transmitted to the client - ACK 220 nonce ok.
5. During the communication session - Print the encrypted message received from the client, Print the decrypted message after applying RSA-CBC.


Client:
1. Print on screen the received certificate from the secure server: dCA(e,n)
2. Print on screen the decrypted certificate from the secure server: eCA(dCA(e,n))
3. Print on screen the ACK transmitted by the client once it has decrypted the certificate of the server successfully: ACK 226 public key received.
4. Print on screen the NONCE.
5. Print on screen the encrypted NONCE e(NONCE).
6. Print ACK transmitted by the client once it has encrypted the NONCE successfully: ACK 226 public key received.
7. During the communication session: Print the plaintext message, Print the encrypted message (using RSA-CBC).


Restrictions:
OpenSSL (or other libraries with built-in cryptographic functions) are not allowed.


## How to use

1. For both the Secure Server and Secure Client, run the makefile provided and then run the executable (first the server and then the client).
2. From the client type the message you want to send and press enter.


## Notes
- Values for the Server's and Certificate Authority are hardcoded. The Server has a Public Key, Private Key, and Private CA Key. The client only has the CA's Public Key.
- After decrypting the message the Server sends the message back in plaintext to the Client. This is for demonstration purposes only (as specified in the brief) as in a real world scenario this would defeat the purpose of using encryption in the first place.
