Diffie-Hellman-key-exchange
===========================

Diffie Hellman key exchange


Files included:

Utilities.java 
- a class used to provide utilities to encrypt/decrypt files and protocol messages, and to hash Diffie-Hellman key into a usable 128 bit AES key

Server.java
- A file used for receive and decrypt encrypted files from Client(s), using Diffie-Hellman key exchange

Client.java
- A file used for transferring files securely to Server, using Diffie-Hellman key exchange

ServerThread.java
- Class used by Server to set up threads for clients who connect to the Server

README.txt

To compile the program type in command line:
>> javac *.java

To Run program:
Start by running the server first type: java Server [port#] were port# is a free port number of your choosing
The Server is now ready to receive files from the Client

NOTE: After the Client has connected key exchange may take several minutes

To run program in debug mode(this invokes all messages). 
Type java Server port# debug in the command line


The following is how the program works:

1.The server generates a safe prime, generates a 1024 bit random prime q, using probablePrime method of BigInteger class calculates its probability

2. The server sends p to the client using base 64 encoding

3. A primitive root of g is found

4. The server sends g to the client using base 64 encoding, which the Client decodes

5. The server and Client each produce random 1025 bit integers

6. The server computes yb = g^b using fast modular exponentiation

7. The server sends yb to client using base 64 encoding

8. The client computes ya = g^a using fast modular exponentiation 

9. The client sends ya to the Server

10. The server computes ya^b using fast modular exponentiaition, yielding the Diffie-Hellman key

11. The server obtains the MD5 hash of the key to obtain the 128 bit shared key for AES

encryption/decryption
12. The client computes yb^a using fast modular exponentiation

13. The client obtains the MD5 hash of the key to obtain the 128 bit shared key for AES encryption/decryption

