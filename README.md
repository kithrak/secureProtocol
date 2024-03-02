# secureProtocol
Small Experiment to write a Secure Communication protocol using ECC and AES encryption

1) Code is developed using Linux with OpenSSL libraries installed for encryption and decryption 
2) If OpenSSL is not installed follow the below steps( ubuntu) 
  a) sudo apt-get update
  b) sudo apt-get install openssl
  c) sudo apt-get install libssl-dev
3) Makefile is already provided. running "make" will generate client and server executables
4) Now server and client can be run from different terminals.
5) Python script is also present along the code which helps to 500 threads 
	simultaneously for testing purposes if required 
