
#CryptoAuthentication OpenSSL Engine  
[TOC]
##Overview
This is an OpenSSL Engine implementation using ATECC508A for ECC key storage, ECDSA sign/verify, ECDH, and FIPS Random Number Generator

The implementation integrates the [Atmel ATECC508A](http://www.atmel.com/devices/atecc508a.aspx) into the [OpenSSL ENGINE API](http://openssl.org/docs/manmaster/crypto/engine.html) to provide secure hardware key storage, [CAVP certified random numbers](http://csrc.nist.gov/groups/STM/cavp/documents/aes/aesval.html), P256 ECDSA & ECDH, and secure storage for data.

This project will integrate the key creation and import capabilities of the ATECC508A into the OpenSSL key creation and certificate creation process. 

Also, secure key storage for RSA keys are implemented using the encrypted read/write feature of the ATECC508A. 

###Supported Cipher Suites
Many ECDH(E)-ECDSA and ECDHE-RSA cipher suites are supported with the OpenSSL Engine for ATECC508A implementation.  

Details for cipher suites can be found [here](https://github.com/AtmelCSO/cryptoauth-openssl-engine/wiki/Supported-Ciphers)

##Download and Make 
Build instructions for Linux can be found on the Wiki pages associate with this project.

See: [Compile OpenSSL Engine for ATECC508A on Linux](https://github.com/AtmelCSO/cryptoauth-openssl-engine/wiki/Linux:-Compile-OpenSSL-Engine-for-ATECC508A)

##Platform Integration
Follow the platform integration instructions found [here](https://github.com/AtmelCSO/cryptoauth-openssl-engine/wiki/Integrate-ATECC508A-onto-Your-Platform)

##Unit Tests
Unit testing is provided for both integration of the ATECC508A device and OpenSSL Examples.  
For details see:
[Platform Integration Tests](https://github.com/AtmelCSO/cryptoauth-openssl-engine/wiki/ATECC508A-Integration-Tests)
[OpenSSL Engine Tests & Examples](https://github.com/AtmelCSO/cryptoauth-openssl-engine/wiki/Tests-And-Examples)

Source-Level Documentation
Full Doxygen source-level documentation is provided.
See: /docs/doxygen/html/index.html

##Web Server Setup
The OpenSSL Engine for ATECC508A can also be configured. 
See Details [here](https://github.com/AtmelCSO/cryptoauth-openssl-engine/wiki/Web-Server-For-The-Web-Browser).

##Wiki Topics:
- [Linux Development Setup](https://github.com/AtmelCSO/cryptoauth-openssl-engine/wiki/Linux:-Development-Setup)
- [Compiling on Linux](https://github.com/AtmelCSO/cryptoauth-openssl-engine/wiki/Linux:-Compile-OpenSSL-Engine-for-ATECC508A)
- [Debugging on Linux](https://github.com/AtmelCSO/cryptoauth-openssl-engine/wiki/Linux:-Debugging)
- [ATECC508A Integration](https://github.com/AtmelCSO/cryptoauth-openssl-engine/wiki/ATECC508A:-Platform-Integration)
- [ATECC508A Certificate Provisioning](http://www.atmel.com/tools/at88ckeccroot-signer.aspx)
- [Tests and Examples](https://github.com/AtmelCSO/cryptoauth-openssl-engine/wiki/Tests:-OpenSSL-Tests-and-Examples)


