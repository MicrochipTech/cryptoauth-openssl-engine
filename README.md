# cryptoauth-openssl-engine
OpenSSL Engine implementation using ATECC508 for ECC key storage, ECDSA sign/verify, ECDH, and FIPS Random Number Generator (RNG).
#CryptoAuthentication OpenSSL Engine  

[TOC]
##Overview
The implementation integrates the Atmel ATECC508A[^ecc508] into the OpenSSL ENGINE API’s[engine]()o provide secure hardware key storage, CAVP certified random numbers[^nist], P256 ECDSA & ECDH, and secure storage for data.

This project will integrate the key creation and import capabilities of the ATECC508 into the OpenSSL key creation and certificate creation process. 

Also, secure key storage for RSA keys are implemented using the encrypted read/write feature of the ATECC508A. 

###Supported Cipher Suites
[RFC5289](http://tools.ietf.org/html/rfc5289)
TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256
TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256

TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256

[RFC7251](http://tools.ietf.org/html/rfc7251)
TLS_ECDHE_ECDSA_WITH_AES_128_CCM

[RFC4492](http://tools.ietf.org/html/rfc4492)
TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA

##Download and Make 
Build instructions for Linux can be found on the Wiki pages associate with this project.
See: [Compile OpenSSL Engine for ATECC508 on Linux](https://github.com/AtmelCSO/cryptoauth-openssl-engine/wiki/Compile-OpenSSL-Engine-for-ATECC508-on-Linux)

##Platform Integration
Follow the platform integration instructions found [here](https://github.com/AtmelCSO/cryptoauth-openssl-engine/wiki/Integrate-ATECC508-onto-Your-Platform)

##Unit Tests
[Platform Integration Tests](https://github.com/AtmelCSO/cryptoauth-openssl-engine/wiki/ATECC508A-Integration-Tests)
[OpenSSL Engine Tests & Examples](https://github.com/AtmelCSO/cryptoauth-openssl-engine/wiki/Tests-And-Examples)

Source-Level Documentation
- Doxygen

ENGINE
Client/Server

##Web Server Example


##Wiki Topics:
Debugging on Linux
Linux Development Setup
ATECC508A Certificate Provisioning 



[^ecc508]: http://www.atmel.com/devices/atecc508a.aspx

[^engine]: http://openssl.org/docs/manmaster/crypto/engine.html 

[^nist]: http://csrc.nist.gov/groups/STM/cavp/documents/aes/aesval.html




