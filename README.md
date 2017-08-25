
Configuration:

Most of the configuration of the library can be done in lib/openssl/eccx08_engine.h or via defines during build

The exception to this is in eccx08_platform.c where key slots are defaulted 

If the ATCA_OPENSSL_ENGINE_STATIC_CONFIG define is set to 1 then device and signer certificate definitions will
have to be linked into the library at build. 

e.g. see the line in the makefile: #LIBATECCSSL_OBJECTS += cert_def_1_signer.c cert_def_2_signer.c


Makfile:

The makefile included in this archive is fairly basic and is not what one would consider appropriate for a package
so there is likely some manual configuration that would be needed at this stage


To build the library:

> make libateccssl

To run the test program:

> make test

To extract certificates (if the engine is added to the openssl.cnf file):

> openssl engine ateccx08 -t -post GET_DEVICE_CERT:./device.der
> openssl engine ateccx08 -t -post GET_SIGNER_CERT:./signer.der

Otherwise you'll have to use an interactive openssl session (see openssl engine -h and engine -vvv for details)

> openssl

OpenSSL> engine dynamic -pre SO_PATH:/<full path to libeccssl.so> -pre LIST_ADD:1 -pre ID:ateccx08 -pre LOAD
OpenSSL> engine ateccx08 -t -post GET_DEVICE_CERT:./device.der
OpenSSL> engine ateccx08 -t -post GET_SIGNER_CERT:./signer.der

Then to verify the certs:
> openssl x509 -in device.der -inform der -text -noout
> openssl x509 -in signer.der -inform der -text -noout

To set up your openssl.cnf file

Find which openssl.cnf file your instance is using you can:

> openssl version -a | grep OPENSSLDIR
OPENSSLDIR: "/usr/lib/ssl"

will tell you the base location where openssl is looking for the openssl.cnf file. It may be a symbolic link to another location

> ls -l /usr/lib/ssl
lrwxrwxrwx 1 root root 14 Apr 24 15:22 certs -> /etc/ssl/certs
lrwxrwxrwx 1 root root 20 Jan 31 05:53 openssl.cnf -> /etc/ssl/openssl.cnf

To set up the openssl.cnf to use the engine:

# At the top:

openssl_conf = openssl_init

# Append to the end:

[ openssl_init ]
engines = engine_section

[ engine_section ]
ateccx08 = ateccx08_config

[ ateccx08_config ]
engine_id = ateccx08
# Or if you sym link the libateccssl.so to the engine directory the next line is not needed
dynamic_path = <full path to libateccssl.so>
device_key_slot = 0
init = 0

To use the engine in an application you can reference the openssl tests (test/openssl/test_engine.c) but the basic principle is that
if the openssl.cnf file is configured correctly all an application really needs to do is add a call to OPENSSL_config if it is not already
doing so and then to decide what functionality that the application wants and register it.
