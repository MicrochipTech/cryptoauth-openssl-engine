#!/bin/bash
# With NEW_KEY=1 the script requires to enter the password 3 times. 
# It is required because by default "openssl req"
# cannot do it without the password. 
# Then "openssl ec" removes the password
# NOTE! Be careful with NEW_KEY=1. Atmel certificates may be invalidated!
# A new key may be generated if key is not locked! 

set -e
set -x
cd $(dirname $0)
source ./common.sh

cd ..
cd ${CERTSTORE}

if [ -z "$COMPANY" ]; then
    COMPANY="homut"
fi

if [ -z "$NEW_KEY" ]; then
  NEW_KEY=0
fi

if [ $NEW_KEY = "1" ]; then

#  generate a new key then generate and sign server certificate using engine
rm -f ${CERTSTORE}/privkeys/${COMPANY}_server_eccx08.key \
 ${CERTSTORE}/csr/${COMPANY}_server_eccx08.csr \
 ${CERTSTORE}/personal/${COMPANY}_server_eccx08.crt \
 ${CERTSTORE}/privkeys/${COMPANY}_server_eccx08.der

${CMD} req ${KEYGEN_ENGINE} \
 -new -newkey ec:${CERTSTORE}/prime256v1.pem \
 -keyout ${CERTSTORE}/privkeys/${COMPANY}_server_eccx08.key \
 -out ${CERTSTORE}/csr/${COMPANY}_server_eccx08.csr \
 -sha256 -config ${CERTSTORE}/openssl.cnf \
 -subj '/C=US/ST=CA/L=Sunnyvale/O=Homut\ LLC/CN=server_eccx08/' \
 -verify

else

#  generate and sign certificates using engine, use existing key
${CMD} req ${ENGINE} \
 -new -key ${CERTSTORE}/privkeys/${COMPANY}_server_eccx08.key \
 -out ${CERTSTORE}/csr/${COMPANY}_server_eccx08.csr \
 -sha256 -config ${CERTSTORE}/openssl.cnf \
 -subj '/C=US/ST=CA/L=Sunnyvale/O=Homut LLC/CN=server_eccx08/' \
 -verify

fi

${CMD} ca \
 -batch -config ${CERTSTORE}/openssl.cnf \
 -extensions v3_ca -days 365 \
 -outdir ${CERTSTORE}/newcerts \
 -in ${CERTSTORE}/csr/${COMPANY}_server_eccx08.csr \
 -cert ${CERTSTORE}/trusted/${COMPANY}_intermediate.crt \
 -keyfile ${CERTSTORE}/privkeys/${COMPANY}_intermediate.key \
 -out ${CERTSTORE}/personal/${COMPANY}_server_eccx08.crt

${CMD} ec \
 -in ${CERTSTORE}/privkeys/${COMPANY}_server_eccx08.key \
 -out ${CERTSTORE}/privkeys/${COMPANY}_server_eccx08.key

${CMD} ec \
 -in ${CERTSTORE}/privkeys/${COMPANY}_server_eccx08.key \
 -outform DER -out ${CERTSTORE}/privkeys/${COMPANY}_server_eccx08.der

hexdump -C ${CERTSTORE}/privkeys/${COMPANY}_server_eccx08.der

exit $?
