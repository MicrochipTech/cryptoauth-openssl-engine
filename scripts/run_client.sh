#!/bin/bash
set -e
set -x
cd $(dirname $0)
source ./common.sh

BUNDLE=bundle

if [ $USE_RSA = "0" ]; then
  RSA=
else
  RSA=rsa_
  if [ $USE_ENGINE = "0" ]; then
    KEYFORM=
  else
    KEYFORM="-keyform ENG"
  fi
fi

if [ $USE_ATMEL_CA = "0" ]; then
    export DEVICE_CERT_PEM=${CERTSTORE}/personal/${COMPANY}_${RSA}${TARGET}.crt
    export DEVICE_KEY=${CERTSTORE}/privkeys/${COMPANY}_${RSA}${TARGET}.key
    export SIGNER_PATH=${CERTSTORE}/trusted
    export SIGNER_BUNDLE=${CERTSTORE}/trusted/${COMPANY}_${RSA}${BUNDLE}.crt
else
    export DEVICE_CERT_PEM=${DEVICE_CERT}.pem
fi

# Note this env var can be considered in OpenSSL s_client.c (see getenv)

if [ -z "$SSL_CIPHER" ]; then
    #export SSL_CIPHER=ECDHE-ECDSA-AES128-GCM-SHA256 # define RSA to nothing on both client and server
    export SSL_CIPHER=ECDH-ECDSA-AES128-GCM-SHA256 # define RSA to nothing on both client and server
    #export SSL_CIPHER=ECDHE-RSA-AES128-SHA # define RSA=rsa_ on both client and server
    #export SSL_CIPHER=ECDHE-RSA-AES128-SHA256 # define RSA=rsa_ on both client and server
fi

#export SSL_CIPHER=ECDH-RSA-AES128-SHA256 # - dropped from SOW
#export SSL_CIPHER=DH-RSA-AES256-SHA256  # requires TARGET="dh"on server side - dropped from SOW

# Call TLS client

set +e
if [ $USE_EXAMPLE = "0" ]; then
    ${CMD}  s_client ${ENGINE} -connect localhost:${PORT} \
    -verify 2 \
    -cert ${DEVICE_CERT_PEM} ${KEYFORM} \
    -key ${DEVICE_KEY} \
    -CApath ${SIGNER_PATH} \
    -CAfile ${SIGNER_BUNDLE} \
    -cipher ${SSL_CIPHER} \
    -no_ssl2 -no_ssl3 -no_tls1 -no_tls1_1 \
#    -showcerts 
else
    ${CMD_EX} ${ENGINE_EX} \
    -d 2 \
    -c ${SSL_CIPHER} \
    -p ${SIGNER_PATH} \
    -b ${SIGNER_BUNDLE} \
    -f ${DEVICE_CERT_PEM} \
    -k ${DEVICE_KEY}
fi
STATUS=$?
echo "EXIT STATUS: ${STATUS}"
exit ${STATUS}
