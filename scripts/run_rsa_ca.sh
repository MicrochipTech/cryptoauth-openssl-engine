#!/bin/bash
set -x
set -e
cd $(dirname $0)
source ./common.sh

cd ..

# Create CA (RSA) #

cd ${CERTSTORE}

if [ $NEW_ROOT = "1" ]; then
    ##
    ## Root cert
    ##
    ${CMD} genrsa -out ${CERTSTORE}/privkeys/${COMPANY}_rsa_root.key 2048
    ${CMD} req -new -key ${CERTSTORE}/privkeys/${COMPANY}_rsa_root.key \
     -out ${CERTSTORE}/csr/${COMPANY}_rsa_root.csr -sha256 \
     -config ${CERTSTORE}/openssl.cnf \
     -subj "/C=US/ST=CA/L=Sunnyvale/O=Homut LLC/CN=Homut RSA Root/" \
     -verify
    ${CMD} ca -batch -create_serial \
     -out ${CERTSTORE}/trusted/${COMPANY}_rsa_root.crt -days 1000 \
     -selfsign -extensions v3_ca_has_san -config openssl.cnf \
     -keyfile ${CERTSTORE}/privkeys/${COMPANY}_rsa_root.key \
     -infiles ${CERTSTORE}/csr/${COMPANY}_rsa_root.csr

    ##
    ## Intermediate cert
    ##
    ${CMD} genrsa -out ${CERTSTORE}/privkeys/${COMPANY}_rsa_intermediate.key 2048
    ${CMD} req -new -key ${CERTSTORE}/privkeys/${COMPANY}_rsa_intermediate.key \
     -out ${CERTSTORE}/csr/${COMPANY}_rsa_intermediate.csr -sha256 \
     -config ${CERTSTORE}/openssl.cnf \
     -subj "/C=US/ST=CA/L=Sunnyvale/O=Homut LLC/CN=Homut RSA Intermediate/" \
     -verify
    ${CMD} ca -batch -config ${CERTSTORE}/openssl.cnf \
     -extensions v3_ca -days 365 \
     -in ${CERTSTORE}/csr/${COMPANY}_rsa_intermediate.csr \
     -cert ${CERTSTORE}/trusted/${COMPANY}_rsa_root.crt \
     -keyfile ${CERTSTORE}/privkeys/${COMPANY}_rsa_root.key \
     -out ${CERTSTORE}/trusted/${COMPANY}_rsa_intermediate.crt

    ##
    ## Create cert bundle
    ##
    cat ${CERTSTORE}/trusted/${COMPANY}_rsa_root.crt \
     ${CERTSTORE}/trusted/${COMPANY}_rsa_intermediate.crt > \
     ${CERTSTORE}/trusted/${COMPANY}_rsa_bundle.crt

fi

## 
## Server cert
##
${CMD} genrsa -out ${CERTSTORE}/privkeys/${COMPANY}_rsa_server.key 2048
${CMD} req -new -key ${CERTSTORE}/privkeys/${COMPANY}_rsa_server.key \
    -out ${CERTSTORE}/csr/${COMPANY}_rsa_server.csr -sha256 \
    -config ${CERTSTORE}/openssl.cnf \
    -subj /C=US/ST=CA/L=Sunnyvale/O=Homut\ LLC/CN=Homut\ RSA\ Server/ \
    -reqexts v3_req -verify
${CMD} ca -batch -config ${CERTSTORE}/openssl.cnf \
    -days 365 -in ${CERTSTORE}/csr/${COMPANY}_rsa_server.csr \
    -cert ${CERTSTORE}/trusted/${COMPANY}_rsa_intermediate.crt \
    -keyfile ${CERTSTORE}/privkeys/${COMPANY}_rsa_intermediate.key \
    -out ${CERTSTORE}/personal/${COMPANY}_rsa_server.crt

##
## Client cert
##
${CMD} genrsa -out ${CERTSTORE}/privkeys/${COMPANY}_rsa_client.key 2048
${CMD} req -new -key ${CERTSTORE}/privkeys/${COMPANY}_rsa_client.key \
    -out ${CERTSTORE}/csr/${COMPANY}_rsa_client.csr -sha256 \
    -config ${CERTSTORE}/openssl.cnf \
    -subj /C=US/ST=CA/L=Sunnyvale/O=Homut\ LLC/CN=Homut\ RSA\ Client/ \
    -reqexts v3_req -verify
${CMD} ca -batch -config ${CERTSTORE}/openssl.cnf \
    -days 365 -in ${CERTSTORE}/csr/${COMPANY}_rsa_client.csr \
    -cert ${CERTSTORE}/trusted/${COMPANY}_rsa_intermediate.crt \
    -keyfile ${CERTSTORE}/privkeys/${COMPANY}_rsa_intermediate.key \
    -out ${CERTSTORE}/personal/${COMPANY}_rsa_client.crt

##
## Client cert (key in ECC508)
##
${CMD} genrsa -engine ateccx08 \
    -out ${CERTSTORE}/privkeys/${COMPANY}_rsa_client_eccx08.key 2048
${CMD} req -engine ateccx08 -keyform ENG -new \
    -key ${CERTSTORE}/privkeys/${COMPANY}_rsa_client_eccx08.key \
    -out ${CERTSTORE}/csr/${COMPANY}_rsa_client_eccx08.csr -sha256 \
    -config ${CERTSTORE}/openssl.cnf \
    -subj /C=US/ST=CA/L=Sunnyvale/O=Homut\ LLC/CN=Homut\ RSA\ Client\ ECCX08/ \
    -reqexts v3_req -verify
${CMD} ca -batch -config ${CERTSTORE}/openssl.cnf \
    -days 365 -in ${CERTSTORE}/csr/${COMPANY}_rsa_client_eccx08.csr \
    -cert ${CERTSTORE}/trusted/${COMPANY}_rsa_intermediate.crt \
    -keyfile ${CERTSTORE}/privkeys/${COMPANY}_rsa_intermediate.key \
    -out ${CERTSTORE}/personal/${COMPANY}_rsa_client_eccx08.crt

## 
## Server cert (key in ECC508)
##
# Reuse client key. Need a separate script if generating a new key
# By default the common name will be set to "homut".
# Provide a common name to match the server URL ("localhost", "127.0.0.1", real IP address, etc

cp ${CERTSTORE}/privkeys/${COMPANY}_rsa_client_eccx08.key \
    ${CERTSTORE}/privkeys/${COMPANY}_rsa_server_eccx08.key
#        ${CMD} genrsa -engine ateccx08 -out ${CERTSTORE}/privkeys/${COMPANY}_rsa_server_eccx08.key 2048
${CMD} req -engine ateccx08 -keyform ENG \
    -new -key ${CERTSTORE}/privkeys/${COMPANY}_rsa_server_eccx08.key \
    -out ${CERTSTORE}/csr/${COMPANY}_rsa_server_eccx08.csr -sha256 \
    -config ${CERTSTORE}/openssl.cnf \
    -reqexts v3_req -verify \
    -subj "/C=US/ST=CA/L=Sunnyvale/O=Homut\ LLC/CN=${COMMON_NAME}/" 
#    -subj /C=US/ST=CA/L=Sunnyvale/O=Homut\ LLC/CN=Homut\ RSA\ Server\ ECCX08/ 
${CMD} ca -batch -config ${CERTSTORE}/openssl.cnf \
    -days 365 -in ${CERTSTORE}/csr/${COMPANY}_rsa_server_eccx08.csr \
    -cert ${CERTSTORE}/trusted/${COMPANY}_rsa_intermediate.crt \
    -keyfile ${CERTSTORE}/privkeys/${COMPANY}_rsa_intermediate.key \
    -out ${CERTSTORE}/personal/${COMPANY}_rsa_server_eccx08.crt

##
## Debug
##
#	cat trusted/${COMPANY}_rsa_bundle.crt
