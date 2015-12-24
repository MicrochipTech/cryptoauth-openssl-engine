#!/bin/bash
# If Atmel delievers the openssl key file then it is safer to use NEW_KEY=0
# If the openssl key file is not delievered then this script may be called
# with the NEW_KEY=1. If the device key in ATECC08 hardware wasn't locked
# during provisioning then it may be destroyed. Verify that it is locked
# before using NEW_KEY=1.
# Type the same password 3 times once prompted. Any 4 characters are sufficient.

set -e
set -x
cd $(dirname $0)
source ./common.sh

set +e
${CMD_EX} -E -e ateccx08
#gdb --args ${CMD_EX} -E -e ateccx08

# Convert certificates from DER to PEM format and bundle the CA
${CMD} x509 -inform DER -outform PEM -in ${SIGNER_CERT}.der -out ${SIGNER_CERT}.pem
${CMD} x509 -inform DER -outform PEM -in ${ROOT_CERT}.der -out ${ROOT_CERT}.pem
cat ${SIGNER_CERT}.pem ${ROOT_CERT}.pem > ${SIGNER_BUNDLE}
${CMD} x509 -inform DER -outform PEM -in ${DEVICE_CERT}.der -out ${DEVICE_CERT}.pem

if [ $NEW_KEY = "1" ]; then
    ${CMD} req ${KEYGEN_ENGINE} \
     -new -newkey ec:${CERTSTORE}/prime256v1.pem \
     -keyout ${DEVICE_KEY} \
     -out ${DEVICE_CSR} \
     -sha256 -config ${CERTSTORE}/openssl.cnf \
     -subj '/C=US/ST=CA/CN=dummy_eccx08/' \
     -verify

${CMD} ec \
 -in ${DEVICE_KEY} \
 -out ${DEVICE_KEY}

fi

STATUS=$?
echo "EXIT STATUS: ${STATUS}"
exit ${STATUS}

