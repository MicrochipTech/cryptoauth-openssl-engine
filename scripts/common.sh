#!/bin/bash
set -e
set -x
cd $(dirname $0)
cd ..
export TREE_TOP=${PWD}
export CERTSTORE=$TREE_TOP/certstore
export SCRIPTS=$TREE_TOP/scripts
export BIN_DIR=$TREE_TOP/install_dir/bin
export EX_DIR=$TREE_TOP/client-server

# Certificate names
export DEVICE_CERT=${CERTSTORE}/personal/AT_device
export DEVICE_KEY=${CERTSTORE}/privkeys/AT_device.key
export DEVICE_CSR=${CERTSTORE}/csr/AT_device.csr
export SIGNER_CERT=${CERTSTORE}/trusted/AT_signer
export SIGNER_PATH=${CERTSTORE}/trusted
export ROOT_CERT=${CERTSTORE}/trusted/AT_root
export SIGNER_BUNDLE=${CERTSTORE}/trusted/AT_bundle.crt

export LD_LIBRARY_PATH=$TREE_TOP/install_dir/lib
export LD_PRELOAD=/lib/x86_64-linux-gnu/libpthread.so.0

if [ -z "$PORT_NUMBER" ]; then
    export PORT_NUMBER=49917
fi

if [ -z "$IP_ADDRESS" ]; then
    export IP_ADDRESS="127.0.0.1"
fi

export ENGINE="-engine ateccx08"
export KEYGEN_ENGINE="-keygen_engine ateccx08"

if [ -z "$COMPANY" ]; then
    export COMPANY="homut"
fi

if [ -z "$COMMON_NAME" ]; then
    export COMMON_NAME="homut"
fi

if [ -z "$USE_EXAMPLE" ]; then
    export USE_EXAMPLE=0
fi

if [ -z "$USE_ENGINE" ]; then
    export USE_ENGINE=0
fi

if [ -z "$USE_ATMEL_CA" ]; then
    export USE_ATMEL_CA=0
fi

if [ -z "$NEW_KEY" ]; then
    export NEW_KEY=0
fi

if [ -z "$NEW_ROOT" ]; then
    export NEW_ROOT=0
fi

if [ -z "$USE_WWW" ]; then
    USE_WWW=0
fi

if [ $USE_ENGINE = "0" ]; then
    export ENGINE=
    export ENGINE_EX=
else
    export ENGINE="-engine ateccx08"
    export ENGINE_EX="-e ateccx08"
fi

if [ -z "$USE_RSA" ]; then
    export USE_RSA=0
fi

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

export CMD=${BIN_DIR}/openssl
#export CMD=${TREE_TOP}/cmd_openssl gdb 
#export CMD="gdb --args ${BIN_DIR}/openssl"
export CMD_EX="${EX_DIR}/exchange-tls12"
#export CMD_EX="gdb --args ${EX_DIR}/exchange-tls12"


