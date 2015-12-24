#!/bin/bash
set -x 
set -e

#sudo chmod a+rw /dev/ttyACM0

#./cmd_openssl gdb req -keygen_engine ateccx08 -engine ateccx08 -new -newkey ec:prime256v1.pem -keyout privkeys/homut_server_eccx08.key -out csr/homut_server_eccx08.csr -sha256 -config openssl.cnf -subj """/C=US/ST=CA/L=Sunnyvale/O=Homut LLC/CN=homut_server_eccx08/""" -verify
#exit 0

function upfind() {
    dir=`pwd`
    while [ "$dir" != "/" ]; do
	p=`find "$dir" -maxdepth 1 -name $1`
	if [ ! -z $p ]; then
	    echo "$dir"
	    return 
	fi
        dir=`dirname "$dir"`
    done
}

BASEDIR="$(upfind .git)"
cd ${BASEDIR}/certstore

# Note that prime256v1.pem is now checked into repository
#${BASEDIR}/install_dir/bin/openssl ecparam -name prime256v1 -out prime256v1.pem

ARCH=`arch`
if [ ${ARCH} != "armv7l" ]; then
    LD_PRELOAD=/lib/x86_64-linux-gnu/libpthread.so.0 gdb --args ${BASEDIR}/install_dir/bin/openssl req -keygen_engine ateccx08 -engine ateccx08 -new -newkey ec:prime256v1.pem -keyout privkeys/homut_server_eccx08.key -out csr/homut_server_eccx08.csr -sha256 -config openssl.cnf -subj "/C=US/ST=CA/L=Sunnyvale/O=Homut LLC/CN=homut_server_eccx08/" -verify
else
    LD_PRELOAD=/lib/arm-linux-gnueabihf/libpthread.so.0 gdb --args ${BASEDIR}/install_dir/bin/openssl req -keygen_engine ateccx08 -engine ateccx08 -new -newkey ec:prime256v1.pem -keyout privkeys/homut_server_eccx08.key -out csr/homut_server_eccx08.csr -sha256 -config openssl.cnf -subj "/C=US/ST=CA/L=Sunnyvale/O=Homut LLC/CN=homut_server_eccx08/" -verify
fi

cd -
