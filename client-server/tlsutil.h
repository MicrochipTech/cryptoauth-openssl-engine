/**
 *
 * \file tlsutil.h
 * \brief Common functions for the TLS1.2 client/server exchange utility. It is an example
 * of the programmatic use of the ateccx08 engine for TLS1.2
 * exchange. For details see
 * https://wiki.openssl.org/index.php/SSL/TLS_Client and
 * https://wiki.openssl.org/index.php/Simple_TLS_Server
 *
 * Copyright (c) 2015 Atmel Corporation. All rights reserved.
 *
 * \atmel_crypto_device_library_license_start
 *
 * \page License
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. Neither the name of Atmel nor the names of its contributors may be used to endorse
 *    or promote products derived from this software without specific prior written permission.
 *
 * 4. This software may only be redistributed and used in connection with an
 *    Atmel integrated circuit.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef SSLUTIL_H_
#define SSLUTIL_H_

#include <stdio.h>
#include <memory.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/engine.h>

#include <engine_meth/ecc_meth.h>

#define EXCHANGE_VERSION "1.0.1"
#define PORT_NUMBER      (49917)

#define CHK_NULL(x) if ((x)==NULL) { sleep(1); exit (1); }
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); sleep(1); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); sleep(2); exit(2); }

int setup_engine(const char *engine_id);
void init_openssl(void);
SSL_CTX* create_context(uint32_t is_server);
int config_args_ssl_call(SSL_CTX *ctx, SSL_CONF_CTX *cctx);
int configure_context(SSL_CTX *ctx, const char *ca_path, const char *chain_file,
                      const char *cert_file);
int load_private_key(const char *engine_id, SSL_CTX *ctx, const char *key_file);
void cleanup_openssl(void);

int connect_client(const char *engine_id, const char *ca_path, const char *chain_file,
                   const char *cert_file, const char *key_file, const char *cipher_list);
int connect_server(const char *engine_id, const char *ca_path, const char *chain_file,
                   const char *cert_file, const char *key_file);

int save_private_key(EVP_PKEY *pkey, const char *privkey_fname);
int save_x509_certificate(X509 *x509, const char *cert_fname);
int run_engine_cmds(const char *engine_id, int cmd, char *buffer, int len);


#endif /* SSLUTIL_H_ */
