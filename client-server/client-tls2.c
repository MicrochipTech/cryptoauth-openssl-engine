/**
 *  \file client-tls2.c
 * \brief The client portion of the TLS1.2 client/server
 * exchange utility. For details see
 * https://wiki.openssl.org/index.php/SSL/TLS_Client
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

#include "tlsutil.h"

/**
 *
 * \brief A complete procedure of connecting client
 * using TLS-1.2 protocol over TCP/IP
 *
 * \param[in] engine_id Engine ID (use Software libraries if
 *       NULL)
 * \param[in] ca_path Path to CA (Certificate Authority)
 * \param[in] chain_file Chain File Name (Certificate Bundle)
 * \param[in] cert_file Certificate File Name
 * \param[in] key_file Private Key File Name
 * \param[in] cipher_list Cipher list string
 *                    (ECDH-ECDSA-AES128-SHA256,
 *                    ECDH-ECDSA-AES128-GCM-SHA256, etc) - Must
 *                    be SHA-256 for ECC508
 * \return 0 for success
 */
int connect_client(const char *engine_id, const char *ca_path, const char *chain_file,
                   const char *cert_file, const char *key_file, const char *cipher_list)
{
    int err = 0;
    SSL_CTX *ctx = NULL;
    SSL *ssl;
    X509 *server_cert;
    int sd;
    struct sockaddr_in sa;
    char *str;
    char *message = "Clent sends Hello to Server!";
    char buf[1024 * 8];

    init_openssl();
    ctx = create_context(0);
    CHK_NULL(ctx);

    err = setup_engine(engine_id);
    if (err == 0) {
        return 9;
    }

    err = SSL_CTX_set_cipher_list(ctx, cipher_list);
    if (err == 0) {
        fprintf(stderr, "SSL_CTX_set_cipher_list() error\n");
        return 10;
    }

    err = configure_context(ctx, ca_path, chain_file, cert_file);
    if (err == 0) {
        return 11;
    }

    /* Enable server certificate verification. Enable before accepting connections. */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT |
                       SSL_VERIFY_CLIENT_ONCE, 0);

    err = load_private_key(engine_id, ctx, key_file);
    if (err == 0) {
        return 13;
    }

    /* Use standard TCP socket first */

    sd = socket(AF_INET, SOCK_STREAM, 0);
    CHK_ERR(sd, "socket");

    memset(&sa, '\0', sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = inet_addr("127.0.0.1"); /* localhost */
    sa.sin_port = htons(PORT_NUMBER);

    err = connect(sd, (struct sockaddr *)&sa, sizeof(sa));
    CHK_ERR(err, "connect");

    fprintf(stderr, "Connected to server %s, port %u\n", inet_ntoa(sa.sin_addr),
            ntohs(sa.sin_port));

    /* TCP connection ready, start TLS1.2 negotiation */

    ssl = SSL_new(ctx);
    CHK_NULL(ssl);

    SSL_set_fd(ssl, sd);
    SSL_set_connect_state(ssl);
    err = SSL_connect(ssl);
    CHK_SSL(err);

    /* Optional section of code, not required for data exchange */
    fprintf(stderr, "Client Version: %s\n", SSL_get_version(ssl));

    /* The cipher negotiated and being used */
    fprintf(stderr, "Using cipher %s\n", SSL_get_cipher(ssl));

    /* Get server's certificate */
    server_cert = SSL_get_peer_certificate(ssl);
    CHK_NULL(server_cert);
    fprintf(stderr, "Server certificate:\n");

    str = X509_NAME_oneline(X509_get_subject_name(server_cert), 0, 0);
    CHK_NULL(str);
    fprintf(stderr, "\t subject: %s\n", str);
    OPENSSL_free(str);

    str = X509_NAME_oneline(X509_get_issuer_name(server_cert), 0, 0);
    CHK_NULL(str);
    fprintf(stderr, "\t issuer: %s\n", str);
    OPENSSL_free(str);

    /* Deallocate certificate, free memory */
    X509_free(server_cert);

    /* Use TLS1.2 transmit and receive */

    err = SSL_write(ssl, message, strlen(message));
    CHK_SSL(err);

    err = SSL_read(ssl, buf, sizeof(buf) - 1);
    CHK_SSL(err);
    buf[err] = '\0';
    fprintf(stderr, "\n Received %d characters from server: '%s'\n\n", err, buf);
    SSL_shutdown(ssl);

    close(sd);
    SSL_free(ssl);
    if (ctx) SSL_CTX_free(ctx);
    cleanup_openssl();

    return 0;
}

