/**
 *
 * \file tlsutil.c
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

#include "tlsutil.h"

/**
 *
 * \brief setup OpenSSL engine by engine ID
 *
 * \param[in] engine_id Engine ID (just return if NULL)
 * \return 1 for success, 0 for error
 */
int setup_engine(const char *engine_id)
{
#ifndef OPENSSL_NO_ENGINE
    ENGINE *e = NULL;

    if (engine_id == NULL) {
        return 1;
    }
    ENGINE_load_builtin_engines();
    e = ENGINE_by_id(engine_id);
    if (!e) {
        fprintf(stderr, "FAILED to load engine: %s\n", engine_id);
        return 0;
    }
    if (!ENGINE_set_default(e, ENGINE_METHOD_ALL)) {
        fprintf(stderr, "FAILED to set default engine: %s\n", engine_id);
        ENGINE_free(e);
        return 0;
    }
#endif // OPENSSL_NO_ENGINE
    return 1;
}

/**
 *
 * \brief Calls OpenSSL standard initialize methods
 *
 */
void init_openssl(void)
{
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

/**
 *
 * \brief Creates the SSL context for server or
 * client
 *
 * \param[in] is_server 1 - for server, 0 - for client
 * \return a pointer to SSL_CTX for success, NULL for error
 */
SSL_CTX* create_context(uint32_t is_server)
{
    const SSL_METHOD *method = NULL;
    SSL_CTX *ctx = NULL;

    if (is_server) {
        method = TLSv1_2_server_method();
    } else {
        method = TLSv1_2_client_method();
    }
    if (!method) {
        goto done;
    }

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        fprintf(stderr, "tlsutil:create_context() cannot create SSL context\n");
        goto done;
    }
done:
    return ctx;
}

/**
 *
 * \brief Configures the SSL context for server or
 * client using provided certificates, chain files, and private
 * keys (ATECCX08 token are encoded into the OpenSSL private key
 * files)
 *
 * \param[in] ctx SSL context
 * \param[in] ca_path Path to CA (Certificate Authority)
 * \param[in] chain_file Chain File Name (Certificate Bundle)
 * \param[in] cert_file Certificate File Name
 * \return 1 for success
 */
int configure_context(SSL_CTX *ctx, const char *ca_path, const char *chain_file,
                      const char *cert_file)
{
    int rc = 0;

    /* Compression should not be used: there are CRIME and BREACH attacks
       that leverage HTTP compression */
    if (!SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION)) {
        fprintf(stderr, "SSL_CTX_set_options(SSL_OP_NO_COMPRESSION) error\n");
        goto done;
    }

    if (SSL_CTX_load_verify_locations(ctx, chain_file, ca_path) <= 0) {
        ERR_print_errors_fp(stderr);
        goto done;
    }

    if (SSL_CTX_use_certificate_chain_file(ctx, chain_file) <= 0) {
        ERR_print_errors_fp(stderr);
        goto done;
    }
    /* 
     * See SSL_CTX_use_certificate_chain_file() in the ssl/ssl_rsa.c file as 
     * a reference if we get the chain from the hardware without saving to 
     * a file 
     */

    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "SSL_CTX_use_certificate_file() error\n");
        ERR_print_errors_fp(stderr);
        goto done;
    }
    if (!SSL_CTX_set_default_verify_paths(ctx)) {
        ERR_print_errors_fp(stderr);
        goto done;
    }

    rc = 1;
done:
    return (rc);
}

/**
 *
 * \brief setup OpenSSL engine by engine ID
 *
 * \param[in] engine_id Engine ID
 * \param ctx[in] SSL context
 * \param key_file[in] Private Key File Name
 * \return 1 for success, 0 for error
 */
int load_private_key(const char *engine_id, SSL_CTX *ctx, const char *key_file)
{
    int rc = 0;
    ENGINE *e = NULL;
    EVP_PKEY *pkey = NULL;

    if (engine_id) {
        e = ENGINE_by_id(engine_id);
        pkey = ENGINE_load_private_key(e, key_file, NULL, NULL);
        if (NULL == pkey) {
            fprintf(stderr, "load_private_key(): pkey is NULL\n");
            goto done;
        }
        rc = SSL_CTX_use_PrivateKey(ctx, pkey);
        EVP_PKEY_free(pkey);
    } else {
        if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
            fprintf(stderr, "SSL_CTX_use_PrivateKey_file() error");
            ERR_print_errors_fp(stderr);
            goto done;
        }
        /* 
         * The SSL_CTX_use_PrivateKey_file() calls 
         * ret = SSL_CTX_use_PrivateKey(ctx, pkey); 
         * Can be used instead if we get the private key from the hardware and use it immediately. 
         * Openssl engine structure provides hooks to load_privkey() and load_pubkey() functions. 
         * There are no hooks for certificates.
         */
    }

    rc = SSL_CTX_check_private_key(ctx);
    if (!rc) {
        fprintf(stderr, "Private key does not match public key in certificate\n");
        goto done;
    }
done:
    return (rc);

}

/**
 *
 * \brief A modification of the args_ssl_call()
 * function from the openssl aps/s_cb.c file
 *
 * \param[in] ctx SSL context
 * \param[in, out] cctx SSL_CONF_CTX
 * \return 0 for success
 */
int config_args_ssl_call(SSL_CTX *ctx, SSL_CONF_CTX *cctx)
{
    SSL_CONF_CTX_set_ssl_ctx(cctx, ctx);
    /*
     * This is a special case to keep existing s_server functionality: if we
     * don't have any curve specified *and* we haven't disabled ECDHE then
     * use P-256.
     */
    if (SSL_CONF_cmd(cctx, "-named_curve", "P-256") <= 0) {
        fprintf(stderr, "Error setting EC curve\n");
        return 0;
    }
    if (!SSL_CONF_CTX_finish(cctx)) {
        fprintf(stderr, "Error finishing context\n");
        return 0;
    }
    return 1;
}

/**
 *
 * \brief Call OpenSSL standard cleanup methods
 *
 */
void cleanup_openssl()
{
    EVP_cleanup();
}

/**
 *
 * Saves unencrypted private key in the PEM format. There is no
 * reason to use password/encryption for keys tht are already in
 * the hardware. Here we expect a pointer to the key, not a real
 * key
 *
 * \param[in] pkey pointer to public/private key structure
 *             (private key may be just a tocken, pointing to
 *             the hardware)
 * \param[in] privkey_fname Private Key File Name
 * \return 1 for success
 */
int save_private_key(EVP_PKEY *pkey, const char *privkey_fname)
{
    int rc = 0;
    FILE *fd = NULL;

    fd = fopen(privkey_fname, "wb");
    if (fd == NULL) {
        goto done;
    }

    rc = PEM_write_PrivateKey(fd, pkey, NULL, NULL, 0, NULL, NULL);
done:
    if (fd) {
        fclose(fd);
    }
    return (rc);
}

/**
 *
 * Saves a certificate in the PEM format
 *
 * \param[in] x509 pointer to X509 structure with certificate
 * \param[in] cert_fname Certificate file name
 * \return 1 for success
 */
int save_x509_certificate(X509 *x509, const char *cert_fname)
{
    int rc = 0;
    FILE *fd = NULL;

    fd = fopen(cert_fname, "wb");
    if (fd == NULL) {
        goto done;
    }

    rc = PEM_write_X509(fd, x509);
done:
    if (fd) {
        fclose(fd);
    }
    return (rc);
}

/**
 *
 * Calls different engine commands by CMD ID
 *
 * \param[in] engine_id Engine ID (just return if NULL)
 * \param[in] cmd a command to pass to the engine library (for
 *            the list of commands see ecc_meth.h file
 * \param[in, out] buffer an optional buffer to pass into the
 *       command
 * \param[in, out] len the buffer size
 * \return 1 for success, 0 for error
 */
int run_engine_cmds(const char *engine_id, int cmd, char *buffer, int len)
{
    ENGINE *e = NULL;

    if (engine_id == NULL) {
        return 1;
    }
    e = ENGINE_by_id(engine_id);

    ENGINE_ctrl(e, cmd, len, buffer, 0);
    return 1;
}

