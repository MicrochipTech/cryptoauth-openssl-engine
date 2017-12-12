/**
 * \brief OpenSSL ENGINE Ciphers Interface
 *
 * \copyright Copyright (c) 2017 Microchip Technology Inc. and its subsidiaries (Microchip). All rights reserved.
 *
 * \page License
 *
 * You are permitted to use this software and its derivatives with Microchip
 * products. Redistribution and use in source and binary forms, with or without
 * modification, is permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. The name of Microchip may not be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * 4. This software may only be redistributed and used in connection with a
 *     Microchip integrated circuit.
 *
 * THIS SOFTWARE IS PROVIDED BY MICROCHIP "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT ARE
 * EXPRESSLY AND SPECIFICALLY DISCLAIMED. IN NO EVENT SHALL MICROCHIP BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "eccx08_engine.h"

#if ATCA_OPENSSL_ENGINE_ENABLE_CIPHERS
#include "eccx08_engine_internal.h"

#include "openssl\evp.h"

static int eccx08_cipher_ids[] = { NID_ecdsa_with_SHA256 };   /*  @todo figure out the correct cipher list */

static EVP_CIPHER eccx08_cipher_method = {
    //int nid;
    //int block_size;
    ///* Default value for variable length ciphers */
    //int key_len;
    //int iv_len;
    ///* Various flags */
    //unsigned long flags;
    ///* init key */
    //int(*init) (EVP_CIPHER_CTX *ctx, const unsigned char *key,
    //    const unsigned char *iv, int enc);
    ///* encrypt/decrypt data */
    //int(*do_cipher) (EVP_CIPHER_CTX *ctx, unsigned char *out,
    //    const unsigned char *in, size_t inl);
    ///* cleanup ctx */
    //int(*cleanup) (EVP_CIPHER_CTX *);
    ///* how big ctx->cipher_data needs to be */
    //int ctx_size;
    ///* Populate a ASN1_TYPE with parameters */
    //int(*set_asn1_parameters) (EVP_CIPHER_CTX *, ASN1_TYPE *);
    ///* Get parameters from a ASN1_TYPE */
    //int(*get_asn1_parameters) (EVP_CIPHER_CTX *, ASN1_TYPE *);
    ///* Miscellaneous operations */
    //int(*ctrl) (EVP_CIPHER_CTX *, int type, int arg, void *ptr);
    ///* Application data */
    //void *app_data;
};

int eccx08_cipher_selector(ENGINE *e, const EVP_CIPHER **cipher, const int **nids, int nid)
{
    DEBUG_ENGINE("Entered\n");
    if (!digest) {
        *nids = eccx08_digest_ids;
        return 2;
    }

    if (nid == NID_sha256)
    {
        *digest = &eccx08_sha256_method;
        return 1;
    }
    else
    {
        DEBUG_ENGINE("Unsupported digest type %d requested\n", nid);
        *digest = NULL;
        return 0;
    }
}

int eccx08_cipher_init(void)
{

}

#else

int eccx08_cipher_init(void)
{
    return 0;
}

#endif