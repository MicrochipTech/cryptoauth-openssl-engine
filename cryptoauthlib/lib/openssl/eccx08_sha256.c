/**
 * \brief OpenSSL ENGINE SHA256 Interface for ATECCx08 devices
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
 *    Microchip integrated circuit.
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

#if ATCA_OPENSSL_ENGINE_ENABLE_SHA256
#include "eccx08_engine_internal.h"

/** \brief List of supported digesting algorithms */
static int eccx08_digest_ids[] = { NID_sha256 };

/**
 * \brief Digest more bytes
 */
static int eccx08_sha256_update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    ATCA_STATUS status = atcab_hw_sha2_256_update(ctx->md_data, data, count);

    DEBUG_ENGINE("%s(%#x)\n", status ? "Failed" : "Succeeded", status);

    return (ATCA_SUCCESS == status) ? 1 : 0;
}

/**
 * \brief Finalize the digest and release the lock
 */
static int eccx08_sha256_final(EVP_MD_CTX *ctx, unsigned char *md)
{
    DEBUG_ENGINE("Entered\n");

    ATCA_STATUS status = atcab_hw_sha2_256_finish(ctx->md_data, md);

    DEBUG_ENGINE("%s(%#x)\n", status ? "Failed" : "Succeeded", status);

    (void)atcab_release_safe();

    return (ATCA_SUCCESS == status) ? 1 : 0;
}

/**
 * \brief Copy an existing digest context - will not free the global lock
 */
int eccx08_sha256_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from)
{
    DEBUG_ENGINE("Entered\n");
    if (to->md_data && from->md_data) {
        memcpy(to->md_data, from->md_data, to->digest->ctx_size);
    }
    return 1;
}

static int eccx08_sha256_cleanup(EVP_MD_CTX *ctx)
{
    DEBUG_ENGINE("Entered\n");
    return 1;
}

/**
* \brief Set up a SHA256 context for the ATECCx08 device. The user has to be
*   aware that this grabs the global device lock and will inhibit other
*   operations from occuring until final has been called
*/
static int eccx08_sha256_init(EVP_MD_CTX *ctx)
{
    DEBUG_ENGINE("Entered\n");
    DEBUG_ENGINE("ctx: %p\n", ctx);
    DEBUG_ENGINE("ctx->md_data: %p\n", ctx->md_data);

    ATCA_STATUS status = atcab_init_safe(pCfg);

    if (ATCA_SUCCESS == status)
    {
        status = atcab_hw_sha2_256_init(ctx->md_data);
    }

    DEBUG_ENGINE("%s(%#x)\n", status ? "Failed" : "Succeeded", status);

    if (ATCA_SUCCESS != status)
    {
        (void)atcab_release_safe();
    }

    return (ATCA_SUCCESS == status) ? 1 : 0;
}

/**
 * \brief OpenSSL digest structure for registering with the core api
 */
static EVP_MD eccx08_sha256_method = {
    NID_sha256,                         /**< Type/Algorithm */
    NID_ecdsa_with_SHA256,              /**< Private Key type - N/A for sha256 */
    SHA256_DIGEST_LENGTH,               /**< Digest size - SHA256 is always 32 */
    EVP_MD_FLAG_PKEY_METHOD_SIGNATURE,  
    eccx08_sha256_init,
    eccx08_sha256_update,
    eccx08_sha256_final,
    NULL,
    NULL,
    // NULL,                               /**< Sign - Not used since EVP_MD_FLAG_PKEY_METHOD_SIGNATURE is set */
    // NULL,                               /**< Verify - Not used since EVP_MD_FLAG_PKEY_METHOD_SIGNATURE is set */
    // { NID_undef, NID_undef, 0, 0, 0 },
    //64,                                 /**< Block Size - fixed at 64 for SHA256 */
    EVP_PKEY_ECDSA_method,
    SHA256_CBLOCK,
    sizeof(atca_sha256_ctx_t),          /**< Required size for (EVP_MD_CTX)->md_data  */
    NULL,
};

int eccx08_sha256_selector(ENGINE *e, const EVP_MD **digest, const int **nids, int nid)
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

#endif //ATCA_OPENSSL_ENGINE_ENABLE_SHA256
