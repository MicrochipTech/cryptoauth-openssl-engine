/**
 * \brief OpenSSL ENGINE callback functions for ECDH
 *      See reference code at crypto/ecdh/ech_ossl.c
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


#include <openssl/engine.h>
#include "eccx08_engine.h"
#include "eccx08_engine_internal.h"

uint8_t g_eccx08_transport_key[] = {
    0x44, 0x00, 0x44, 0x01, 0x44, 0x02, 0x44, 0x03, 
    0x44, 0x04, 0x44, 0x05, 0x44, 0x06, 0x44, 0x07, 
    0x44, 0x08, 0x44, 0x09, 0x44, 0x0A, 0x44, 0x0B,
    0x44, 0x0C, 0x44, 0x0D, 0x44, 0x0E, 0x44, 0x0F
};

static ECDH_METHOD * eccx08_ecdh_default;

/**
 *  \brief Generates an ephemeral key in TLS_SLOT_ECDHE_PRIV
 *  slot of the ATECCX08 (if public key is not provided in the
 *  ecdh parameter) chip then computes a 32-byte shared secret
 *  based on this key and a ECDHE peer public key
 *
 *  \param[out] out A buffer to return the ECDHE shared secret
 *  \param[in] outlen The size of the "out" buffer
 *  \param[in] pub_key A pointer to the EC_POINT structure with
 *         a public key from the ECDHE peer
 *  \param[in, out] ecdh A pointer to the EC_KEY structure with
 *         the ECDH private/public keys (private key data is
 *         ignored by the ateccx08 engine)
 *  \param[in] KDF A pointer to an optional key deriviation function
 *  \return 1 on success, 0 on error
 */
static int eccx08_ecdh_compute_key(void *out, size_t outlen, 
    const EC_POINT *pub_key, EC_KEY *ecdh, 
    void* (*KDF)(const void *in, size_t inlen, void *out, size_t *outlen))
{
    DEBUG_ENGINE("Entered: outlen %d\n", outlen);

    eccx08_eckey_debug(NULL, ecdh);

    /* Check if the provided key is a hardware key */
    if (!eccx08_eckey_isx08key(ecdh))
    {
        /* Not a hardware key - compute normally */
        return eccx08_ecdh_default->compute_key(out, outlen, pub_key, ecdh, KDF);
    }
    else
    {
        BN_CTX *ctx;
        EC_POINT *tmp = NULL;
        BIGNUM *x = NULL, *y = NULL;
        const EC_GROUP *group;
        int ret = -1;
        size_t buflen;
        size_t len;
        unsigned char *buf = NULL;
        int i;
        ATCA_STATUS status = ATCA_GEN_FAIL;
        uint8_t *raw_key = NULL;
        uint8_t *shared_secret = NULL;
        point_conversion_form_t form;
        bool lock = false;


        if (outlen > INT_MAX) {
            ECDHerr(ECDH_F_ECDH_COMPUTE_KEY, ERR_R_MALLOC_FAILURE); /* sort of,
                                                                     * anyway */
            return -1;
        }

        if ((ctx = BN_CTX_new()) == NULL) {
            goto err;
        }
        BN_CTX_start(ctx);
        x = BN_CTX_get(ctx);
        y = BN_CTX_get(ctx);

        group = EC_KEY_get0_group(ecdh);


        form = EC_GROUP_get_point_conversion_form(group);

        len = EC_POINT_point2oct(group, pub_key, form, NULL, 0, NULL);
        if (len == 0) {
            ECerr(EC_F_EC_ASN1_GROUP2PARAMETERS, ERR_R_EC_LIB);
            goto err;
        }
        if ((raw_key = OPENSSL_malloc(len)) == NULL) {
            ECerr(EC_F_EC_ASN1_GROUP2PARAMETERS, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        if (!EC_POINT_point2oct(group, pub_key, form, raw_key, len, NULL)) {
            ECerr(EC_F_EC_ASN1_GROUP2PARAMETERS, ERR_R_EC_LIB);
            goto err;
        }
        shared_secret = (uint8_t *)OPENSSL_malloc(ATCA_BLOCK_SIZE);
        if (shared_secret == NULL) {
            goto err;
        }

        if (!EC_POINT_point2oct(group, EC_KEY_get0_public_key(ecdh), form, raw_key, len, NULL)) {
            ECerr(EC_F_EC_ASN1_GROUP2PARAMETERS, ERR_R_EC_LIB);
            goto err;
        }

        buflen = (EC_GROUP_get_degree(group) + 7) / 8;
        len = ATCA_BLOCK_SIZE;
        memset(buf, 0, buflen - len);

        status = atcab_init_safe(pCfg);
        if (status != ATCA_SUCCESS) {
            DEBUG_ENGINE("Error in atcab_init_safe\n");
            goto err;
        }

        status = atcab_ecdh_enc(0, &raw_key[1], shared_secret, g_eccx08_transport_key, 4);

        atcab_release_safe();

        printf("ECDH: Computed Key\n");
        for (i = 0; i < ATCA_BLOCK_SIZE; i++)
        {
            printf("%02x ", shared_secret[i]);
        }
        printf("\n\n");

        if (status != ATCA_SUCCESS) {
            DEBUG_ENGINE("Error in atcab_ecdh\n");
            goto err;
        }

        if ((buf = OPENSSL_malloc(buflen)) == NULL) {
            DEBUG_ENGINE("Alloc Failed\n");
            goto err;
        }
        memcpy(buf + buflen - len, shared_secret, len);

        if (KDF != 0) {
            DEBUG_ENGINE("Running KDF\n");
            if (KDF(buf, buflen, out, &outlen) == NULL) {
                DEBUG_ENGINE("KDF Failed\n");
                goto err;
            }
            ret = outlen;
        }
        else {
            DEBUG_ENGINE("No KDF\n");
            /* no KDF, just copy as much as we can */
            if (outlen > buflen) outlen = buflen;
            memcpy(out, buf, outlen);
            ret = outlen;
        }
        DEBUG_ENGINE("Succeded\n");

    err:
        if (tmp)
        {
            EC_POINT_free(tmp);
        }

        if (ctx)
        {
            BN_CTX_end(ctx);
            BN_CTX_free(ctx);
        }

        if (buf)
        {
            OPENSSL_free(buf);
        }

        if (raw_key)
        {
            OPENSSL_free(raw_key);
        }

        if (shared_secret)
        {
            OPENSSL_free(shared_secret);
        }

        return (ret);
    }
}

static ECDH_METHOD eccx08_ecdh = {
    "ATECCX08 ECDH METHOD",
    eccx08_ecdh_compute_key,
    0,
    NULL
};

#if ATCA_OPENSSL_OLD_API

int eccx08_ecdh_init(ECDH_METHOD ** ppMethod)
{
    DEBUG_ENGINE("Entered\n");

    eccx08_ecdh_default = ECDH_get_default_method();

    if (!ppMethod)
    {
        return ENGINE_OPENSSL_FAILURE;
    }

    *ppMethod = &eccx08_ecdh;

    return ENGINE_OPENSSL_SUCCESS;
}

int eccx08_ecdh_cleanup(void)
{
    DEBUG_ENGINE("Entered\n");
    return ENGINE_OPENSSL_SUCCESS;
}

#endif
