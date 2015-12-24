/**
 *  \file eccx08_ecdh.c
 * \brief Implementation of OpenSSL ENGINE callback functions for ECDH
 *        See reference code at crypto/ecdh/ech_ossl.c
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

#include <stdint.h>
#include <limits.h>
#include <string.h>
#include <assert.h>
#include <openssl/engine.h>
#include <crypto/ec/ec_lcl.h>
#include <crypto/ecdh/ech_locl.h>
#include <crypto/ecdsa/ecs_locl.h>
#include <ssl/ssl_locl.h>
#include <err.h>
#include "ecc_meth.h"

static uint32_t software_ecdh = 0;

/* ECDH stuff */
#ifndef OPENSSL_NO_ECDH
static int ECDH_eccx08_init(EC_KEY *pub_key);
static int ECDH_eccx08_get_pubkey(EC_POINT *pub_key, uint8_t *serial_number, int serial_len);
static int ECDH_eccx08_compute_key(void *out, size_t outlen, const EC_POINT *pub_key,
                                   EC_KEY *ecdh, void* (*KDF)(const void *in,
                                                              size_t inlen, void *out,
                                                              size_t *outlen));
/**
 *  \brief Generates a 32-byte private key then replaces it with token
 *  data using the eccx08_eckey_encode_in_privkey() call
 *
 *  \param[out] pub_key Pointer to EC_POINT Public Key on success
 *  \param[in] serial_number 9 bytes of ATECCX08 serial number
 *  \param[in] serial_len Size of the ATECCX08 serial number buffer
 *  \return 1 on success, 0 on error
 */
static int ECDH_eccx08_get_pubkey(EC_POINT *pub_key, uint8_t *serial_number, int serial_len)
{
    int rc = 0;
    int ret = 0;
    ATCA_STATUS status = ATCA_GEN_FAIL;

    uint8_t slotid = TLS_SLOT_ECDHE_PRIV;
    uint8_t raw_pubkey[MEM_BLOCK_SIZE * 2];

    EC_GROUP *ecgroup = NULL;
    int asn1_flag = OPENSSL_EC_NAMED_CURVE;
    point_conversion_form_t form = POINT_CONVERSION_UNCOMPRESSED;
    char tmp_buf[MEM_BLOCK_SIZE * 2 + 1];

    /* Openssl raw key has a leading byte with conversion form id */
    tmp_buf[0] = POINT_CONVERSION_UNCOMPRESSED;

    if (!ecgroup) {
        ecgroup = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
        if (!ecgroup) goto done;
        EC_GROUP_set_point_conversion_form(ecgroup, form);
        EC_GROUP_set_asn1_flag(ecgroup, asn1_flag);
    }

#ifdef USE_ECCX08
    eccx08_debug("ECDH_eccx08_get_pubkey() - hw\n");
    status = atcatls_init(pCfg);
    if (status != ATCA_SUCCESS) {
        eccx08_debug("ECDH_eccx08_get_pubkey() - error in atcatls_init \n");
        goto done;
    }
    //read serial number here
    status = atcatls_get_sn(serial_number);
    if (status != ATCA_SUCCESS) {
        eccx08_debug("ECDH_eccx08_get_pubkey() - error in atcatls_get_sn \n");
        goto done;
    }
    //Generate private key then get public key
    status = atcatls_create_key(slotid, raw_pubkey);
    if (status != ATCA_SUCCESS) {
        eccx08_debug("ECDH_eccx08_get_pubkey() - error in atcatls_get_pubkey \n");
        goto done;
    }
    status = atcatls_finish();
    if (status != ATCA_SUCCESS) {
        eccx08_debug("ECDH_eccx08_get_pubkey() - error in atcatls_finish \n");
        goto done;
    }
#else // USE_ECCX08
    eccx08_debug("ECDH_eccx08_get_pubkey() - NO HW \n");
    memcpy(raw_pubkey, test_pub_key, MEM_BLOCK_SIZE * 2);
#endif // USE_ECCX08
    memcpy(&tmp_buf[1], raw_pubkey, MEM_BLOCK_SIZE * 2);
    ret = EC_POINT_oct2point(ecgroup, pub_key, tmp_buf, MEM_BLOCK_SIZE * 2 + 1, NULL);
    if (!ret) {
        eccx08_debug("ECDH_eccx08_get_pubkey() - error in EC_POINT_oct2point \n");
        goto done;
    }
    rc = 1;
done:
    return (rc);
}

/**
 *  \brief Initialize the ECDH method by generates an ephemeral
 *  key in TLS_SLOT_ECDHE_PRIV slot of the ATECCX08
 *
 *  \param[in, out] ecdh A pointer to the EC_KEY structure with
 *         the ECDH private/public keys (private key data is
 *         ignored by the ateccx08 engine)
 *  \return 1 on success, 0 on error
 */
static int ECDH_eccx08_init(EC_KEY *ecdh)
{
    uint8_t serial_number[ATCA_SERIAL_NUM_SIZE];

    eccx08_debug("ECDH_eccx08_init()\n");
    return ECDH_eccx08_get_pubkey(ecdh->pub_key, serial_number, ATCA_SERIAL_NUM_SIZE);
}

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
static int ECDH_eccx08_compute_key(void *out, size_t outlen, const EC_POINT *pub_key,
                                   EC_KEY *ecdh, void* (*KDF)(const void *in,
                                                              size_t inlen, void *out,
                                                              size_t *outlen))
{
    BN_CTX *ctx;
    EC_POINT *tmp = NULL;
    BIGNUM *x = NULL, *y = NULL;
    const BIGNUM *priv_key;
    const EC_GROUP *group;
    int ret = -1;
    size_t buflen, len;
    unsigned char *buf = NULL;

    uint8_t serial_number[ATCA_SERIAL_NUM_SIZE];
    ATCA_STATUS status = ATCA_GEN_FAIL;
    uint8_t *raw_key = NULL;
    uint8_t *shared_secret = NULL;
    uint8_t slotid = TLS_SLOT_ECDHE_PRIV;
    point_conversion_form_t form;
    bool lock = false;
    uint8_t encKey[ATCA_KEY_SIZE];
    uint8_t enckeyId = TLS_SLOT_ENC_PARENT;

    if (ecdh->flags & SSL_kECDHe) {
        slotid = TLS_SLOT_AUTH_PRIV;
    }
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

    if (0 == software_ecdh) {
        eccx08_debug("ECDH_eccx08_compute_key(): HW \n");

        form = EC_GROUP_get_point_conversion_form(group);

        len = EC_POINT_point2oct(group, pub_key, form, NULL, len, NULL);
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
        shared_secret = (uint8_t *)OPENSSL_malloc(MEM_BLOCK_SIZE);
        if (shared_secret == NULL) {
            goto err;
        }

        buflen = (EC_GROUP_get_degree(group) + 7) / 8;
        len = MEM_BLOCK_SIZE;
        memset(buf, 0, buflen - len);

        //Create new Ephemeral private and public keys just if required
        if (ecdh->pub_key) {
            ECDH_eccx08_get_pubkey(ecdh->pub_key, serial_number, ATCA_SERIAL_NUM_SIZE);
        }

        status = atcatls_init(pCfg);
        if (status != ATCA_SUCCESS) {
            eccx08_debug("ECDH_eccx08_compute_key(): error in atcatls_init\n");
            goto err;
        }
        //set encryption key
        status = atcatlsfn_set_get_enckey(&eccx08_get_enc_key);
        if (status != ATCA_SUCCESS) {
            eccx08_debug("ECDH_eccx08_compute_key() - error in atcatlsfn_set_get_enckey \n");
            goto err;
        }
        status = eccx08_get_enc_key(encKey, ATCA_KEY_SIZE);
        if (status != ATCA_SUCCESS) {
            eccx08_debug("ECDH_eccx08_compute_key() - error in eccx08_get_enc_key \n");
            goto err;
        }
        status = atcatls_set_enckey(encKey, enckeyId, lock);
        if (status != ATCA_SUCCESS) {
            eccx08_debug("ECDH_eccx08_compute_key() - error in atcatls_init_enckey \n");
            goto err;
        }
        //read serial number here
        status = atcatls_get_sn(serial_number);
        if (status != ATCA_SUCCESS) {
            eccx08_debug("ECDH_eccx08_compute_key() - error in atcatls_get_sn \n");
            goto err;
        }
        status = atcatls_ecdh(slotid, &raw_key[1], shared_secret);
        if (status != ATCA_SUCCESS) {
            eccx08_debug("ECDH_eccx08_compute_key(): error in atcatls_ecdh\n");
            goto err;
        }
        status = atcatls_finish();
        if (status != ATCA_SUCCESS) {
            eccx08_debug("ECDH_eccx08_compute_key(): error in atcatls_finish\n");
            goto err;
        }
        if ((buf = OPENSSL_malloc(buflen)) == NULL) {
            ECDHerr(ECDH_F_ECDH_COMPUTE_KEY, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        memcpy(buf + buflen - len, shared_secret, len);
    } else {
        eccx08_debug("ECDH_eccx08_compute_key(): SW\n");

        priv_key = EC_KEY_get0_private_key(ecdh);
        if (priv_key == NULL) {
            ECDHerr(ECDH_F_ECDH_COMPUTE_KEY, ECDH_R_NO_PRIVATE_VALUE);
            goto err;
        }

        if (EC_KEY_get_flags(ecdh) & EC_FLAG_COFACTOR_ECDH) {
            if (!EC_GROUP_get_cofactor(group, x, ctx) ||
                !BN_mul(x, x, priv_key, ctx)) {
                ECDHerr(ECDH_F_ECDH_COMPUTE_KEY, ERR_R_MALLOC_FAILURE);
                goto err;
            }
            priv_key = x;
        }

        if ((tmp = EC_POINT_new(group)) == NULL) {
            ECDHerr(ECDH_F_ECDH_COMPUTE_KEY, ERR_R_MALLOC_FAILURE);
            goto err;
        }

        if (!EC_POINT_mul(group, tmp, NULL, pub_key, priv_key, ctx)) {
            ECDHerr(ECDH_F_ECDH_COMPUTE_KEY, ECDH_R_POINT_ARITHMETIC_FAILURE);
            goto err;
        }

        if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) ==
                NID_X9_62_prime_field) {
            if (!EC_POINT_get_affine_coordinates_GFp(group, tmp, x, y, ctx)) {
                ECDHerr(ECDH_F_ECDH_COMPUTE_KEY, ECDH_R_POINT_ARITHMETIC_FAILURE);
                goto err;
            }
        }
#ifndef OPENSSL_NO_EC2M
else {
            if (!EC_POINT_get_affine_coordinates_GF2m(group, tmp, x, y, ctx)) {
                ECDHerr(ECDH_F_ECDH_COMPUTE_KEY, ECDH_R_POINT_ARITHMETIC_FAILURE);
                goto err;
            }
        }
#endif

        buflen = (EC_GROUP_get_degree(group) + 7) / 8;
        len = BN_num_bytes(x);
        if (len > buflen) {
            ECDHerr(ECDH_F_ECDH_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        if ((buf = OPENSSL_malloc(buflen)) == NULL) {
            ECDHerr(ECDH_F_ECDH_COMPUTE_KEY, ERR_R_MALLOC_FAILURE);
            goto err;
        }

        memset(buf, 0, buflen - len);
        if (len != (size_t)BN_bn2bin(x, buf + buflen - len)) {
            ECDHerr(ECDH_F_ECDH_COMPUTE_KEY, ERR_R_BN_LIB);
            goto err;
        }
    }

    if (KDF != 0) {
        if (KDF(buf, buflen, out, &outlen) == NULL) {
            ECDHerr(ECDH_F_ECDH_COMPUTE_KEY, ECDH_R_KDF_FAILED);
            goto err;
        }
        ret = outlen;
    } else {
        /* no KDF, just copy as much as we can */
        if (outlen > buflen) outlen = buflen;
        memcpy(out, buf, outlen);
        ret = outlen;
    }

err:
    if (tmp) EC_POINT_free(tmp);
    if (ctx) BN_CTX_end(ctx);
    if (ctx) BN_CTX_free(ctx);
    if (buf) OPENSSL_free(buf);
    if (raw_key) OPENSSL_free(raw_key);
    if (shared_secret) OPENSSL_free(shared_secret);
    return (ret);
}
#endif                        /* !OPENSSL_NO_ECDH */

#ifndef OPENSSL_NO_ECDH
/**
 *  \brief eccx08_ecdh is an OpenSSL ECDH_METHOD structure
 *         specific to the ateccx08 engine.
 *         See the crypto/ecdh/ech_locl.h file for details on
 *         the ECDH_METHOD structure.
 *         Note that ECDH method requires a patch to be applied
 *         to the openssl code.
 */
ECDH_METHOD eccx08_ecdh = {
    "Atmel ECCX08 ECDH method",  // name
    ECDH_eccx08_compute_key,     // compute_key
    ECDH_eccx08_init,            // init
    NULL,                        // finish
    0,                           // flags
    NULL                         // app_data
};
#endif                        /* !OPENSSL_NO_ECDH */

/**
 *
 * \brief Initialize the ECDH method for ateccx08 engine
 *
 * \return 1 for success
 */
int eccx08_ecdh_init(uint32_t use_software)
{
    const ECDH_METHOD *ecdh_meth = ECDH_get_default_method();

    eccx08_ecdh.flags = ecdh_meth->flags;
    eccx08_ecdh.app_data = ecdh_meth->app_data;

    software_ecdh = use_software;
    if (use_software) {
        eccx08_debug("eccx08_ecdh_init() - SW\n");
    } else {
        eccx08_debug("eccx08_ecdh_init() - HW\n");
    }
    return 1;
}


