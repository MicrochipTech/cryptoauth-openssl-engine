/**
 *  \file eccx08_ecdsa_sign.c
 * \brief Implementation of OpenSSL ENGINE callback functions for ECDSA signingﬂ
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
#include <assert.h>
#include <openssl/engine.h>
#include <crypto/ecdh/ech_locl.h>
#include <crypto/ecdsa/ecs_locl.h>

#include <crypto/ec/ec_lcl.h>

#include <bn.h>
#include "ecc_meth.h"

#ifndef OPENSSL_NO_ECDSA

/**
 *
 * \brief Sends a digest to the ATECCX08 chip to generate an
 *        ECDSA signature using private key from
 *        TLS_SLOT_AUTH_PRIV slot. The private key is always
 *        stays in the chip: OpenSSL (nor any other software)
 *        has no way to read it.
 *
 * \param[in] dgst - a pointer to the buffer with a message
 *       digest (just SHA-256 is expected)
 * \param[in] dgst_len - the digest size (must be 32 bytes for
 *       ateccx08 engine)
 * \param[in] inv - a pointer to the BIGNUM structure (not used
 *       by ateccx08 engine)
 * \param[in] rp - a pointer to the BIGNUM structure (not used
 *       by ateccx08 engine)
 * \param[in] eckey - a pointer to EC_KEY structure with public
 *       ECC key and the private key token describing the
 *       private key in the ATECCX08 chip
 * \return a pointer to the ECDSA_SIG structure for success,
 *         NULL otherwise
 */
static ECDSA_SIG* ECDSA_eccx08_do_sign(const unsigned char *dgst, int dgst_len,
                                       const BIGNUM *inv, const BIGNUM *rp,
                                       EC_KEY *eckey)
{
    int ret = 0;
    uint8_t slotid = TLS_SLOT_AUTH_PRIV;
    uint8_t serial_number[ATCA_SERIAL_NUM_SIZE];
    uint8_t *raw_sig = NULL;
    uint16_t sig_len = MEM_BLOCK_SIZE * 2;
    ECDSA_SIG *sig = NULL;
    ATCA_STATUS status = ATCA_GEN_FAIL;

    const ECDSA_METHOD *std_meth = ECDSA_get_default_method();

#ifdef USE_ECCX08
    if (dgst_len != MEM_BLOCK_SIZE) {
        eccx08_debug("ECDSA_eccx08_do_sign(): ERROR dgst_len\n");
        goto done;
    }

    eccx08_debug("ECDSA_eccx08_do_sign(): int eckey HW\n");
    raw_sig = (uint8_t *)OPENSSL_malloc(sig_len);
    if (raw_sig == NULL) {
        goto done;
    }
    status = atcatls_init(pCfg);
    if (status != ATCA_SUCCESS) {
        eccx08_debug("ECDSA_eccx08_do_sign(): error in atcatls_init\n");
        goto done;
    }
    //read serial number here
    status = atcatls_get_sn(serial_number);
    if (status != ATCA_SUCCESS) {
        eccx08_debug("ECDSA_eccx08_do_sign() - error in atcatls_get_sn \n");
        goto done;
    }
    status = atcatls_sign(slotid, dgst, raw_sig);
    if (status != ATCA_SUCCESS) {
        eccx08_debug("ECDSA_eccx08_do_sign(): error in atcatls_sign\n");
        goto done;
    }
    status = atcatls_finish();
    if (status != ATCA_SUCCESS) {
        eccx08_debug("ECDSA_eccx08_do_sign(): error in atcatls_finish\n");
        goto done;
    }

    ret = eccx08_eckey_compare_privkey(eckey, slotid, serial_number, ATCA_SERIAL_NUM_SIZE);
    if (ret == 0) {
        eccx08_debug("ECDSA_eccx08_do_sign(): private key file mismatch\n");
        goto done;
    }
    sig = (ECDSA_SIG *)OPENSSL_malloc(sizeof(ECDSA_SIG));
    if (sig == NULL) {
        goto done;
    }
    sig->r = BN_bin2bn(raw_sig, sig_len / 2, NULL);
    sig->s = BN_bin2bn(&raw_sig[sig_len / 2], sig_len / 2, NULL);
done:
    if (raw_sig) {
        OPENSSL_free(raw_sig);
    }
#else // USE_ECCX08
    eccx08_debug("ECDSA_eccx08_do_sign(): ext eckey SW\n");
    sig = std_meth->ecdsa_do_sign(dgst, dgst_len, inv, rp, eckey);
#endif // USE_ECCX08
    return (sig);
}

/**
 *
 * \brief Setup the signing method.
 *
 * \param[in] eckey A pointer to EC_KEY structure
 * \param[in] ctx A pointer to the BN_CTX structure
 * \param[in/out] kinv A double pointer to the BIGNUM
 *       structure
 * \param[in/out] r A double pointer to the BIGNUM structure
 * \return 1 for success
 */
static int ECDSA_eccx08_sign_setup(EC_KEY *eckey, BN_CTX *ctx, BIGNUM **kinv,
                                   BIGNUM **r)
{
    const ECDSA_METHOD *std_meth = ECDSA_get_default_method();

    eccx08_debug("ECDSA_eccx08_sign_setup()\n");
    std_meth->ecdsa_sign_setup(eckey, ctx, kinv, r);
    return (1);
}

/**
 *
 * \brief Verifies the digest signature.
 *
 * \param[in] dgst A pointer to the buffer with a message
 *       digest (just SHA-256 is expected)
 * \param[in] dgst_len The digest size (must be 32 bytes for
 *       ateccx08 engine)
 * \param[in] inv A pointer to the ECDSA_SIG structure with
 *       expected signature
 * \param[in] eckey A pointer to EC_KEY structure with public
 *       ECC key to verify the signature
 * \return 1 for success (signature is verified and no error is
 *         detected)
 */
static int ECDSA_eccx08_do_verify(const unsigned char *dgst, int dgst_len,
                                  const ECDSA_SIG *sig, EC_KEY *eckey)
{
    int ret = 0;
    const ECDSA_METHOD *std_meth = ECDSA_get_default_method();

#ifdef USE_ECCX08
    ATCA_STATUS status = ATCA_GEN_FAIL;
    uint8_t *raw_pubkey = NULL;
    uint8_t *raw_sig = NULL;
    uint16_t sig_len = MEM_BLOCK_SIZE * 2;
    uint16_t len;
    const EC_GROUP *group;
    point_conversion_form_t form;
    bool verified = 0;

    eccx08_debug("ECDSA_eccx08_do_verify(): HW\n");

    raw_sig = (uint8_t *)OPENSSL_malloc(sig_len);
    if (raw_sig == NULL) {
        goto done;
    }

    len = BN_num_bytes(sig->r);
    if (len > sig_len / 2) {
        goto done;
    }
    len = BN_num_bytes(sig->s);
    if (len > sig_len / 2) {
        goto done;
    }
    len = BN_bn2bin(sig->r, raw_sig);
    if (len > sig_len / 2) {
        goto done;
    }
    len = BN_bn2bin(sig->s, &raw_sig[sig_len / 2]);
    if (len > sig_len / 2) {
        goto done;
    }

    group = EC_KEY_get0_group(eckey);
    form = EC_GROUP_get_point_conversion_form(group);

    len = EC_POINT_point2oct(group, eckey->pub_key, form, NULL, len, NULL);

    raw_pubkey = (uint8_t *)OPENSSL_malloc(len);
    if (raw_pubkey == NULL) {
        goto done;
    }

    if (eckey->pub_key) {
        EC_POINT_point2oct(group, eckey->pub_key, form, raw_pubkey, len, NULL);
    }

    status = atcatls_init(pCfg);
    if (status != ATCA_SUCCESS) {
        eccx08_debug("ECDSA_eccx08_do_verify(): error in atcatls_init\n");
        goto done;
    }

    status = atcatls_verify(dgst, raw_sig, &raw_pubkey[1], &verified);
    if (status != ATCA_SUCCESS) {
        eccx08_debug("ECDSA_eccx08_do_verify(): error in atcatls_verify\n");
        goto done;
    }

    status = atcatls_finish();
    if (status != ATCA_SUCCESS) {
        eccx08_debug("ECDSA_eccx08_do_verify(): error in atcatls_finish\n");
        goto done;
    }

    ret = (status == ATCA_SUCCESS);

done:
    if (raw_sig) {
        OPENSSL_free(raw_sig);
    }

    if (raw_pubkey) {
        OPENSSL_free(raw_pubkey);
    }
#else  // USE_ECCX08
    eccx08_debug("ECDSA_eccx08_do_verify(): SW\n");
    ret = std_meth->ecdsa_do_verify(dgst, dgst_len, sig, eckey);
#endif // USE_ECCX08

    return (ret);
}

#endif                        /* !OPENSSL_NO_ECDSA */


#ifndef OPENSSL_NO_ECDSA
/**
 *  \brief eccx08_ecdsa is an OpenSSL ECDSA_METHOD structure
 *         specific to the ateccx08 engine.
 *         See the crypto/ecdsa/ecs_locl.h file for details on
 *         the ECDSA_METHOD structure
 */
ECDSA_METHOD eccx08_ecdsa = {
    "ATECCX08 ECDSA METHOD",    // const char *name;
    ECDSA_eccx08_do_sign,       // ECDSA_SIG *(*ecdsa_do_sign) (const unsigned char *dgst, int dgst_len,
                                //    const BIGNUM *inv, const BIGNUM *rp,
                                //    EC_KEY *eckey);
    ECDSA_eccx08_sign_setup,    // int (*ecdsa_sign_setup) (EC_KEY *eckey, BN_CTX *ctx, BIGNUM **kinv,
                                //    BIGNUM **r);
    ECDSA_eccx08_do_verify,     // int (*ecdsa_do_verify) (const unsigned char *dgst, int dgst_len,
                                //    const ECDSA_SIG *sig, EC_KEY *eckey);
    0,                          // int flags;
    NULL,                       // void *app_data;
};
#endif                        /* !OPENSSL_NO_ECDSA */

