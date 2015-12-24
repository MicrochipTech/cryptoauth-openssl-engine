/**
 *  \file eccx08_rsa_meth.c
 * \brief Implementation of OpenSSL ENGINE callback functions
 *        for RSA. For details see crypto/rsa/rsa_eay.c
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

#include <stdio.h>
#include <crypto/cryptlib.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>

#include <stdint.h>
#include <assert.h>
#include <openssl/engine.h>
#include "ecc_meth.h"

#ifndef RSA_NULL

static int eccx08_rsa_init(RSA *rsa);

/**
 *
 * \brief Generates an RSA key. It is just a copy from rsa_gen.c
 *        - there is no separate method for it. For details see
 *          help to RSA_generate_key() function.
 *
 * \param[in/out] rsa - a pointer to the RSA structure
 * \param[in] bits - number of bits in the RSA key
 * \param[in] e_value - a pointer to the public exponent
 * \param[in] cb - a callback function may be used to provide
 *       feedback about the progress of the key generation
 * \return 1 for success
 */
static int eccx08_rsa_builtin_keygen(RSA *rsa, int bits, BIGNUM *e_value,
                                     BN_GENCB *cb)
{
    BIGNUM *r0 = NULL, *r1 = NULL, *r2 = NULL, *r3 = NULL, *tmp;
    BIGNUM local_r0, local_d, local_p;
    BIGNUM * pr0,*d,*p;
    int bitsp, bitsq, ok = -1, n = 0;
    BN_CTX *ctx = NULL;

    ctx = BN_CTX_new();
    if (ctx == NULL) goto err;
    BN_CTX_start(ctx);
    r0 = BN_CTX_get(ctx);
    r1 = BN_CTX_get(ctx);
    r2 = BN_CTX_get(ctx);
    r3 = BN_CTX_get(ctx);
    if (r3 == NULL) goto err;

    bitsp = (bits + 1) / 2;
    bitsq = bits - bitsp;

    /* We need the RSA components non-NULL */
    if (!rsa->n && ((rsa->n = BN_new()) == NULL)) goto err;
    if (!rsa->d && ((rsa->d = BN_new()) == NULL)) goto err;
    if (!rsa->e && ((rsa->e = BN_new()) == NULL)) goto err;
    if (!rsa->p && ((rsa->p = BN_new()) == NULL)) goto err;
    if (!rsa->q && ((rsa->q = BN_new()) == NULL)) goto err;
    if (!rsa->dmp1 && ((rsa->dmp1 = BN_new()) == NULL)) goto err;
    if (!rsa->dmq1 && ((rsa->dmq1 = BN_new()) == NULL)) goto err;
    if (!rsa->iqmp && ((rsa->iqmp = BN_new()) == NULL)) goto err;

    BN_copy(rsa->e, e_value);

    /* generate p and q */
    for (;;) {
        if (!BN_generate_prime_ex(rsa->p, bitsp, 0, NULL, NULL, cb)) goto err;
        if (!BN_sub(r2, rsa->p, BN_value_one())) goto err;
        if (!BN_gcd(r1, r2, rsa->e, ctx)) goto err;
        if (BN_is_one(r1)) break;
        if (!BN_GENCB_call(cb, 2, n++)) goto err;
    }
    if (!BN_GENCB_call(cb, 3, 0)) goto err;
    for (;;) {
        /*
         * When generating ridiculously small keys, we can get stuck
         * continually regenerating the same prime values. Check for this and
         * bail if it happens 3 times.
         */
        unsigned int degenerate = 0;
        do {
            if (!BN_generate_prime_ex(rsa->q, bitsq, 0, NULL, NULL, cb)) goto err;
        } while ((BN_cmp(rsa->p, rsa->q) == 0) && (++degenerate < 3));
        if (degenerate == 3) {
            ok = 0;             /* we set our own err */
            RSAerr(RSA_F_RSA_BUILTIN_KEYGEN, RSA_R_KEY_SIZE_TOO_SMALL);
            goto err;
        }
        if (!BN_sub(r2, rsa->q, BN_value_one())) goto err;
        if (!BN_gcd(r1, r2, rsa->e, ctx)) goto err;
        if (BN_is_one(r1)) break;
        if (!BN_GENCB_call(cb, 2, n++)) goto err;
    }
    if (!BN_GENCB_call(cb, 3, 1)) goto err;
    if (BN_cmp(rsa->p, rsa->q) < 0) {
        tmp = rsa->p;
        rsa->p = rsa->q;
        rsa->q = tmp;
    }

    /* calculate n */
    if (!BN_mul(rsa->n, rsa->p, rsa->q, ctx)) goto err;

    /* calculate d */
    if (!BN_sub(r1, rsa->p, BN_value_one())) goto err;               /* p-1 */
    if (!BN_sub(r2, rsa->q, BN_value_one())) goto err;               /* q-1 */
    if (!BN_mul(r0, r1, r2, ctx)) goto err;               /* (p-1)(q-1) */
    if (!(rsa->flags & RSA_FLAG_NO_CONSTTIME)) {
        pr0 = &local_r0;
        BN_with_flags(pr0, r0, BN_FLG_CONSTTIME);
    } else pr0 = r0;
    if (!BN_mod_inverse(rsa->d, rsa->e, pr0, ctx)) goto err;               /* d */

    /* set up d for correct BN_FLG_CONSTTIME flag */
    if (!(rsa->flags & RSA_FLAG_NO_CONSTTIME)) {
        d = &local_d;
        BN_with_flags(d, rsa->d, BN_FLG_CONSTTIME);
    } else d = rsa->d;

    /* calculate d mod (p-1) */
    if (!BN_mod(rsa->dmp1, d, r1, ctx)) goto err;

    /* calculate d mod (q-1) */
    if (!BN_mod(rsa->dmq1, d, r2, ctx)) goto err;

    /* calculate inverse of q mod p */
    if (!(rsa->flags & RSA_FLAG_NO_CONSTTIME)) {
        p = &local_p;
        BN_with_flags(p, rsa->p, BN_FLG_CONSTTIME);
    } else p = rsa->p;
    if (!BN_mod_inverse(rsa->iqmp, rsa->q, p, ctx)) goto err;

    ok = 1;
err:
    if (ok == -1) {
        RSAerr(RSA_F_RSA_BUILTIN_KEYGEN, ERR_LIB_BN);
        ok = 0;
    }
    if (ctx != NULL) {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }

    return ok;
}

/**
 *
 * \brief Encrypts sensitive parameters of the RSA structure
 *        with a generated AES key. The AES key and IV are saved
 *        into ATECCX08 chip
 *
 * \param[in/out] rsa - a pointer to the RSA structure
 * \param[in] bits - number of bits in the RSA key
 * \param[in] e_value - a pointer to the public exponent
 * \param[in] cb - a callback function may be used to provide
 *       feedback about the progress of the key generation
 * \return 1 for success
 */
static int eccx08_rsa_keygen(RSA *rsa, int bits, BIGNUM *e_value, BN_GENCB *cb)
{
    int ret = 0;
    ATCA_STATUS status = ATCA_GEN_FAIL;
    uint8_t serial_number[ATCA_SERIAL_NUM_SIZE];
    uint8_t aes_key[ATCA_KEY_SIZE];
    uint8_t aes_iv[ATCA_KEY_SIZE];
    bool lock = false;
    uint8_t encKey[ATCA_KEY_SIZE];
    uint8_t enckeyId = TLS_SLOT_ENC_PARENT;
    uint8_t slotId = TLS_SLOT8_ENC_STORE;
    int16_t raw_key_len;
    char *raw_key = NULL;
    const RAND_METHOD *rand_meth = RAND_get_rand_method();

    //Generate AES key and IV to encrypt RSA private key
    rand_meth->bytes(aes_key, ATCA_KEY_SIZE);
    rand_meth->bytes(aes_iv, ATCA_KEY_SIZE);

    ret = eccx08_rsa_builtin_keygen(rsa, bits, e_value, cb);
    if (ret != 1) {
        eccx08_debug("eccx08_rsa_keygen(): error in eccx08_rsa_builtin_keygen\n");
        return ret;
    }
    ret = eccx08_BN_encrypt(rsa->p, aes_iv, aes_key);
    if (ret != 1) {
        eccx08_debug("eccx08_rsa_keygen(): error in eccx08_BN_encrypt: rsa->p\n");
        return ret;
    }
    ret = eccx08_BN_encrypt(rsa->q, aes_iv + 1, aes_key);
    if (ret != 1) {
        eccx08_debug("eccx08_rsa_keygen(): error in eccx08_BN_encrypt: rsa->q\n");
        return ret;
    }
    ret = eccx08_BN_encrypt(rsa->dmp1, aes_iv + 2, aes_key);
    if (ret != 1) {
        eccx08_debug("eccx08_rsa_keygen(): error in eccx08_BN_encrypt: rsa->dmp1\n");
        return ret;
    }
    ret = eccx08_BN_encrypt(rsa->dmq1, aes_iv + 3, aes_key);
    if (ret != 1) {
        eccx08_debug("eccx08_rsa_keygen(): error in eccx08_BN_encrypt: rsa->dmq1\n");
        return ret;
    }
    ret = eccx08_BN_encrypt(rsa->iqmp, aes_iv + 4, aes_key);
    if (ret != 1) {
        eccx08_debug("eccx08_rsa_keygen(): error in eccx08_BN_encrypt: rsa->iqmp\n");
        return ret;
    }

    //Save AES key and IV to slot #8 of ATECC508
    status = atcatls_init(pCfg);
    if (status != ATCA_SUCCESS) {
        eccx08_debug("eccx08_rsa_keygen(): error in atcatls_init\n");
        goto err;
    }
    //set encryption key
    status = atcatlsfn_set_get_enckey(&eccx08_get_enc_key);
    if (status != ATCA_SUCCESS) {
        eccx08_debug("eccx08_rsa_keygen() - error in atcatlsfn_set_get_enckey \n");
        goto err;
    }
    status = eccx08_get_enc_key(encKey, ATCA_KEY_SIZE);
    if (status != ATCA_SUCCESS) {
        eccx08_debug("eccx08_rsa_keygen() - error in eccx08_get_enc_key \n");
        goto err;
    }
    status = atcatls_set_enckey(encKey, enckeyId, lock);
    if (status != ATCA_SUCCESS) {
        eccx08_debug("eccx08_rsa_keygen() - error in atcatls_init_enckey \n");
        goto err;
    }
    //read serial number here
    status = atcatls_get_sn(serial_number);
    if (status != ATCA_SUCCESS) {
        eccx08_debug("eccx08_rsa_keygen() - error in atcatls_get_sn \n");
        goto err;
    }
    status = atcatls_enc_write(slotId, 0, enckeyId, aes_key, ATCA_KEY_SIZE);
    if (status != ATCA_SUCCESS) {
        eccx08_debug("eccx08_rsa_keygen(): atcatls_enc_write AES err\n");
        goto err;
    }
    status = atcatls_enc_write(slotId, 1, enckeyId, aes_iv, ATCA_KEY_SIZE);
    if (status != ATCA_SUCCESS) {
        eccx08_debug("eccx08_rsa_keygen(): atcatls_enc_write IV err\n");
        goto err;
    }
    status = atcatls_finish();
    if (status != ATCA_SUCCESS) {
        eccx08_debug("eccx08_rsa_keygen(): error in atcatls_finish\n");
        goto err;
    }

    //Replace private key in RSA structure with a token
    //For now p and q are used rather than d in openssl
    raw_key_len = BN_num_bytes(rsa->d);
    raw_key = (char *)OPENSSL_malloc(raw_key_len);
    if (!raw_key) {
        goto err;
    }

    BN_bn2bin(rsa->d, raw_key);

    ret = eccx08_eckey_fill_key(raw_key, raw_key_len, slotId, serial_number, ATCA_SERIAL_NUM_SIZE);
    if (ret == 0) {
        goto err;
    }
    BN_bin2bn(raw_key, raw_key_len, rsa->d);
    ret = 1;
err:
    if (raw_key) {
        OPENSSL_free(raw_key);
    }
    return ret;
}

/**
 *  \brief eccx08_rsa_meth is an OpenSSL RSA_METHOD structure
 *         specific to the ateccx08 engine.
 *         See the include/openssl/rsa.h file for details on the
 *         RSA_METHOD structure
 */
static RSA_METHOD eccx08_rsa_meth = {
    "ECCX08 PKCS#1 RSA",
    NULL,
    NULL,    /* signature verification */
    NULL,    /* signing */
    NULL,
    NULL,
    NULL,
    eccx08_rsa_init,
    NULL,
    0,                          /* flags */
    NULL,
    0,                          /* rsa_sign */
    0,                          /* rsa_verify */
    eccx08_rsa_keygen           /* rsa_keygen */
};


/**
 *
 * \brief Returns a pointer to eccx08 RSA method implementation
 *
 * \return a pointer to RSA_METHOD structure
 */
const RSA_METHOD* ECCX08_RSA_meth(void)
{
    return (&eccx08_rsa_meth);
}

/**
 *
 * \brief Initialize the RSA method for ateccx08 engine
 *
 * \param[in/out] rsa - a pointer to the RSA structure
 * \return 1 for success
 */
static int eccx08_rsa_init(RSA *rsa)
{
    const RSA_METHOD *rsa_meth = RSA_PKCS1_SSLeay();
    eccx08_debug("eccx08_rsa_init()\n");
    eccx08_rsa_meth.rsa_pub_enc = rsa_meth->rsa_pub_enc;
    eccx08_rsa_meth.rsa_pub_dec = rsa_meth->rsa_pub_dec;
    eccx08_rsa_meth.rsa_priv_enc = rsa_meth->rsa_priv_enc;
    eccx08_rsa_meth.rsa_priv_dec = rsa_meth->rsa_priv_dec;

    eccx08_rsa_meth.rsa_mod_exp = rsa_meth->rsa_mod_exp;
    eccx08_rsa_meth.bn_mod_exp = rsa_meth->bn_mod_exp;

    eccx08_rsa_meth.flags = rsa_meth->flags;
    eccx08_rsa_meth.app_data = rsa_meth->app_data;

    eccx08_rsa_meth.finish = rsa_meth->finish;

    return (1);
}

#endif
