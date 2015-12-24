/**
 *  \file eccx08_eckey_meth.c
 * \brief Implementation of OpenSSL ENGINE callback functions
 *        for ECC and RSA key management. See reference code at
 *        ec_pmeth.c and crypto/evp/evp_locl.h
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
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <crypto/ec/ec_lcl.h>
#include <crypto/evp/evp.h>
#include <crypto/evp/evp_locl.h>
#include <crypto/asn1/asn1_locl.h>
#include <crypto/ossl_typ.h>
#include "ecc_meth.h"

/**
 *
 * \brief Allocates the EVP_PKEY structure, decrypt the RSA
 *        private key, and load it to the allocated EVP_PKEY
 *        structure. The encryption key is retrieved from the
 *        ECCX08 chip. See the eccx08_rsa_keygen() function from
 *        the eccx08_rsa_meth.c file for details.
 *
 * \param[in] e - a pointer to the engine (ateccx08 in our case).
 * \param[in] file - the file name associated with the private key
 * \param[in] ui_method - a pointer to the UI_METHOD structure
 *       (not used by the ateccx08 engine)
 * \param[in] callback_data - an optional parameter to provide
 *       the callback data (not used by the ateccx08 engine)
 * \return EVP_PKEY for success, NULL otherwise
 */
EVP_PKEY* eccx08_load_privkey(ENGINE *e, const char *file,
                              UI_METHOD *ui_method,
                              void *callback_data)
{
    BIO *key = NULL;
    EVP_PKEY *pkey = NULL;

    int ret = 0;
    int len = 0;
    BIGNUM *priv_key;
    char *ptr = NULL;
    ATCA_STATUS status = ATCA_GEN_FAIL;
    uint8_t serial_number[ATCA_SERIAL_NUM_SIZE];
    uint8_t aes_key[ATCA_KEY_SIZE];
    uint8_t aes_iv[ATCA_KEY_SIZE];
    int16_t aes_key_len;
    bool lock = false;
    uint8_t encKey[ATCA_KEY_SIZE];
    uint8_t enckeyId = TLS_SLOT_ENC_PARENT;
    uint8_t slotId = TLS_SLOT8_ENC_STORE;
    uint8_t block = 0;
    int16_t raw_key_len;
    char *raw_key = NULL;

    eccx08_debug("eccx08_load_privkey()\n");

    key = BIO_new(BIO_s_file());
    if (key == NULL) {
        eccx08_debug("eccx08_load_privkey() - error in BIO_new \n");
        goto err;
    }

    if (BIO_read_filename(key, file) <= 0) {
        eccx08_debug("eccx08_load_privkey() - error opening %s\n", file);
        goto err;
    }

    pkey = PEM_read_bio_PrivateKey(key, NULL, NULL, NULL);

    if (NULL == pkey) {
        eccx08_debug("eccx08_load_privkey(): pkey is NULL\n");
        goto err;
    }
    if (NULL == pkey->pkey.rsa) {
        eccx08_debug("eccx08_load_privkey(): pkey->pkey.rsa is NULL\n");
        fprintf(stderr, "**** ATECCX08 error ****\n"
                "Not a valid file: %s\n"
                " An encrypted RSA private key file is expected. \n",
                file);
        goto err;
    }
    priv_key = pkey->pkey.rsa->d;
    if (NULL == priv_key) {
        goto err;
    }

    len = priv_key->dmax * sizeof(*priv_key->d);
    ptr = (char *)OPENSSL_malloc(len);
    if (!ptr) {
        goto err;
    }
    raw_key = (char *)OPENSSL_malloc(len);
    if (!raw_key) {
        goto err;
    }

    //Restore AES key and IV from slot #8 of ATECC508
    status = atcatls_init(pCfg);
    if (status != ATCA_SUCCESS) {
        eccx08_debug("eccx08_load_privkey(): error in atcatls_init\n");
        goto err;
    }
    //set encryption key
    status = atcatlsfn_set_get_enckey(&eccx08_get_enc_key);
    if (status != ATCA_SUCCESS) {
        eccx08_debug("eccx08_load_privkey() - error in atcatlsfn_set_get_enckey \n");
        goto err;
    }
    status = eccx08_get_enc_key(encKey, ATCA_KEY_SIZE);
    if (status != ATCA_SUCCESS) {
        eccx08_debug("eccx08_load_privkey() - error in eccx08_get_enc_key \n");
        goto err;
    }
    status = atcatls_set_enckey(encKey, enckeyId, lock);
    if (status != ATCA_SUCCESS) {
        eccx08_debug("eccx08_load_privkey() - error in atcatls_init_enckey \n");
        goto err;
    }
    //read serial number here
    status = atcatls_get_sn(serial_number);
    if (status != ATCA_SUCCESS) {
        eccx08_debug("eccx08_load_privkey() - error in atcatls_get_sn \n");
        goto err;
    }

    aes_key_len = ATCA_KEY_SIZE;
    status = atcatls_enc_read(slotId, 0, enckeyId, aes_key, &aes_key_len);
    if ((status != ATCA_SUCCESS) || (aes_key_len != ATCA_KEY_SIZE)) {
        eccx08_debug("eccx08_load_privkey(): atcatls_enc_read AES key err, stat = %d, len = %d\n",
                     status, aes_key_len);
        goto err;
    }
    aes_key_len = ATCA_KEY_SIZE;
    status = atcatls_enc_read(slotId, 1, enckeyId, aes_iv, &aes_key_len);
    if ((status != ATCA_SUCCESS) || (aes_key_len != ATCA_KEY_SIZE)) {
        eccx08_debug("eccx08_load_privkey(): atcatls_enc_read IV err, stat = %d, len = %d\n",
                     status, aes_key_len);
        goto err;
    }
    status = atcatls_finish();
    if (status != ATCA_SUCCESS) {
        eccx08_debug("eccx08_load_privkey(): error in atcatls_finish\n");
        goto err;
    }

    //Verify the token stored in rsa->d field
    ret = eccx08_eckey_fill_key(ptr, len, slotId, serial_number, ATCA_SERIAL_NUM_SIZE);
    if (ret == 0) {
        goto err;
    }

    BN_bn2bin(priv_key, raw_key);

    //Make sure that the token in the file created for this ECC508 device
    if (0 != memcmp(raw_key, ptr, MEM_BLOCK_SIZE)) {
        eccx08_debug("eccx08_load_privkey(): wrong token\n");
        status = atcatls_finish();
        goto err;
    }

    //decrypt sensitive data
    if (NULL == pkey->pkey.rsa->p) {
        eccx08_debug("eccx08_load_privkey(): pkey->pkey.rsa->p is NULL\n");
        goto err;
    }
    ret = eccx08_BN_decrypt(pkey->pkey.rsa->p, aes_iv, aes_key);
    if (ret != 1) {
        eccx08_debug("eccx08_load_privkey(): eccx08_BN_decrypt p error\n");
        goto err;
    }
    if (NULL == pkey->pkey.rsa->q) {
        eccx08_debug("eccx08_load_privkey(): pkey->pkey.rsa->q is NULL\n");
        goto err;
    }
    ret = eccx08_BN_decrypt(pkey->pkey.rsa->q, aes_iv + 1, aes_key);
    if (ret != 1) {
        eccx08_debug("eccx08_load_privkey(): eccx08_BN_decrypt q error\n");
        goto err;
    }
    ret = eccx08_BN_decrypt(pkey->pkey.rsa->dmp1, aes_iv + 2, aes_key);
    if (ret != 1) {
        eccx08_debug("eccx08_load_privkey(): eccx08_BN_decrypt dmp1 error\n");
        goto err;
    }
    ret = eccx08_BN_decrypt(pkey->pkey.rsa->dmq1, aes_iv + 3, aes_key);
    if (ret != 1) {
        eccx08_debug("eccx08_load_privkey(): eccx08_BN_decrypt dmq1 error\n");
        goto err;
    }
    ret = eccx08_BN_decrypt(pkey->pkey.rsa->iqmp, aes_iv + 4, aes_key);
    if (ret != 1) {
        eccx08_debug("eccx08_load_privkey(): eccx08_BN_decrypt iqmp error\n");
        goto err;
    }
err:
    if (ptr) {
        OPENSSL_free(ptr);
    }
    if (raw_key) {
        OPENSSL_free(raw_key);
    }
    if (key != NULL) {
        BIO_free(key);
    }
    if (pkey == NULL) {
        eccx08_debug("eccx08_load_privkey() unable to load key from %s\n", file);
    }
    return (pkey);
}

/**
 *
 * \brief Allocates the EVP_PKEY structure and load there an ECC
 *        public key returned by the ECCX08 chip
 *
 * \param[in] e - a pointer to the engine (ateccx08 in our case).
 * \param[in] key_id - a string for key ID (not used by the ateccx08 engine)
 * \param[in] ui_method - a pointer to the UI_METHOD structure
 *       (not used by the ateccx08 engine)
 * \param[in] callback_data - an optional parameter to provide
 *       the callback data (not used by the ateccx08 engine)
 * \return EVP_PKEY for success, NULL otherwise
 */
EVP_PKEY* eccx08_load_pubkey(ENGINE *e, const char *key_id,
                             UI_METHOD *ui_method,
                             void *callback_data)
{
    EVP_PKEY *pkey = NULL;

    eccx08_debug("eccx08_load_pubkey()\n");
    pkey = (EVP_PKEY *)OPENSSL_malloc(sizeof(EVP_PKEY));
    if (pkey == NULL) {
        goto done;
    }
    pkey->pkey.ec = (EC_KEY *)OPENSSL_malloc(sizeof(EC_KEY));
    if (pkey->pkey.ec == NULL) {
        OPENSSL_free(pkey);
        goto done;
    }
    pkey->pkey.ec->pub_key = (EC_POINT *)OPENSSL_malloc(sizeof(EC_POINT));
    if (pkey->pkey.ec->pub_key == NULL) {
        OPENSSL_free(pkey->pkey.ec);
        OPENSSL_free(pkey);
        goto done;
    }

done:
    return (pkey);
}

extern const EVP_PKEY_ASN1_METHOD eckey_asn1_meth;

/**
 *
 * \brief Initialize the EC key.
 *
 * \param[in] ctx - a pointer to the EVP_PKEY_CTX
 * \return 1 for success
 */
static int eccx08_pkey_ec_init(EVP_PKEY_CTX *ctx)
{
    int rc = 0;
    int ret = 0;
    EC_KEY *eckey = NULL;
    EVP_PKEY *evpkey = ctx->pkey;
    X509_ALGOR *alg1;
    ATCA_STATUS status = ATCA_GEN_FAIL;

    uint8_t slotid = TLS_SLOT_AUTH_PRIV;
    uint8_t raw_pubkey[MEM_BLOCK_SIZE * 2];

    uint8_t serial_number[ATCA_SERIAL_NUM_SIZE];
    int snid, hnid;
    EC_GROUP *ecgroup = NULL;

    const EVP_PKEY_METHOD *std_meth = EVP_PKEY_meth_find(EVP_PKEY_EC);

    ret = std_meth->init(ctx);
    if (!ret) goto done;
    if (!evpkey) goto done;

    eckey = evpkey->pkey.ec;

#ifdef USE_ECCX08
    eccx08_debug("eccx08_pkey_ec_init() - hw\n");
    status = atcatls_init(pCfg);
    if (status != ATCA_SUCCESS) {
        eccx08_debug("eccx08_pkey_ec_init() - error in atcatls_init \n");
        goto done;
    }
    //read serial number here
    status = atcatls_get_sn(serial_number);
    if (status != ATCA_SUCCESS) {
        eccx08_debug("eccx08_pkey_ec_init() - error in atcatls_get_sn \n");
        goto done;
    }
    //Get public key without private key generation
    status = atcatls_gen_pubkey(slotid, raw_pubkey);
    if (status != ATCA_SUCCESS) {
        eccx08_debug("eccx08_pkey_ec_init() - error in atcatls_get_pubkey \n");
        goto done;
    }
    status = atcatls_finish();
    if (status != ATCA_SUCCESS) {
        eccx08_debug("eccx08_pkey_ec_init() - error in atcatls_finish \n");
        goto done;
    }
#else // USE_ECCX08
    eccx08_debug("eccx08_pkey_ec_init() - NO HW \n");
    memcpy(raw_pubkey, test_pub_key, MEM_BLOCK_SIZE * 2);
#endif // USE_ECCX08
    ret = eccx08_eckey_convert(&eckey, raw_pubkey, serial_number, ATCA_SERIAL_NUM_SIZE);
    if (!ret) {
        eccx08_debug("eccx08_pkey_ec_init() - error in eccx08_eckey_convert \n");
        goto done;
    }
    ctx->pkey = evpkey;
    rc = 1;
done:
    return (rc);
}

/**
 *
 * \brief Initialize the key generation method. A placeholder in our case.
 *
 * \param[in] ctx - a pointer to the EVP_PKEY_CTX
 * \return 1 for success
 */
static int eccx08_pkey_ec_keygen_init(EVP_PKEY_CTX *ctx)
{
    eccx08_debug("eccx08_pkey_ec_keygen_init()\n");
    //Call key generation init
    return 1;
}

/**
 *
 * \brief Generates the ECC private/public key pair. If the key
 * is locked in the TLS_SLOT_AUTH_PRIV then we just derive the
 * public key. If the key is not locked then it is
 * generated/regenerated.
 *
 * \param[in] ctx - a pointer to the EVP_PKEY_CTX
 * \param[out] pkey - a pointer to the generated EVP_PKEY
 * \return 1 for success
 */
static int eccx08_pkey_ec_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    int rc = 0;
    int ret = 0;
    EC_KEY *eckey = NULL;
    ATCA_STATUS status = ATCA_GEN_FAIL;

    uint8_t slotid = TLS_SLOT_AUTH_PRIV;
    uint8_t raw_pubkey[MEM_BLOCK_SIZE * 2];
    uint8_t serial_number[ATCA_SERIAL_NUM_SIZE] =
    { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39 };

    if (!ctx) goto done;
    if (!pkey) goto done;

    if (ctx->pkey && ctx->pkey->pkey.ec) {
        eckey = ctx->pkey->pkey.ec;
    } else {
        eckey = pkey->pkey.ec;
    }

#ifdef USE_ECCX08
    eccx08_debug("eccx08_pkey_ec_keygen() - HW\n");
    status = atcatls_init(pCfg);
    if (status != ATCA_SUCCESS) {
        eccx08_debug("eccx08_pkey_ec_keygen() - error atcatls_init \n");
        goto done;
    }
    //read serial number here
    status = atcatls_get_sn(serial_number);
    if (status != ATCA_SUCCESS) {
        eccx08_debug("eccx08_pkey_ec_keygen() - error atcatls_get_sn \n");
        goto done;
    }
    //Re-generate private key and return public key
    status = atcatls_create_key(slotid, raw_pubkey);
    if (status != ATCA_SUCCESS) {
        eccx08_debug("eccx08_pkey_ec_keygen() - error atcatls_create_key \n");
        eccx08_debug("probably the key is locked. Just get a public key from it \n");
        //Get public key without private key generation
        status = atcatls_gen_pubkey(slotid, raw_pubkey);
        if (status != ATCA_SUCCESS) {
            eccx08_debug("eccx08_pkey_ec_keygen() - error atcatls_gen_pubkey \n");
            goto done;
        }
    }
    status = atcatls_finish();
    if (status != ATCA_SUCCESS) {
        eccx08_debug("eccx08_pkey_ec_keygen() - error atcatls_finish \n");
        goto done;
    }
#else // USE_ECCX08
    eccx08_debug("eccx08_pkey_ec_keygen() - SW \n");
    memcpy(raw_pubkey, test_pub_key, MEM_BLOCK_SIZE * 2);
#endif // USE_ECCX08

    ret = eccx08_eckey_convert(&eckey, raw_pubkey, serial_number, ATCA_SERIAL_NUM_SIZE);
    if (!ret) {
        eccx08_debug("eccx08_pkey_ec_keygen() - error eccx08_eckey_convert \n");
        goto done;
    }
#ifdef ECC_DEBUG
#if 0 // This is a handy routine for debug
    ret = eccx08_eckey_encode_in_privkey(eckey, slotid, serial_number, ATCA_SERIAL_NUM_SIZE);
#endif
#endif // ECC_DEBUG
    if (!ret) goto done;

    pkey->pkey.ec = EC_KEY_dup(eckey);
    pkey->ameth = &eccx08_pkey_asn1_meth;
    rc = 1;
done:
    return (rc);
}

/**
 *
 *  \brief eccx08_pkey_meth is an OpenSSL EVP_PKEY_METHOD
 *         structure specific to the ateccx08 engine. See the
 *         crypto/evp/evp_locl.h and crypto/ec/ec_pmeth.c files
 *         for details on the EVP_PKEY_METHOD structure (struct
 *         evp_pkey_method_st).
 */
EVP_PKEY_METHOD eccx08_pkey_meth = {
    0,                           // pkey_id
    0,                           // flags
    eccx08_pkey_ec_init,         // init - pkey_ec_init in ec_pmeth.c
    NULL,                        // copy - pkey_ec_copy in ec_pmeth.c
    NULL,                        // cleanup - pkey_ec_cleanup in ec_pmeth.c
    NULL,                        // paramgen_init
    NULL,                        // paramgen - pkey_ec_paramgen in ec_pmeth.c
    eccx08_pkey_ec_keygen_init,  // keygen_init - pkey_ec_keygen_init in ec_pmeth.c
    eccx08_pkey_ec_keygen,       // keygen - pkey_ec_keygen in ec_pmeth.c
    NULL,                        // sign_init
    NULL,                        // sign - pkey_ec_sign in ec_pmeth.c
    NULL,                        // verify_init
    NULL,                        // verify - pkey_ec_verify in ec_pmeth.c
    NULL,                        // verify_recover_init
    NULL,                        // verify_recover
    NULL,                        // signctx_init
    NULL,                        // signctx
    NULL,                        // verifyctx_init
    NULL,                        // verifyctx
    NULL,                        // encrypt_init
    NULL,                        // encrypt
    NULL,                        // decrypt_init
    NULL,                        // decrypt
    NULL,                        // derive_init
#ifndef OPENSSL_NO_ECDH
    NULL,                        // derive - pkey_ec_kdf_derive in ec_pmeth.c
#else
    NULL,                        // derive - pkey_ec_kdf_derive in ec_pmeth.c
#endif
    NULL,                        // ctrl - pkey_ec_ctrl in ec_pmeth.c
    NULL                         // ctrl_str - pkey_ec_ctrl_str in ec_pmeth.c
};

static int eccx08_pkey_meth_nids[] = { NID_id_ATECCX08, 0
};

/**
 *
 * \brief Initialize the EVP_PKEY_METHOD method callback for
 *        ateccx08 engine. Just returns a pointer to
 *        EVP_PKEY_METHOD eccx08_pkey_meth
 *
 * \param[in] e - a pointer to the engine (ateccx08 in our case).
 * \param[out] pkey_meth - a double pointer to EVP_PKEY_METHOD
 *       to return the EVP_PKEY_METHOD eccx08_pkey_meth
 * \param[out] nids - a double pointer to return an array of nid's (we return 0)
 * \param[in] nid - a number of expected nid's (we ignore this parameter)
 * \return 1 for success
 */
int eccx08_pkey_meth_f(ENGINE *e, EVP_PKEY_METHOD **pkey_meth,
                       const int **nids, int nid)
{
    eccx08_debug("eccx08_pkey_meth_f()\n");
    if (!pkey_meth) {
        //see gost_eng.c:210 for an example
        *nids = 0;
        return 0;
    }

    *pkey_meth = (EVP_PKEY_METHOD *)&eccx08_pkey_meth;
    return 1;
}

/**
 *
 * \brief Initialize the EVP_PKEY_METHOD method for ateccx08 engine
 *
 * \return 1 for success
 */
int eccx08_pkey_meth_init(void)
{
    const EVP_PKEY_METHOD *pkey_meth = EVP_PKEY_meth_find(EVP_PKEY_EC);

    eccx08_debug("eccx08_pkey_meth_init()\n");

    eccx08_pkey_meth.copy = pkey_meth->copy;
    eccx08_pkey_meth.cleanup = pkey_meth->cleanup;
    eccx08_pkey_meth.paramgen_init = pkey_meth->paramgen_init;
    eccx08_pkey_meth.paramgen = pkey_meth->paramgen;
    eccx08_pkey_meth.sign_init = pkey_meth->sign_init;
    eccx08_pkey_meth.sign = pkey_meth->sign;
    eccx08_pkey_meth.verify_init = pkey_meth->verify_init;
    eccx08_pkey_meth.verify = pkey_meth->verify;
    eccx08_pkey_meth.verify_recover_init = pkey_meth->verify_recover_init;
    eccx08_pkey_meth.verify_recover = pkey_meth->verify_recover;
    eccx08_pkey_meth.signctx_init = pkey_meth->signctx_init;
    eccx08_pkey_meth.signctx = pkey_meth->signctx;
    eccx08_pkey_meth.verifyctx_init = pkey_meth->verifyctx_init;
    eccx08_pkey_meth.verifyctx = pkey_meth->verifyctx;
    eccx08_pkey_meth.encrypt_init = pkey_meth->encrypt_init;
    eccx08_pkey_meth.encrypt = pkey_meth->encrypt;
    eccx08_pkey_meth.decrypt_init = pkey_meth->decrypt_init;
    eccx08_pkey_meth.decrypt = pkey_meth->decrypt;
    eccx08_pkey_meth.derive_init = pkey_meth->derive_init;
    eccx08_pkey_meth.derive = pkey_meth->derive;
    eccx08_pkey_meth.ctrl = pkey_meth->ctrl;
    eccx08_pkey_meth.ctrl_str = pkey_meth->ctrl_str;

    return 1;
}


