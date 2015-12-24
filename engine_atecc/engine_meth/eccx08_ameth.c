/**
 *  \file eccx08_ameth.c
 * \brief Implementation of OpenSSL ENGINE callback functions for ECC
 *       See ec_ameth.c for an example
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
#include <stdio.h>
#include <assert.h>
#include <engine.h>
#include <openssl/x509.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#ifndef OPENSSL_NO_CMS
    #include <openssl/cms.h>
#endif
#include <openssl/asn1t.h>
#include <evp.h>
#include <ossl_typ.h>
#include <err.h>
#ifdef OPENSSL_DEVEL
    #include <crypto/include/internal/asn1_int.h>
#endif // OPENSSL_DEVEL
#include <crypto/asn1/asn1_locl.h>
#include <crypto/ec/ec_lcl.h>
#include <crypto/ecdsa/ecs_locl.h>
#include "ecc_meth.h"

/**
 *
 * \brief Frees up the EVP_PKEY structure.
 *
 * \param[in] pkey - a pointer to the EVP_PKEY structure
 */
static void eccx08_int_ec_free(EVP_PKEY *pkey)
{
    eccx08_debug("eccx08_int_ec_free()\n");
    if (pkey && pkey->pkey.ec) {
        EC_KEY_free(pkey->pkey.ec);
        pkey->pkey.ec = NULL;
    }
    if (pkey && pkey->ameth) {
        pkey->ameth = NULL;
    }
}

/**
 *
 * \brief Verify an item signature (not used by ateccx08).
 *
 * \param[in] ctx - a pointer to the EVP_MD_CTX structure
 * \param[in] it - a pointer to the ASN1_ITEM structure
 * \param[in] asn - a void pointer to the parameter
 * \param[in] a - a pointer to the X509_ALGOR structure
 * \param[in] sig - a pointer to the ASN1_BIT_STRING
 *       structure
 * \param[in] pkey - a pointer to the EVP_PKEY structure
 * \return 1 for success
 */
int eccx08_item_verify(EVP_MD_CTX *ctx, const ASN1_ITEM *it, void *asn,
                       X509_ALGOR *a, ASN1_BIT_STRING *sig, EVP_PKEY *pkey)
{
    eccx08_debug("eccx08_item_verify()\n");
    assert(0);
    return 1;
}

/**
 *
 * \brief Generates a digest then sends the digest to the
 *        ATECCX08 chip to generate an ECDSA signature using
 *        private key from TLS_SLOT_AUTH_PRIV slot. The private
 *        key is always stays in the chip: OpenSSL (nor any
 *        other software) has no way to read it.
 *
 * \param[in] ctx - a pointer to the EVP_MD_CTX structure
 * \param[in] it - a pointer to the ASN1_ITEM structure
 * \param[in] asn - a void pointer to the parameter
 * \param[in] algor1 - a pointer to the X509_ALGOR structure
 * \param[in] algor2 - a pointer to the X509_ALGOR structure
 * \param[out] signature - a pointer to the ASN1_BIT_STRING
 *       structure to return the signature in the ASN.1 format
 * \return 1 for success
 */
int eccx08_item_sign(EVP_MD_CTX *ctx, const ASN1_ITEM *it, void *asn,
                     X509_ALGOR *algor1, X509_ALGOR *algor2,
                     ASN1_BIT_STRING *signature)
{
    int rc = 0;
    int ret = 0;
    const EVP_MD *type;
    EVP_PKEY *pkey;
    uint8_t *buf_in = NULL, *buf_out = NULL;
    uint8_t *sig_in = NULL, *sig_out = NULL;
    size_t inl = 0, outl = 0, outll = 0;
    int signid, paramtype;
    uint8_t slotid = TLS_SLOT_AUTH_PRIV;
    ATCA_STATUS status = ATCA_GEN_FAIL;

    extern ECDSA_METHOD eccx08_ecdsa;

    type = EVP_MD_CTX_md(ctx);
    pkey = EVP_PKEY_CTX_get0_pkey(ctx->pctx);

    if (!type || !pkey) {
        ASN1err(ASN1_F_ASN1_ITEM_SIGN_CTX, ASN1_R_CONTEXT_NOT_INITIALISED);
        return 0;
    }

    if (type->flags & EVP_MD_FLAG_PKEY_METHOD_SIGNATURE) {
        if (!pkey->ameth ||
            !OBJ_find_sigid_by_algs(&signid,
                                    EVP_MD_nid(type),
                                    pkey->ameth->pkey_id)) {
            ASN1err(ASN1_F_ASN1_ITEM_SIGN_CTX,
                    ASN1_R_DIGEST_AND_KEY_TYPE_NOT_SUPPORTED);
            return 0;
        }
    } else signid = type->pkey_type;

    if (pkey->ameth->pkey_flags & ASN1_PKEY_SIGPARAM_NULL) paramtype = V_ASN1_NULL;
    else paramtype = V_ASN1_UNDEF;

    if (algor1) X509_ALGOR_set0(algor1, OBJ_nid2obj(signid), paramtype, NULL);
    if (algor2) X509_ALGOR_set0(algor2, OBJ_nid2obj(signid), paramtype, NULL);

    inl = ASN1_item_i2d(asn, &buf_in, it);
    outll = outl = EVP_PKEY_size(pkey);
    buf_out = OPENSSL_malloc((unsigned int)outl);
    if ((buf_in == NULL) || (buf_out == NULL)) {
        outl = 0;
        ASN1err(ASN1_F_ASN1_ITEM_SIGN_CTX, ERR_R_MALLOC_FAILURE);
        goto done;
    }
#ifdef USE_ECCX08
    eccx08_debug("eccx08_item_sign() - HW\n");

    ret = EVP_DigestUpdate(ctx, buf_in, inl);
    if (!ret) goto done;
    ret = EVP_DigestFinal(ctx, buf_out, (unsigned int *)&outl);
    if (!ret) goto done;
    sig_in = OPENSSL_malloc((unsigned int)outll);  // source of crash
    sig_out = sig_in;
    if (sig_in == NULL) {
        outl = 0;
        ASN1err(ASN1_F_ASN1_ITEM_SIGN_CTX, ERR_R_MALLOC_FAILURE);
        goto done;
    }
    ECDSA_SIG *ecdsasig;
    ecdsasig = eccx08_ecdsa.ecdsa_do_sign(buf_out, outl, NULL, NULL, pkey->pkey.ec);
    if (ecdsasig == NULL) goto done;
    outl = i2d_ECDSA_SIG(ecdsasig, &sig_in);
    if (ecdsasig->r) {
        BN_free(ecdsasig->r);
        ecdsasig->r = NULL;
    }
    if (ecdsasig->s) {
        BN_free(ecdsasig->s);
        ecdsasig->s = NULL;
    }
    ECDSA_SIG_free(ecdsasig);

#else // USE_ECCX08
    eccx08_debug("eccx08_item_sign() - SW\n");
    if (!EVP_DigestSignUpdate(ctx, buf_in, inl)
        || !EVP_DigestSignFinal(ctx, buf_out, &outl)) {
        outl = 0;
        ASN1err(ASN1_F_ASN1_ITEM_SIGN_CTX, ERR_R_EVP_LIB);
        goto done;
    }
#endif // USE_ECCX08
    if (signature->data != NULL) {
        OPENSSL_free(signature->data);
    }
#ifdef USE_ECCX08
    signature->data = sig_out;
    sig_out = NULL;
#else
    signature->data = buf_out;
    buf_out = NULL;
#endif
    signature->length = outl;
    /* 
     * ASN1_item_sign_ctx() in a_sign.c comment (just copy it here): 
     * In the interests of compatibility, I'll make sure that the bit string
     * has a 'not-used bits' value of 0
     */
    signature->flags &= ~(ASN1_STRING_FLAG_BITS_LEFT | 0x07);
    signature->flags |= ASN1_STRING_FLAG_BITS_LEFT;

    rc = 1;
done:
    EVP_MD_CTX_cleanup(ctx);
    if (buf_in != NULL) {
        OPENSSL_cleanse((char *)buf_in, (unsigned int)inl);
        OPENSSL_free(buf_in);
    }
    if (buf_out != NULL) {
        OPENSSL_cleanse((char *)buf_out, outll);
        OPENSSL_free(buf_out);
    }
    if (sig_out != NULL) {
        OPENSSL_cleanse((char *)sig_out, outll);
        OPENSSL_free(sig_out);
    }
    return (rc);
}

/**
 *
 *  \brief eccx08_pkey_asn1_meth is an OpenSSL
 *         EVP_PKEY_ASN1_METHOD structure specific to the
 *         ateccx08 engine. See the crypto/asn1/asn1_locl.h file
 *         for details on the struct evp_pkey_asn1_method_st
 */
EVP_PKEY_ASN1_METHOD eccx08_pkey_asn1_meth = {  // See reference crypto/asn1/asn1_locl.h struct evp_pkey_asn1_method_st
    EVP_PKEY_EC,                                  // pkey_id
    EVP_PKEY_EC,                                  // pkey_base_id
    0,                                            // pkey_flags
    "EC",                                         // pem_str
    "Atmel ECCX08 Hardware Engine ASN1 Methods",  // info
    NULL,                                         // pub_decode - eckey_pub_decode in ec_meth.c - defaulted
    NULL,                                         // pub_encode - eckey_pub_encode in ec_meth.c - defaulted
    NULL,                                         // pub_cmp - eckey_pub_cmp in ec_meth.c - defaulted
    NULL,                                         // pub_print - eckey_pub_print in ec_meth.c - defaulted
    NULL,                                         // priv_decode - eckey_priv_decode in ec_meth.c - defaulted
    NULL,                                         // priv_encode - eckey_priv_encode in ec_meth.c - defaulted
    NULL,                                         // priv_print - eckey_priv_print in ec_meth.c - defaulted
    NULL,                                         // pkey_size - int_ec_size in ec_meth.c - defaulted
    NULL,                                         // pkey_bits - ec_bits in ec_meth.c - defaulted
#ifdef OPENSSL_DEVEL
    NULL,                                         // pkey_security_bits
#endif
    NULL,                                         // param_decode - eckey_param_decode in ec_meth.c - defaulted
    NULL,                                         // param_encode - eckey_param_encode in ec_meth.c - defaulted
    NULL,                                         // param_missing - ec_missing_paramters in ec_meth.c - defaulted
    NULL,                                         // param_copy - ec_copy_parameters in ec_meth.c - defaulted
    NULL,                                         // param_cmp - eckey_cmp_parameters in ec_meth.c - defaulted
    NULL,                                         // param_print - eckey_param_print in ec_meth.c - defaulted
    NULL,                                         // sig_print - defaulted
    eccx08_int_ec_free,                           // pkey_free
    NULL,                                         // pkey_ctrl - ec_pkey_ctrl in ec_meth.c - defaulted
    NULL,                                         // old_priv_decode - defaulted
    NULL,                                         // old_priv_encode - defaulted
#if 0 // TODO:  This routine needs to be completed
    eccx08_item_verify,                           // item_verify
#else
    NULL,
#endif
    eccx08_item_sign                              // item_sign
};

static int eccx08_pkey_asn1_meth_nids[] = { NID_id_ATECCX08, 0
};

/**
 *
 * \brief Initialize the EVP_PKEY_ASN1_METHOD method callback
 *        for ateccx08 engine. Just returns a pointer to
 *        EVP_PKEY_METHOD eccx08_pkey_meth
 *
 * \param[in] e - a pointer to the engine (ateccx08 in our
 *       case).
 * \param[out] pkey_asn1_meth - a double pointer to
 *       EVP_PKEY_ASN1_METHOD to return the EVP_PKEY_ASN1_METHOD
 *       eccx08_pkey_asn1_meth
 * \param[out] nids - a double pointer to return an array of
 *       nid's (we return 0)
 * \param[in] nid - a number of expected nid's (we ignore this
 *       parameter)
 * \return 1 for success
 */
int eccx08_pkey_asn1_meth_f(ENGINE *e, EVP_PKEY_ASN1_METHOD **pkey_asn1_meth,
                            const int **nids, int nid)
{
    eccx08_debug("eccx08_pkey_asn1_meth_f()\n");
    if (!pkey_asn1_meth) {
        //see gost_eng.c:231 for an example
        *nids = 0;
        return 0;
    }

    *pkey_asn1_meth = (EVP_PKEY_ASN1_METHOD *)&eccx08_pkey_asn1_meth;
    return 1;
}

/**
 *
 * \brief Initialize the EVP_PKEY_ASN1_METHOD method for
 *        ateccx08 engine
 *
 * \return 1 for success
 */
int eccx08_pkey_asn1_meth_init(void)
{
    extern const EVP_PKEY_ASN1_METHOD eckey_asn1_meth;

    eccx08_debug("eccx08_pkey_meth_init()\n");

    // We want to call our own encode. Otherwise it fails to write to file
    eccx08_pkey_asn1_meth.pub_encode = eckey_asn1_meth.pub_encode;
    eccx08_pkey_asn1_meth.pub_decode = eckey_asn1_meth.pub_decode;
    eccx08_pkey_asn1_meth.pub_cmp = eckey_asn1_meth.pub_cmp;
    eccx08_pkey_asn1_meth.pub_print = eckey_asn1_meth.pub_print;
    eccx08_pkey_asn1_meth.priv_decode = eckey_asn1_meth.priv_decode;
    eccx08_pkey_asn1_meth.priv_encode = eckey_asn1_meth.priv_encode;

    eccx08_pkey_asn1_meth.priv_print = eckey_asn1_meth.priv_print;
    eccx08_pkey_asn1_meth.pkey_size = eckey_asn1_meth.pkey_size;
    eccx08_pkey_asn1_meth.pkey_bits = eckey_asn1_meth.pkey_bits;
#ifdef OPENSSL_DEVEL
    eccx08_pkey_asn1_meth.pkey_security_bits = eckey_asn1_meth.pkey_security_bits;
#endif
    eccx08_pkey_asn1_meth.param_decode = eckey_asn1_meth.param_decode;
    eccx08_pkey_asn1_meth.param_encode = eckey_asn1_meth.param_encode;
    eccx08_pkey_asn1_meth.param_missing = eckey_asn1_meth.param_missing;

    eccx08_pkey_asn1_meth.param_copy = eckey_asn1_meth.param_copy;
    eccx08_pkey_asn1_meth.param_cmp = eckey_asn1_meth.param_cmp;
    eccx08_pkey_asn1_meth.param_print = eckey_asn1_meth.param_print;
    eccx08_pkey_asn1_meth.sig_print = eckey_asn1_meth.sig_print;

    eccx08_pkey_asn1_meth.pkey_ctrl = eckey_asn1_meth.pkey_ctrl;
    eccx08_pkey_asn1_meth.old_priv_decode = eckey_asn1_meth.old_priv_decode;
    eccx08_pkey_asn1_meth.old_priv_encode = eckey_asn1_meth.old_priv_encode;

    return 1;
}

