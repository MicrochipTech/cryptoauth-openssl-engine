/**
 * \brief OpenSSL Engine Callbacks/Interfaces to Cryptoauthlib Compressed Certificate Formats
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
#include "eccx08_engine_internal.h"
#include "atcacert/atcacert_def.h"
#include "atcacert/atcacert_client.h"

#if ATCA_OPENSSL_ENGINE_STATIC_CONFIG
extern const atcacert_def_t g_cert_def_1_signer;
extern const atcacert_def_t g_cert_def_2_device;
extern const atcacert_def_t g_csr_def_3_device;
#else
uint8_t             g_signer_1_ca_public_key[64];
#endif

/* Signer Certificate Definition */
atcacert_def_t *    g_cert_def_1_signer_ptr;

/* Device Certificate Definition */
atcacert_def_t *    g_cert_def_2_device_ptr;

/* Device Certificate Definition */
atcacert_def_t *    g_cert_def_3_csr_ptr;


/** \brief Allocate a new certificate (atcacert_def_t) */
atcacert_def_t * eccx08_cert_new(size_t size, size_t elements)
{
    atcacert_def_t * pCert = OPENSSL_malloc(sizeof(atcacert_def_t));

    DEBUG_ENGINE("Entered\n");

    if (pCert)
    {
        pCert->cert_template = (size)?OPENSSL_malloc(size):NULL;
        pCert->cert_template_size = size;
        pCert->cert_elements = (elements)?OPENSSL_malloc(sizeof(atcacert_cert_element_t) * elements):NULL;
        pCert->cert_elements_count = elements;

        /* Rationality check */
        if ((!pCert->cert_template && pCert->cert_template_size) ||
            (!pCert->cert_elements && pCert->cert_elements_count))
        {
            /* Incomplete allocation so free what we've already allocated */
            if (pCert->cert_template)
            {
                OPENSSL_free(pCert->cert_template);
            }
            if (pCert->cert_elements)
            {
                OPENSSL_free(pCert->cert_elements);
            }
            OPENSSL_free(pCert);
            pCert = NULL;
        }
    }
    return pCert;
}

/** \brief Free and cleanup a certificate (atcacert_def_t) */
int eccx08_cert_free(void* cert)
{
    atcacert_def_t * pCert = (atcacert_def_t *)cert;

    DEBUG_ENGINE("Entered\n");

    if (pCert)
    {
        if (pCert->cert_template)
        {
            OPENSSL_cleanse(pCert->cert_template, pCert->cert_template_size);
            OPENSSL_free(pCert->cert_template);
        }

        if (pCert->cert_elements)
        {
            OPENSSL_cleanse(pCert->cert_elements, 
                sizeof(atcacert_cert_element_t) * pCert->cert_elements_count);
            OPENSSL_free(pCert->cert_elements);
        }

        OPENSSL_cleanse(pCert, sizeof(atcacert_def_t));
        OPENSSL_free(pCert);
    }
    return ENGINE_OPENSSL_SUCCESS;
}

/** \brief Create a copy of an existing certificate (atcacert_def_t) */
atcacert_def_t * eccx08_cert_copy(atcacert_def_t * pCertOrig)
{
    atcacert_def_t * pCertCopy;

    DEBUG_ENGINE("Entered\n");

    if (!pCertOrig)
    {
        return NULL;
    }

    pCertCopy = eccx08_cert_new(pCertOrig->cert_template_size, 
        pCertOrig->cert_elements_count);

    if (pCertCopy)
    {
        /* Copy all the metadata */
        memcpy(pCertCopy, pCertOrig, (uint8_t*)&pCertCopy->cert_elements - (uint8_t*)pCertCopy);

        /* Copy the template */
        if (pCertOrig->cert_template && pCertOrig->cert_template_size)
        {
            memcpy(pCertCopy->cert_template, pCertOrig->cert_template,
                pCertOrig->cert_template_size);
        }

        /* Copy any extra data */
        if (pCertOrig->cert_elements && pCertOrig->cert_elements_count)
        {
            memcpy(pCertCopy->cert_elements, pCertOrig->cert_elements,
                sizeof(atcacert_cert_element_t) * pCertOrig->cert_elements_count);
        }
    }

    return pCertCopy;
}

int eccx08_cert_init(void)
{
    DEBUG_ENGINE("Entered\n");

#if ATCA_OPENSSL_ENGINE_STATIC_CONFIG
    /* Copy static certs to memory structures */
    g_cert_def_1_signer_ptr = eccx08_cert_copy(&g_cert_def_1_signer);
    g_cert_def_2_device_ptr = eccx08_cert_copy(&g_cert_def_2_device);
    g_cert_def_3_csr_ptr = eccx08_cert_copy(&g_csr_def_3_device);

    //extern const atcacert_def_t g_test_cert_def_0_device;
    //extern const atcacert_def_t g_test_cert_def_1_signer;

    //g_cert_def_1_signer_ptr = eccx08_cert_copy(&g_test_cert_def_1_signer);
    //g_cert_def_2_device_ptr = eccx08_cert_copy(&g_test_cert_def_0_device);
#endif
    return ENGINE_OPENSSL_SUCCESS;
}

int eccx08_cert_cleanup(void)
{
    DEBUG_ENGINE("Entered\n");

    eccx08_cert_free(g_cert_def_1_signer_ptr);
    eccx08_cert_free(g_cert_def_2_device_ptr);

    return ENGINE_OPENSSL_SUCCESS;
}

#if ATCA_OPENSSL_ENGINE_ENABLE_CERTS

ATCA_STATUS eccx08_cert_load_pubkey(const atcacert_def_t* def, const uint8_t keyout[64])
{
    ATCA_STATUS status = ATCA_SUCCESS;
    int i;
    uint8_t * pKeyTmp = OPENSSL_malloc(ATCA_BLOCK_SIZE*3);

    if(!def || !keyout || !pKeyTmp)
    {
        return ATCA_BAD_PARAM;
    }

    for(i=0; 3 > i && ATCA_SUCCESS == status; i++)
    {
        status = atcab_read_zone(def->public_key_dev_loc.zone, 
                                 def->public_key_dev_loc.slot, 
                                 i, 0, &pKeyTmp[i * 32], 32);
    }

    if(ATCA_SUCCESS == status)
    {
        atcacert_public_key_remove_padding(pKeyTmp, keyout);
    }

    OPENSSL_free(pKeyTmp);

    return status;
}

int eccx08_cert_load_client(ENGINE *e, 
    SSL *ssl,                       /**< Session */
    STACK_OF(X509_NAME) *ca_dn,     /**< Client CA Lists */
    X509 **ppCert,                  /**< Output Cert */
    EVP_PKEY **ppKey,               /**< Output Private Key - We'll try to ignore it rather than faking one */
    STACK_OF(X509) **ppOther,       /**< Intermediate CAs - I.e. our signer cert */
    UI_METHOD *ui_method, 
    void *callback_data)
{
    uint8_t *       pCertRaw = NULL;
    size_t          certRawSize = 0;
    X509 *          pCert = NULL;
    ATCA_STATUS     status = ATCA_GEN_FAIL;

    DEBUG_ENGINE("Entered\n");
    DEBUG_ENGINE("ca_dn: %p, ppCert: %p, ppKey: %p\n", ca_dn, ppCert, ppKey);

    if(ppCert)
    {
        DEBUG_ENGINE("*ppCert: %p\n", *ppCert);
    }

    if(ppKey)
    {
        DEBUG_ENGINE("*ppKey: %p\n", *ppKey);
    }

    if (!ppCert || !ppKey || !g_cert_def_2_device_ptr)
    {
        return ENGINE_OPENSSL_FAILURE;
    }

    if (*ppCert)
    {
        X509_free(*ppCert);
        *ppCert = NULL;
    }

    do
    {
        uint8_t *       pCertTmp;

        /* Allocate a temporary buffer to load the reconstructed certificate */
        certRawSize = g_cert_def_2_device_ptr->cert_template_size + 1;
        if (NULL == (pCertRaw = OPENSSL_malloc(certRawSize)))
        {
            break;
        }

        /* Get the device */
        status = atcab_init_safe(pCfg);
        if (ATCA_SUCCESS != status)
        {
            DEBUG_ENGINE("Init Failure: %#x\n", status);
            break;
        }

//        /* Extract/Reconstruct the signer certificate */
//        status = atcacert_read_cert(g_cert_def_1_signer_ptr, g_signer_1_ca_public_key, pCertRaw, &certRawSize);
        status = eccx08_cert_load_pubkey(g_cert_def_1_signer_ptr, g_signer_1_ca_public_key);

        if(ATCA_SUCCESS == status)
        {
            /* Extract/Reconstruct the device certificate */
            status = atcacert_read_cert(g_cert_def_2_device_ptr, g_signer_1_ca_public_key, pCertRaw, &certRawSize);
        }

        /* Make sure we release the device before checking if the operation succeeded */
        if (ATCA_SUCCESS != atcab_release_safe())
        {
            break;
        }

        /* Now check if atcacert_read_cert succeeded */
        if (ATCA_SUCCESS != status)
        {
            DEBUG_ENGINE("Failure: %#x\n", status);
            break;
        }

        /* The pointer passed into d2i_X509 gets modified so we'll lose track of
            our memory if we don't pass a temporary */
        pCertTmp = pCertRaw;
        pCert = d2i_X509(NULL, &pCertTmp, certRawSize);

        /** \todo Check the CA list to verify out cert is signed by somebody in the CA list.
            Technically we should verify the cert we're going to send back has been signed by something in the CA list
            per the TLS specification */

        /** \todo Return intermediate cert list. If ppOther is specified we should return our intermediate certificate
            however since OpenSSL core doesn't use it this feature is only if an application made the call so 
            we'll put a todo here */

        /* Return the newly reconstructed cert in OpenSSL's internal format */
        *ppCert = pCert;

        /* OpenSSL requires a matching "private" key but it luckily only compares the public key
        parameters which would normally be generated when the private key is loaded from a file */
        *ppKey = X509_get_pubkey(pCert);
    } while (0);

    /* Clean up allocated intermediate resources */
    if (pCertRaw)
    {
        OPENSSL_free(pCertRaw);
    }

    if (!*ppCert)
    {
        if (pCert)
        {
            X509_free(pCert);
        }
        return ENGINE_OPENSSL_FAILURE;
    }
    else
    {
        return ENGINE_OPENSSL_SUCCESS;
    }
}

#else

#endif /* ATCA_OPENSSL_ENGINE_ENABLE_CERTS */