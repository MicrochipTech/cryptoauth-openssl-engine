/**
 * \brief OpenSSL Engine Command Interface - "Commands" and openssl.cnf options
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <openssl/crypto.h>
#include <openssl/conf.h>

#include <stdint.h>
#include <limits.h>
#include <assert.h>
#include <openssl/engine.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include "eccx08_engine.h"
#include "eccx08_engine_internal.h"

#include "atcacert/atcacert_client.h"

/* OpenSSL Engine API demands this list be in cmd number order otherwise it'll
throw an invalid cmd number error*/
const ENGINE_CMD_DEFN eccx08_cmd_defns[] = {
    { ECCX08_CMD_GET_VERSION,           "VERSION", 
        "Get engine version", ENGINE_CMD_FLAG_NO_INPUT },
    { ECCX08_CMD_GET_KEY,               "GET_DEVICE_KEY", 
        "Get engine key structure for DEVICE_KEY_SLOT and stores in the provided file", ENGINE_CMD_FLAG_STRING },
    { ECCX08_CMD_GET_DEVICE_CERT,       "GET_DEVICE_CERT",
        "Get device certificate from hardware and stores in the provided filename", ENGINE_CMD_FLAG_STRING },
    { ECCX08_CMD_GET_SIGNER_CERT,       "GET_SIGNER_CERT", 
        "Get signer certificate from hardware and stores in the provided filename", ENGINE_CMD_FLAG_STRING },
    { ECCX08_CMD_LOAD_CERT_CTRL,        "LOAD_CERT_CTRL",
        "Load the device certificate into an OpenSSL cert", ENGINE_CMD_FLAG_INTERNAL },
    { ECCX08_CMD_KEY_SLOT,              "SET_KEY_SLOT", 
        "Where to find the device private key", ENGINE_CMD_FLAG_NUMERIC },
    { ECCX08_CMD_TRANSPORT_KEY,         "set_transport_key",
        "Binary blob with the transport key secret (32 bytes)", ENGINE_CMD_FLAG_STRING | ENGINE_CMD_FLAG_INTERNAL },
    { ECCX08_CMD_ECDH_SLOT,             "set_ecdh_slot",
        "Base slot for ecdh key(s)", ENGINE_CMD_FLAG_NUMERIC | ENGINE_CMD_FLAG_INTERNAL },
    { ECCX08_CMD_ECDH_SLOTS,            "set_ecdh_count",
        "Number of sequential slots to use for ecdh key(s) - e.g. ecdh_key_slot...ecdh_key_slot+ecdh_slot_count-1", 
        ENGINE_CMD_FLAG_NUMERIC | ENGINE_CMD_FLAG_INTERNAL },
    { ECCX08_CMD_DEVICE_CERT,           "set_device_cert_def",
        "Device Cert Configuration Section", ENGINE_CMD_FLAG_STRING | ENGINE_CMD_FLAG_INTERNAL },
    { ECCX08_CMD_SIGNER_CERT,           "set_signer_cert_def",
        "Signer Cert Configuration Section", ENGINE_CMD_FLAG_STRING | ENGINE_CMD_FLAG_INTERNAL },

    /* Structure has to end with a null element */
    { 0, NULL, NULL, 0 }
};

/**
 *
 * \brief Retrieves pre-programmed certificates from ATECCX08
 *        chip and saves them into temporary files as defined in
 *        the dev_cert_fname, signer_cert_fname, and
 *        root_cert_fname variables.
 *
 * \param[in] path a pointer to a buffer with a filename
 * \return ATCA_SUCCESS for success
 */
static int get_cert(char *filename, atcacert_def_t * pCertDef, atcacert_def_t * pSignerDef)
{
    ATCA_STATUS status = ATCA_GEN_FAIL;
    FILE *      fd = NULL;
    uint8_t *   pCertRaw = NULL;
    size_t      certRawSize = 0;

    DEBUG_ENGINE("%s %p\n", filename, pCertDef);

    if (!filename || !pCertDef || '\0' == filename[0])
    {
        return ATCA_BAD_PARAM;
    }

    do
    {
        /* Allocate a temporary buffer to load the reconstructed certificate */
        certRawSize = pCertDef->cert_template_size + 1;
        if (NULL == (pCertRaw = OPENSSL_malloc(certRawSize)))
        {
            DEBUG_ENGINE("Malloc Failure\n");
            break;
        }

        /* Get the device */
        status = atcab_init_safe(pCfg);
        if (ATCA_SUCCESS != status)
        {
            DEBUG_ENGINE("Init Failure: %#x\n", status);
            break;
        }

        if(pSignerDef)
        {
            status = eccx08_cert_load_pubkey(g_cert_def_1_signer_ptr, g_signer_1_ca_public_key);
        }
        else
        {
            status = atcab_read_pubkey(15, g_signer_1_ca_public_key);
        }

        if(ATCA_SUCCESS == status)
        {
            /* Extract/Reconstruct the certificate */
            status = atcacert_read_cert(pCertDef, 
                                        g_signer_1_ca_public_key, 
                                        pCertRaw, &certRawSize);
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

        fd = fopen(filename, "wb");
        if (fd == NULL) {
            DEBUG_ENGINE("Failure to open: %s\n", filename);
            status = ATCA_GEN_FAIL;
            break;
        }
        
        if(certRawSize != fwrite(pCertRaw, 1, certRawSize, fd))
        {
            DEBUG_ENGINE("Failed to write: %s\n", filename);
            status = ATCA_GEN_FAIL;
        }
        
    } while(0);

    if(pCertRaw)
    {
        OPENSSL_free(pCertRaw);
    }

    if(fd)
    {
        fclose(fd);
    }

    return status;
}

/**
 *
 * \brief Retrieves pre-programmed certificates from ATECCX08
 *        chip and saves them into temporary files as defined in
 *        the dev_cert_fname, signer_cert_fname, and
 *        root_cert_fname variables.
 *
 * \param[in] path a pointer to a buffer with a filename
 * \return ATCA_SUCCESS for success
 */
static int get_device_cert(char *filename)
{
    return get_cert(filename, g_cert_def_2_device_ptr, g_cert_def_1_signer_ptr);
}

/**
* \brief Retrieves key from ATECCX08 chip and builds a key structure and
* saves it as as a private key file in PEM format
*
* \return ATCA_SUCCESS for success
*/
static int get_key(ENGINE* e, uint16_t keyid, char * filename)
{
    ATCA_STATUS status = ATCA_GEN_FAIL;
    char* key_str[32];
    EVP_PKEY* pkey;
    
    DEBUG_ENGINE("Entered\n");

    snprintf(key_str, 32, "ATECCx08:%02x:%02x:%02x:%02x", pCfg->iface_type, 
        pCfg->atcai2c.bus, pCfg->atcai2c.slave_address, keyid);
    key_str[31] = '\0';

    pkey = eccx08_load_pubkey(e, key_str, NULL, NULL);

    if (pkey)
    {
        EC_KEY * ec = EVP_PKEY_get1_EC_KEY(pkey);
        if (ec)
        {
            BIO * bio = BIO_new(BIO_s_file());
            BIO_write_filename(bio, filename);
            if (bio)
            {
                if (PEM_write_bio_ECPrivateKey(bio, ec, NULL, NULL, 0, NULL, NULL))
                {
                    status = ATCA_SUCCESS;
                }
                BIO_free(bio);
            }
            EC_KEY_free(ec);
        }
        EVP_PKEY_free(pkey);
    }

    return status;
}

/**
 * \brief Retrieves pre-programmed signer certificate from
 *        ATECCX08 chip and saves it into a global signerCert
 *        buffer.
 *
 * \param[in] path a pointer to a buffer with a filename
 * \return ATCA_SUCCESS for success
 */
static int get_signer_cert(char *filename)
{
    return get_cert(filename, g_cert_def_1_signer_ptr, NULL);
}

static int load_device_cert(cmd_load_cert_params* p)
{
    if (!p)
    {
        return ATCA_BAD_PARAM;
    }

    if(eccx08_cert_load_client(NULL, NULL, NULL, &p->cert, NULL, NULL, NULL, NULL))
    {
        return ATCA_SUCCESS;
    }
    else
    {
        return ATCA_GEN_FAIL;
    }
}

static ATCA_STATUS set_device_key_slot(uint32_t i)
{
    if (16 > i)
    {
        eccx08_engine_config.device_key_slot = i;
        return ATCA_SUCCESS;
    }
    return ATCA_BAD_PARAM;
}

static ATCA_STATUS set_ecdh_slot(uint32_t i)
{
    if (16 > i)
    {
        eccx08_engine_config.ecdh_key_slot = i;
        return ATCA_SUCCESS;
    }
    return ATCA_BAD_PARAM;
}

static ATCA_STATUS set_ecdh_count(uint32_t i)
{
    if (16 > i)
    {
        eccx08_engine_config.ecdh_key_count = i;
        return ATCA_SUCCESS;
    }
    return ATCA_BAD_PARAM;
}

static ATCA_STATUS set_transport_key(uint8_t * p)
{
    if (p)
    {
        memcpy(g_eccx08_transport_key, p, sizeof(g_eccx08_transport_key));
        return ATCA_SUCCESS;
    }
    return ATCA_BAD_PARAM;
}

/**
 * \brief Configure the device cert from the config file 
 * \param[in] pStr should contain the section name
 * \return ATCA_SUCCESS when configuration completed without error
 */
static ATCA_STATUS config_device_cert(char* pStr)
{
    if (!pStr)
    {
        return ATCA_BAD_PARAM;
    }
    return ATCA_SUCCESS;
}

/**
 * \brief Configure the signer cert from the config file
 * \param[in] pStr should contain the section name
 * \return ATCA_SUCCESS when configuration completed without error
 */
static ATCA_STATUS config_signer_cert(char* pStr)
{
    if (!pStr)
    {
        return ATCA_BAD_PARAM;
    }
    return ATCA_SUCCESS;
}

/**
 * \brief Call a function of the ateccx08 engine depending on
 * provided command.
 *
 * \param[in] e a pointer to the ENGINE structure
 * \param[in] cmd a command to execute. For the full list of
 *       commands see ECCX08_CMD_* defines in the ecc_meth.h
 *       file
 * \param[in] i an integer parameter of the command
 * \param[in,out] p a void * parameter of the command
 * \param[in] f a function pointer parameter of the command
 * \return 1 for success
 */
int eccx08_cmd_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f)(void))
{
    ATCA_STATUS status = ATCA_GEN_FAIL;
    DEBUG_ENGINE("Entered\n");

    if ((cmd < ENGINE_CMD_BASE) || (cmd >= ECCX08_CMD_MAX)) {
        /* if cmd < ENGINE_CMD_BASE this is being called by OpenSSL.
           In this case no work to do so just return. */
        return ENGINE_OPENSSL_SUCCESS;
    }

    switch (cmd) {
        case ECCX08_CMD_GET_VERSION:
            DEBUG_ENGINE("ENGINE Version: %s\n", ECCX08_ENGINE_VERSION);
            status = ATCA_SUCCESS;
            break;

         case ECCX08_CMD_GET_KEY:
            status = get_key(e, eccx08_engine_config.device_key_slot, p);
            break;
        case ECCX08_CMD_GET_DEVICE_CERT:
            status = get_device_cert(p);
            break;
        case ECCX08_CMD_GET_SIGNER_CERT:
            status = get_signer_cert(p);
            break;
        case ECCX08_CMD_LOAD_CERT_CTRL:
            status = load_device_cert(p);
            break;
        case ECCX08_CMD_KEY_SLOT:
            status = set_device_key_slot(i);
            break;
        case ECCX08_CMD_ECDH_SLOT:
            status = set_ecdh_slot(i);
            break;
        case ECCX08_CMD_ECDH_SLOTS:
            status = set_ecdh_count(i);
            break;
        case ECCX08_CMD_DEVICE_CERT:
            status = config_device_cert(p);
            break;
        case ECCX08_CMD_SIGNER_CERT:
            status = config_signer_cert(p);
            break;
        case ECCX08_CMD_TRANSPORT_KEY:
            status = set_transport_key(p);
            break;
        default:
            DEBUG_ENGINE("Unknown command: %d with i=%d, p=%s\n", cmd, i, p?p:"");
            break;
    }

    if (ATCA_SUCCESS == status)
    {
        return ENGINE_OPENSSL_SUCCESS;
    }

    return ENGINE_OPENSSL_FAILURE;
}

