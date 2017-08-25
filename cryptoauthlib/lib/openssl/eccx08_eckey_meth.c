/**
 * \brief OpenSSL ENGINE callback functions for ECC key management. 
 *      See reference code at ec_pmeth.c and crypto/evp/evp_locl.h
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

/* Additional OpenSSL Headers */
#include <openssl/evp.h>

/**
* \brief Converts raw 64 bytes of public key (ATECC508 format) to the
*  openssl EC_KEY structure. It allocates EC_KEY structure and
*  does not free it (must be a caller to free)
*
* \param[out] pEckey Pointer to EC_KEY with Public Key on success
* \param[in] pPubkeyRaw Raw public key, 64 bytes length 32-byte X following with 32-byte Y
* \return 1 on success, 0 on error
*/
static int eccx08_eckey_convert(EC_KEY *pEcKey, uint8_t *pPubKeyRaw, size_t pubkeylen)
{
    int         rv = ENGINE_OPENSSL_FAILURE;
    EC_GROUP *  group = NULL;
    EC_POINT *  point = NULL;

    if (!pEcKey || !pPubKeyRaw)
    {
        return ENGINE_OPENSSL_FAILURE;
    }

    /* Rationality checks */
    if ((POINT_CONVERSION_UNCOMPRESSED != pPubKeyRaw[0]) ||
        (ATCA_BLOCK_SIZE * 2 + 1 != pubkeylen))
    {
        return ENGINE_OPENSSL_FAILURE;
    }

    do
    {
        /* Get the group from the EC_KEY */
        group = EC_KEY_get0_group(pEcKey);

        /* Check that the group is allocated and configured correctly */
        if (!group)
        {
            group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
            if (group)
            {
                EC_GROUP_set_point_conversion_form(group, POINT_CONVERSION_UNCOMPRESSED);
                EC_GROUP_set_asn1_flag(group, OPENSSL_EC_NAMED_CURVE);

                if (!EC_KEY_set_group(pEcKey, group))
                {
                    break;
                }

                /* Since set_group makes a copy of it we have to free the temporary */
                EC_GROUP_free(group);

                /* Try to get the EC_KEY copy */
                group = EC_KEY_get0_group(pEcKey);
                if (!group)
                {
                    break;
                }
            }
            else
            {
                break;
            }
        }

        /* Allocate a public key from the group - this trusts that if one was provided its correct */
        point = EC_POINT_new(group);

        /* Use the openssl octect to point conversion routine to convert the raw format */
        if (EC_POINT_oct2point(group, point, pPubKeyRaw, pubkeylen, NULL))
        {
            EC_KEY_set_public_key(pEcKey, point);
            rv = ENGINE_OPENSSL_SUCCESS;
        }
    } while (0);

    /* Free temporary resources */
    if (point)
    {
        EC_POINT_free(point);
    }

    return (rv);
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
    ATCA_STATUS status = ATCA_GEN_FAIL;
    EC_GROUP *  group = NULL;
    EC_KEY *    eckey = NULL;
    EVP_PKEY *  pkey;

    DEBUG_ENGINE("Entered\n");

    if (NULL == (pkey = EVP_PKEY_new()))
    {
        return NULL;
    }

    do
    {
        uint8_t raw_pubkey[ATCA_BLOCK_SIZE * 2 + 1];

        /* Openssl raw key has a leading byte with conversion form id */
        raw_pubkey[0] = POINT_CONVERSION_UNCOMPRESSED;

        if (NULL == (eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)))
        {
            break;
        }

        /* Note: After this point eckey is associated with pkey and will be
            freed when pkey is freed */
        if (!EVP_PKEY_assign_EC_KEY(pkey, eckey))
        {
            EC_KEY_free(eckey);
            break;
        }

        /* Assign the group info */
        group = EC_KEY_get0_group(eckey);
        if (group)
        {
            EC_GROUP_set_point_conversion_form(group, POINT_CONVERSION_UNCOMPRESSED);
            EC_GROUP_set_asn1_flag(group, OPENSSL_EC_NAMED_CURVE);
        }

        /* Connect the basics */
        pkey->type = EVP_PKEY_EC;
        pkey->engine = e;
        pkey->ameth = EVP_PKEY_asn1_find(&e, EVP_PKEY_EC);

        /* Grab the device */
        status = atcab_init_safe(pCfg); 
        if (status != ATCA_SUCCESS) {
            DEBUG_ENGINE("Result %d\n", status);
            break;
        }

        /* Get public key without private key generation */
        status = atcab_get_pubkey(eccx08_engine_config.device_key_slot, &raw_pubkey[1]);
        if (status != ATCA_SUCCESS) {
            DEBUG_ENGINE("Result %d\n", status);
        }

        /* Release the device before testing status */
        if (ATCA_SUCCESS != atcab_release_safe()) {
            DEBUG_ENGINE("Result %d\n", status);
            break;
        }

        /* Check atcab_get_pubkey result */
        if (ATCA_SUCCESS != status)
        {
            DEBUG_ENGINE("Result %d\n", status);
            break;
        }

        /* Convert the raw public key into OpenSSL type */
        if (!eccx08_eckey_convert(eckey, raw_pubkey, sizeof(raw_pubkey)))
        {
            DEBUG_ENGINE("Convert Failed\n");
            status = ATCA_GEN_FAIL;
            break;
        }
    } while (0);

    if (ATCA_SUCCESS != status)
    {
        if (pkey)
        {
            EVP_PKEY_free(pkey);
            pkey = NULL;
        }
    }

    return (pkey);
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
    DEBUG_ENGINE("Entered\n");
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
    int rv = ENGINE_OPENSSL_FAILURE;
    EC_KEY *eckey = NULL;
    EC_GROUP * group = NULL;

    ATCA_STATUS status = ATCA_GEN_FAIL;
    uint8_t raw_pubkey[ATCA_BLOCK_SIZE * 2 + 1];

    DEBUG_ENGINE("Entered\n");

    if (!ctx || !pkey)
    {
        return ENGINE_OPENSSL_FAILURE;
    }

    eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!eckey)
    {
        return ENGINE_OPENSSL_FAILURE;
    }

    /* Note: After this point eckey is associated with pkey and will be 
        freed when pkey is freed */
    EVP_PKEY_assign_EC_KEY(pkey, eckey);

    do
    {
        if (EVP_PKEY_CTX_get0_pkey(ctx))
        {
            if (!EVP_PKEY_copy_parameters(pkey, EVP_PKEY_CTX_get0_pkey(ctx)))
            {
                break;
            }
        }

        /* Grab the device */
        status = atcab_init_safe(pCfg);
        if (status != ATCA_SUCCESS) {
            DEBUG_ENGINE("Result %d\n", status);
            break;
        }

        /* Openssl raw key has a leading byte with conversion form id */
        raw_pubkey[0] = POINT_CONVERSION_UNCOMPRESSED;

        //Re-generate private key and return public key
        status = atcab_genkey(eccx08_engine_config.device_key_slot, &raw_pubkey[1]);
        if (status != ATCA_SUCCESS) {
            DEBUG_ENGINE("Result %d\n", status);
            DEBUG_ENGINE("The key is probably locked. Get the public key from it \n");
            //Get public key without private key generation
            status = atcab_get_pubkey(eccx08_engine_config.device_key_slot, &raw_pubkey[1]);
        }

        if (ATCA_SUCCESS != atcab_release_safe()) {
            DEBUG_ENGINE("Result %d\n", status);
            break;
        }

        /* Check atcab_get_pubkey result */
        if (ATCA_SUCCESS != status)
        {
            DEBUG_ENGINE("Result %d\n", status);
            break;
        }

        /* Convert from raw bytes to OpenSSL key */
        rv = eccx08_eckey_convert(eckey, raw_pubkey, sizeof(raw_pubkey));
        if (!rv)
        {
            DEBUG_ENGINE("Error in eccx08_eckey_convert \n");
        }
    } while (0);
}

static EVP_PKEY_METHOD * eccx08_pkey_meth;

static int eccx08_pkey_meth_ids[] = { EVP_PKEY_EC, 0 };

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
int eccx08_pmeth_selector(ENGINE *e, EVP_PKEY_METHOD **pkey_meth,
                       const int **nids, int nid)
{
    DEBUG_ENGINE("Entered\n");
    if (!pkey_meth) {
        *nids = eccx08_pkey_meth_ids;
        return 2;
    }

    if (EVP_PKEY_EC == nid)
    {
        *pkey_meth = eccx08_pkey_meth;
        return ENGINE_OPENSSL_SUCCESS;
    }
    else
    {
        DEBUG_ENGINE("Unsupported type %d requested\n", nid);
        *pkey_meth = NULL;
        return ENGINE_OPENSSL_FAILURE;
    }
}

/**
 *
 * \brief Allocate and initialize a pkey method structure for the engine
  * \return 1 for success
 */
int eccx08_pkey_meth_init(void)
{
    DEBUG_ENGINE("Entered\n");

    if (!eccx08_pkey_meth)
    {
        eccx08_pkey_meth = EVP_PKEY_meth_new(EVP_PKEY_EC, 0);
    }
    
    if (!eccx08_pkey_meth)
    {
        return ENGINE_OPENSSL_FAILURE;
    }
    
    /* Copy the default methods */
    EVP_PKEY_meth_copy(eccx08_pkey_meth, EVP_PKEY_meth_find(EVP_PKEY_EC));

    /* Set our own local methods */
    EVP_PKEY_meth_set_keygen(eccx08_pkey_meth, eccx08_pkey_ec_keygen_init, eccx08_pkey_ec_keygen);

    return ENGINE_OPENSSL_SUCCESS;
}

int eccx08_pkey_meth_cleanup(void)
{
    DEBUG_ENGINE("Entered\n");
    if (eccx08_pkey_meth)
    {
        EVP_PKEY_meth_free(eccx08_pkey_meth);
        eccx08_pkey_meth = NULL;
    }
}
