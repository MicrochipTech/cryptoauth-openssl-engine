/**
 *  \file eccx08_cmd_defns.c
 * \brief Implementation of OpenSSL ENGINE callback functions for certificate handling
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
#include <string.h>
#include <stdlib.h>

#include <openssl/crypto.h>

#include <stdint.h>
#include <limits.h>
#include <assert.h>
#include <openssl/engine.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <crypto/ec/ec_lcl.h>
#include <crypto/ecdh/ech_locl.h>
#include <crypto/ecdsa/ecs_locl.h>
#include <err.h>
#include "ecc_meth.h"

static const ENGINE_CMD_DEFN eccx08_cmd_defns[] = {
    { ECCX08_CMD_GET_DEVICE_CERT,
        "device_cert",
        "Get device certificate from hardware",
        ENGINE_CMD_FLAG_NO_INPUT },
    { ECCX08_CMD_GET_PRIV_KEY,
        "get_privkey",
        "Get device private key from hardware",
        ENGINE_CMD_FLAG_NO_INPUT },
    { ECCX08_CMD_GET_PUB_KEY,
        "get_pubkey",
        "Get device public key from hardware",
        ENGINE_CMD_FLAG_NO_INPUT },
    { ECCX08_CMD_GET_SIGNER_CERT,
        "signer_cert",
        "Get signer certificate from hardware",
        ENGINE_CMD_FLAG_NO_INPUT },
    { ECCX08_CMD_VERIFY_SIGNER_CERT,
        "signer_verify",
        "Verify signer certificate using hardware",
        ENGINE_CMD_FLAG_NO_INPUT },
    { ECCX08_CMD_VERIFY_DEVICE_CERT,
        "device_verify",
        "Verify device certificate using hardware",
        ENGINE_CMD_FLAG_NO_INPUT },

    { 0, NULL, NULL, 0 }
};

#include "platform.h"

uint8_t signerPubkey[64] = { 0 };
uint8_t caPubkey[64] = { 0 };
uint8_t rootCert[1024] = { 0 };
uint8_t signerCert[1024] = { 0 };
uint8_t deviceCert[1024] = { 0 };
size_t rootCertSize = 1024;
size_t signerCertSize = 1024;
size_t deviceCertSize = 1024;

int get_device_cert(char *path);
int get_public_key(void);
int get_signer_cert(char *path);
int verify_signer_cert(void);
int verify_device_cert(void);
int get_root_cert(char *path);
int extract_all_certs(char *path);

/**
 *
 * \brief Retrieves pre-programmed certificates from ATECCX08
 *        chip and saves them into temporary files as defined in
 *        the dev_cert_fname, signer_cert_fname, and
 *        root_cert_fname variables.
 *
 * \param[in] path a pointer to a buffer with a path to the
 *       certstore
 * \return ATCA_SUCCESS for success
 */
int get_device_cert(char *path)
{
    ATCA_STATUS status = ATCA_GEN_FAIL;
    int len = 0;
    char dev_cert_fname[300];

    snprintf(dev_cert_fname, 300, "%s/personal/AT_device.der", path);

    eccx08_debug("eccx08_cmd_ctrl(ECCX08_CMD_GET_DEVICE_CERT)\n");
    // Get the device certificate
    status = atcatls_get_cert(&g_cert_def_0_device_t, signerPubkey, deviceCert, &deviceCertSize);
    if (status != ATCA_SUCCESS) {
        eccx08_debug("eccx08_cmd_ctrl(): error in atcatls_get_cert\n");
        goto err;
    }
    FILE *fd = fopen(dev_cert_fname, "wb");
    if (fd == NULL) {
        fprintf(stderr, "get_device_cert(): cannot open file %s\n", dev_cert_fname);
        goto err;
    }
    len = fwrite(deviceCert, 1, deviceCertSize, fd);
    if (len != deviceCertSize) {
        fprintf(stderr, "get_device_cert(): cannot write file %s; len = %d\n", dev_cert_fname, len);
        goto err;
    }
    fclose(fd);
err:
    return status;
}

/**
 *
 * \brief Retrieves the signer public key from ATECCX08 chip and
 *        saves them into a global signerPubkey buffer.
 *
 * \return ATCA_SUCCESS for success
 */
int get_public_key(void)
{
    ATCA_STATUS status = ATCA_GEN_FAIL;

    eccx08_debug("eccx08_cmd_ctrl(ECCX08_CMD_GET_PUB_KEY)\n");
    // Get the signer public key from the signer certificate
    status = atcacert_get_subj_public_key(&g_cert_def_1_signer_t, signerCert, signerCertSize, signerPubkey);
    if (status != ATCA_SUCCESS) {
        eccx08_debug("eccx08_cmd_ctrl(): error in atcacert_get_subj_public_key\n");
        goto err;
    }
err:
    return status;
}

/**
 *
 * \brief Retrieves pre-programmed signer certificate from
 *        ATECCX08 chip and saves it into a global signerCert
 *        buffer.
 *
 * \param[in] path a pointer to a buffer with a path to the
 *       certstore
 * \return ATCA_SUCCESS for success
 */
int get_signer_cert(char *path)
{
    ATCA_STATUS status = ATCA_GEN_FAIL;
    int len = 0;
    char signer_cert_fname[300];

    snprintf(signer_cert_fname, 300, "%s/trusted/AT_signer.der", path);

    eccx08_debug("eccx08_cmd_ctrl(ECCX08_CMD_GET_SIGNER_CERT)\n");
    // Get the signer certificate
    status = atcatls_get_cert(&g_cert_def_1_signer_t, g_signer_1_ca_public_key_t, signerCert, &signerCertSize);
    if (status != ATCA_SUCCESS) {
        eccx08_debug("eccx08_cmd_ctrl(): error in atcatls_get_cert\n");
        goto err;
    }
    FILE *fd = fopen(signer_cert_fname, "wb");
    if (fd == NULL) {
        fprintf(stderr, "get_signer_cert(): cannot open file %s\n", signer_cert_fname);
        goto err;
    }
    len = fwrite(signerCert, 1, signerCertSize, fd);
    if (len != signerCertSize) {
        fprintf(stderr, "get_signer_cert(): cannot write file %s; len = %d\n", signer_cert_fname, len);
        goto err;
    }
    fclose(fd);
err:
    return status;
}

/**
 *
 * \brief Verifies the signer certificate using the ATECCX08
 *        chip hardware and data in caPubkey buffer (CA root
 *        key).
 *
 * \return ATCA_SUCCESS for success
 */
int verify_signer_cert(void)
{
    ATCA_STATUS status = ATCA_GEN_FAIL;

    eccx08_debug("eccx08_cmd_ctrl(ECCX08_CMD_VERIFY_SIGNER_CERT)\n");
    // Verify the signer certificate
    status = atcacert_verify_cert_hw(&g_cert_def_1_signer_t, signerCert, signerCertSize, caPubkey);
    if (status != ATCA_SUCCESS) {
        eccx08_debug("eccx08_cmd_ctrl(): error in atcacert_verify_cert_hw\n");
        goto err;
    }
err:
    return status;
}

/**
 *
 * \brief Verifies the device certificate using the ATECCX08
 *        chip hardware and data in signerPubkey buffer.
 *
 * \return ATCA_SUCCESS for success
 */
int verify_device_cert(void)
{
    ATCA_STATUS status = ATCA_GEN_FAIL;

    eccx08_debug("eccx08_cmd_ctrl(ECCX08_CMD_VERIFY_DEVICE_CERT)\n");
    // Verify the device certificate
    status = atcacert_verify_cert_hw(&g_cert_def_0_device_t, deviceCert, deviceCertSize, signerPubkey);
    if (status != ATCA_SUCCESS) {
        eccx08_debug("eccx08_cmd_ctrl(): error in atcacert_verify_cert_hw\n");
        goto err;
    }
err:
    return status;
}

/**
 *
 * \brief Retrieves pre-programmed CA certificate (the root)
 *        from ATECCX08 chip and saves it into a global rootCert
 *        buffer.
 *
 * \param[in] path a pointer to a buffer with a path to the
 *       certstore
 * \return ATCA_SUCCESS for success
 */
int get_root_cert(char *path)
{
    ATCA_STATUS status = ATCA_GEN_FAIL;
    int len = 0;
    char root_cert_fname[300];

    snprintf(root_cert_fname, 300, "%s/trusted/AT_root.der", path);

    eccx08_debug("eccx08_cmd_ctrl(ECCX08_CMD_GET_ROOT_CERT)\n");
    // Get root certificate
    status = atcatls_get_ca_cert(rootCert, &rootCertSize);
    if (status != ATCA_SUCCESS) {
        eccx08_debug("eccx08_cmd_ctrl(): error in atcacert_verify_cert_hw\n");
        goto err;
    }
    FILE *fd = fopen(root_cert_fname, "wb");
    if (fd == NULL) {
        fprintf(stderr, "get_root_cert(): cannot open file %s\n", root_cert_fname);
        goto err;
    }
    len = fwrite(rootCert, 1, rootCertSize, fd);
    if (len != rootCertSize) {
        fprintf(stderr, "get_root_cert(): cannot write file %s; len = %d\n", root_cert_fname, len);
        goto err;
    }
    fclose(fd);
err:
    return status;
}

/**
 *
 * \brief Retrieves all pre-programmed certificates from
 *        ATECCX08 chip and saves it into a global buffers.
 *        Calls functions to verify them.
 *
 * \param[in] path a pointer to a buffer with a path to the
 *       certstore
 * \return ATCA_SUCCESS for success
 */
int extract_all_certs(char *path)
{
    ATCA_STATUS status = ATCA_GEN_FAIL;

    eccx08_debug("eccx08_cmd_ctrl(ECCX08_CMD_EXTRACT_ALL_CERTS)\n");
    // Get the CA public key
    memcpy(caPubkey, g_signer_1_ca_public_key_t, sizeof(caPubkey));

    status = get_signer_cert(path);
    if (status != ATCA_SUCCESS) {
        goto err;
    }
    status = get_public_key();
    if (status != ATCA_SUCCESS) {
        goto err;
    }
    status = get_device_cert(path);
    if (status != ATCA_SUCCESS) {
        goto err;
    }
    status = verify_signer_cert();
    if (status != ATCA_SUCCESS) {
        goto err;
    }
    status = verify_device_cert();
    if (status != ATCA_SUCCESS) {
        goto err;
    }
    status = get_root_cert(path);
    if (status != ATCA_SUCCESS) {
        goto err;
    }
err:
    return status;
}

/**
 *
 * \brief Call a function of the ateccx08 engine depending on
 * provided command.
 * This is an extension of OpenSSL: there is no openssl cli
 * command to call this function. See run_engine_cmds() function
 * from the tlsutils.c file for details.
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
    int ret = 1;
    ATCA_STATUS status = ATCA_GEN_FAIL;
    char path[256];
    char *cmd_buf = (char *)p;

    strncpy(path, p, 256);
    //ctx = ENGINE_get_ex_data(e, capi_idx);
    status = atcatls_init(&cfg_ecc508_kitcdc_default);
    if (status != ATCA_SUCCESS) {
        eccx08_debug("eccx08_cmd_ctrl(): error in atcatls_init\n");
        return ret;
    }
    if (cmd_buf) {
        cmd_buf[0] = '\0';
    }
    switch (cmd) {
        case ECCX08_CMD_GET_VERSION:
            if (cmd_buf) {
                snprintf(cmd_buf, i, "The ateccx08 ENGINE version: %s", ECCX08_ENGINE_VERSION);
            } else {
                ret = 0;
            }
            break;
        case ECCX08_CMD_GET_SIGNER_CERT:
            status = get_signer_cert(path);
            break;
        case ECCX08_CMD_GET_PUB_KEY:
            status = get_public_key();
            break;
        case ECCX08_CMD_GET_DEVICE_CERT:
            status = get_device_cert(path);
            break;
        case ECCX08_CMD_VERIFY_SIGNER_CERT:
            status = verify_signer_cert();
            break;
        case ECCX08_CMD_VERIFY_DEVICE_CERT:
            status = verify_device_cert();
            break;
        case ECCX08_CMD_GET_ROOT_CERT:
            status = get_root_cert(path);
            break;
        case ECCX08_CMD_EXTRACT_ALL_CERTS:
            status = extract_all_certs(path);
            break;
        case ECCX08_CMD_GET_PRIV_KEY:
            eccx08_debug("eccx08_cmd_ctrl(ECCX08_CMD_GET_PRIV_KEY)\n");
            break;
        case 1:
            /* openssl cli sends it for a reason: print and ignore */
            eccx08_debug("eccx08_cmd_ctrl(1)\n");
            break;
        default:
            eccx08_debug("eccx08_cmd_ctrl(): unknown command: %d\n", cmd);
            ret = 0;
    }
err:
    status = atcatls_finish();
    if (status != ATCA_SUCCESS) {
        eccx08_debug("eccx08_cmd_ctrl(): error in atcatls_finish\n");
    }
    return ret;
}


/**
 *
 * \brief Initialize the CMD method for ateccx08 engine
 *
 * \param[in] e a pointer to the ENGINE structure
 * \return 1 for success
 */
int eccx08_cmd_defn_init(ENGINE *e)
{

    eccx08_debug("eccx08_cmd_defn_init()\n");

    return 1;
}


