/**
 * \brief OpenSSL Engine for ATECCx08 devices - Configuration & Functions
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

#ifndef __ECCX08_ENGINE_H__
#define __ECCX08_ENGINE_H__

#include <openssl/engine.h>
#include "cryptoauthlib.h"

/** \brief The engine version number. Must be updated for each engine release */
#define ECCX08_ENGINE_VERSION           "01.00.10"

/** \brief The engine id - short name for OpenSSL */
#define ECCX08_ENGINE_ID                "ateccx08"

/** \brief The engine name - long description of the engine for OpenSSL */
#define ECCX08_ENGINE_NAME              "Microchip ATECCx08 Engine"

/* Configuration options */

/** \brief Advertize RNG to OpenSSL*/
#ifndef ATCA_OPENSSL_ENGINE_ENABLE_RAND
#define ATCA_OPENSSL_ENGINE_ENABLE_RAND         (0)
#endif

/** \brief Use hardware RNG to seed OpenSSL RNG rather than use hardware RNG 
to generate all bytes requested by the interface - faster but could have 
security implications */
#ifndef ATCA_OPENSSL_ENGINE_RAND_SEED_ONLY
#define ATCA_OPENSSL_ENGINE_RAND_SEED_ONLY      (0)
#endif

/** \brief Advertize SHA256 capabilities to OpenSSL for digest functions */
#ifndef ATCA_OPENSSL_ENGINE_ENABLE_SHA256
#define ATCA_OPENSSL_ENGINE_ENABLE_SHA256       (0)
#endif

/** \brief Advertize certificate capabilities to OpenSSL (client certificate) */
#ifndef ATCA_OPENSSL_ENGINE_ENABLE_CERTS
#define ATCA_OPENSSL_ENGINE_ENABLE_CERTS        (1)
#endif

/** \brief Advertize ECDH capabilities to OpenSSL */
#ifndef ATCA_OPENSSL_ENGINE_REGISTER_ECDH
#define ATCA_OPENSSL_ENGINE_REGISTER_ECDH       (0)
#endif

/** \brief Advertize ECDSA capabilities to OpenSSL */
#ifndef ATCA_OPENSSL_ENGINE_REGISTER_ECDSA
#define ATCA_OPENSSL_ENGINE_REGISTER_ECDSA      (1)
#endif

/** \brief Advertize PKEY methods to OpenSSL independent of ECDSA or ECDH */
#ifndef ATCA_OPENSSL_ENGINE_REGISTER_PKEY
#define ATCA_OPENSSL_ENGINE_REGISTER_PKEY       (1)
#endif

/** \brief If advertising ECDSA capability whether or not to use hardware for verification */
#ifndef ATCA_OPENSSL_ENGINE_ENABLE_HW_VERIFY
#define ATCA_OPENSSL_ENGINE_ENABLE_HW_VERIFY    (0)
#endif

/** \brief Advertize cipher capabilities to OpenSSL so they may be used seperately */
#ifndef ATCA_OPENSSL_ENGINE_ENABLE_CIPHERS
#define ATCA_OPENSSL_ENGINE_ENABLE_CIPHERS      (0)
#endif

/** \brief Configuration is statically compiled into the library rather than
loaded from a file or an application */
#ifndef ATCA_OPENSSL_ENGINE_STATIC_CONFIG
#define ATCA_OPENSSL_ENGINE_STATIC_CONFIG       (1)
#endif

/* Global Macros/Definitions */

/* OpenSSL return types don't seem to have a define but since they are counter
    to the convention of cryptoauthlib they are defined here */
#define ENGINE_OPENSSL_SUCCESS                  (1)
#define ENGINE_OPENSSL_FAILURE                  (0)
#define ENGINE_OPENSSL_ERROR                    (-1)

/** \brief OpenSSL Engine Command Numerical Identifiers */
typedef enum {
    ECCX08_CMD_GET_VERSION = ENGINE_CMD_BASE,
    ECCX08_CMD_GET_KEY,
    ECCX08_CMD_GET_DEVICE_CERT,
    ECCX08_CMD_GET_SIGNER_CERT,
    ECCX08_CMD_LOAD_CERT_CTRL,
    ECCX08_CMD_KEY_SLOT,
    ECCX08_CMD_TRANSPORT_KEY,
    ECCX08_CMD_ECDH_SLOT,
    ECCX08_CMD_ECDH_SLOTS,
    ECCX08_CMD_DEVICE_CERT,
    ECCX08_CMD_SIGNER_CERT,
    ECCX08_CMD_MAX
} ECCX08_CMD_LIST;

/* This structure definition isn't from OpenSSL but rather OpenSC/libp11 */
typedef struct
{
    const char *s_slot_cert_id;
    X509 *cert;
} cmd_load_cert_params;

int eccx08_cmd_ctrl(ENGINE *e, int cmd, long i, void *p, void(*f)(void));

#ifdef ECC_DEBUG
char * eccx08_strip_path(char * in_str);
#define DEBUG_ENGINE(f, ...)    fprintf(stderr, "$$%s:%d:%s(): " f, eccx08_strip_path(__FILE__), __LINE__, __FUNCTION__, ##__VA_ARGS__)
#else
#define DEBUG_ENGINE(...)   asm("nop")
#endif

/* Concurency Support - Native to OpenSSL engine today but may move to 
cryptoauthlib at a later date so named accordingly */
ATCA_STATUS atcab_init_safe(ATCAIfaceCfg *cfg);
ATCA_STATUS atcab_release_safe(void);

#endif /* __ECCX08_ENGINE_H__ */

