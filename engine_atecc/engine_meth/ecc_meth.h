/**
 *  \file ecc_meth.h
 * \brief Function definitions used in OpenSSL ENGINE
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

#ifndef __ECC_METH_H__
#define __ECC_METH_H__

#include <openssl/engine.h>
#include <openssl/ossl_typ.h>
#include "atca_status.h"
#include "atcatls_cfg.h"
#include "atcatls.h"

//The engine version number. Must be updated for each engine release
#define ECCX08_ENGINE_VERSION            "01.00.00"

#define NID_id_ATECCX08 (1001)

#define TOKEN_FILE_VERSION       (0x0)
#define PRIVATE_KEY_ID           (0x1)
#define PUBLIC_KEY_ID            (0x2)
#define KEY_LIMITS_LOCKED        (0x1)
#define KEY_LIMITS_UNLOCKED      (0x2)
#define KEY_LIMITS_COUNTED       (0x3)

#define ECCX08_CMD_GET_VERSION           (ENGINE_CMD_BASE)
#define ECCX08_CMD_GET_SIGNER_CERT       (ENGINE_CMD_BASE + 1)
#define ECCX08_CMD_GET_PUB_KEY           (ENGINE_CMD_BASE + 2)
#define ECCX08_CMD_GET_DEVICE_CERT       (ENGINE_CMD_BASE + 3)
#define ECCX08_CMD_VERIFY_SIGNER_CERT    (ENGINE_CMD_BASE + 4)
#define ECCX08_CMD_VERIFY_DEVICE_CERT    (ENGINE_CMD_BASE + 5)
#define ECCX08_CMD_GET_ROOT_CERT         (ENGINE_CMD_BASE + 6)
#define ECCX08_CMD_EXTRACT_ALL_CERTS     (ENGINE_CMD_BASE + 7)
#define ECCX08_CMD_GET_PRIV_KEY          (ENGINE_CMD_BASE + 8)
#define ECCX08_CMD_MAX                   (ENGINE_CMD_BASE + 9)

#define ECCX08_SLOT8_ENC_STORE_LEN       (416)

//Max number of pseudo-random bytes - re-seed after this number
#define MAX_RAND_BYTES                   (10037)

extern ECDH_METHOD eccx08_ecdh;
extern RAND_METHOD eccx08_rand;
extern EVP_PKEY_ASN1_METHOD eccx08_pkey_asn1_meth;
extern ECDSA_METHOD eccx08_ecdsa;

extern ATCAIfaceCfg *pCfg;

int eccx08_debug(const char *fmt, ...);

//static void ERR_ECCX08_error(int function, int reason, char *file, int line);
//#define ECCX08err(f,r) ERR_ECCX08_error((f),(r),__FILE__,__LINE__)

ATCA_STATUS eccx08_get_enc_key(uint8_t *enckey, int16_t keysize);

int eccx08_pkey_meth_f(ENGINE *e, EVP_PKEY_METHOD **pkey_meth,
                       const int **nids, int nid);
int eccx08_pkey_asn1_meth_f(ENGINE *e, EVP_PKEY_ASN1_METHOD **pkey_meth,
                            const int **nids, int nid);
EVP_PKEY* eccx08_load_privkey(ENGINE *e, const char *key_id,
                              UI_METHOD *ui_method,
                              void *callback_data);
EVP_PKEY* eccx08_load_pubkey(ENGINE *e, const char *key_id,
                             UI_METHOD *ui_method,
                             void *callback_data);
int eccx08_destroy(ENGINE *e);
int eccx08_init(ENGINE *e);
int eccx08_finish(ENGINE *e);
int eccx08_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f)());

int eccx08_rand_init(void);
int eccx08_pkey_meth_init(void);
int eccx08_pkey_asn1_meth_init(void);
int eccx08_ecdh_init(uint32_t use_software);

int eccx08_cmd_defn_init(ENGINE *e);
int eccx08_cmd_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f)(void));

//eccx08_common.c
extern uint8_t test_priv_key[MEM_BLOCK_SIZE];
extern uint8_t test_pub_key[MEM_BLOCK_SIZE*2];
int eccx08_eckey_fill_key(char *ptr, int size, uint8_t slot_id,
                          uint8_t *serial_number, int serial_len);
int eccx08_eckey_encode_in_privkey(EC_KEY *eckey, uint8_t slot_id,
                                   uint8_t *serial_number, int serial_len);
int eccx08_eckey_compare_privkey(EC_KEY *eckey, uint8_t slot_id,
                                 uint8_t *serial_number, int serial_len);
int eccx08_generate_key(EC_KEY *eckey, uint8_t *serial_number, int serial_len);
int eccx08_eckey_convert(EC_KEY **p_eckey, uint8_t *raw_pubkey,
                         uint8_t *serial_number, int serial_len);

int eccx08_BN_encrypt(BIGNUM *number, uint8_t *iv, uint8_t *aes_key);
int eccx08_BN_decrypt(BIGNUM *number, uint8_t *iv, uint8_t *aes_key);

//eccx08_rsa_meth.c
const RSA_METHOD* ECCX08_RSA_meth(void);


#endif //__ECC_METH_H__

