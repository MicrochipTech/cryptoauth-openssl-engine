
#include <stdint.h>
#include "ecc_meth.h"

extern const uint8_t g_signer_1_ca_public_key_t[];
extern const uint8_t g_cert_template_1_signer_t[];
extern const atcacert_def_t g_cert_def_1_signer_t;
extern const uint8_t g_cert_template_0_device_t[];
extern const atcacert_def_t g_cert_def_0_device_t;


// This is the user defined encryption key
extern uint8_t staticKey[ATCA_KEY_SIZE];
ATCAIfaceCfg* pCfg;

