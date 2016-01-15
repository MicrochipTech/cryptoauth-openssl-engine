/**
 *  \file eccx08_atecc_binder.c
 * \brief The main entry point for the ateccx08 engine
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
#include <openssl/engine.h>
#include <crypto/ecdh/ech_locl.h>
#include <crypto/ecdsa/ecs_locl.h>
#include <crypto/asn1/asn1_locl.h>
#include "ecc_meth.h"

/* Constants used when creating the ENGINE */
static const char *engine_eccx08_id = "ateccx08";
static const char *engine_eccx08_name = "Atmel ECCx08 hardware engine support";

/**
 *  \brief This internal function is used by ENGINE_zencod () and possibly by the
 * "dynamic" ENGINE support too
 *
 * \param[in] e A pointer to Engine structure that completely describes the engine
 * \return For success return 1
 */
static int bind_helper(ENGINE *e)
{
    uint32_t use_software_ecdh = 0;

#ifdef USE_SW_ECDHE
    use_software_ecdh = 1;
#endif

    eccx08_debug("ECCX08 bind_helper()\n");

#ifndef OPENSSL_NO_ECDSA
    const ECDSA_METHOD *meth_ecdsa;
#endif // !OPENSSL_NO_ECDSA

#ifndef OPENSSL_NO_ECDH
    const ECDH_METHOD *meth_ecdh;
#endif // !OPENSSL_NO_ECDH

    // Register callbacks
    if (!ENGINE_set_id(e, engine_eccx08_id) ||
        !ENGINE_set_name(e, engine_eccx08_name) ||
#ifndef OPENSSL_NO_ECDH
        !ENGINE_set_ECDH(e, &eccx08_ecdh) ||
#endif // !OPENSSL_NO_ECDH
        !ENGINE_set_RAND(e, &eccx08_rand) ||
#ifndef OPENSSL_NO_ECDSA
        !ENGINE_set_ECDSA(e, &eccx08_ecdsa) ||
#endif // !OPENSSL_NO_ECDSA
        !ENGINE_set_load_privkey_function(e, &eccx08_load_privkey) ||
        !ENGINE_set_load_pubkey_function(e, &eccx08_load_pubkey) ||
        !ENGINE_set_destroy_function(e, eccx08_destroy) ||
        !ENGINE_set_init_function(e, eccx08_init) ||
        !ENGINE_set_finish_function(e, eccx08_finish) ||
        !ENGINE_set_ctrl_function(e, eccx08_ctrl) ||
        !ENGINE_set_pkey_meths(e, eccx08_pkey_meth_f) ||
        !ENGINE_set_pkey_asn1_meths(e, eccx08_pkey_asn1_meth_f) ||
#ifndef OPENSSL_NO_RSA
        !ENGINE_set_RSA(e, ECCX08_RSA_meth()) ||
#endif // !OPENSSL_NO_RSA
        (0)) {
        eccx08_debug("encountered trouble!()\n");
        return 0;
    }

    eccx08_rand_init();
    eccx08_pkey_meth_init();
    eccx08_pkey_asn1_meth_init();
    eccx08_ecdh_init(use_software_ecdh);
    eccx08_cmd_defn_init(e);

#ifndef OPENSSL_NO_ECDSA
    meth_ecdsa = ECDSA_get_default_method();
    eccx08_ecdsa.ecdsa_sign_setup = meth_ecdsa->ecdsa_sign_setup;
    eccx08_ecdsa.app_data = meth_ecdsa->app_data;
    eccx08_ecdsa.flags = meth_ecdsa->flags;
#endif  // OPENSSL_NO_ECDSA

    eccx08_debug("returned normally()\n");
    return 1;
}

#ifdef ENGINE_DYNAMIC_SUPPORT
/**
 *  \brief Binds ATECCx08 Engine to OpenSSL crypto API
 *
 * \param[in] e A pointer to Engine structure that completely describes the engine
 * \param[in] id String to identify the Engine implementation (e.g. "ateccx08")
 * \return For success return 1
 */
static int bind_fn(ENGINE *e, const char *id)
{
    eccx08_debug("bind_fn()\n");
    if (id && (strcmp(id, engine_eccx08_id) != 0)) {
        return 0;
    }
    if (!bind_helper(e)) {
        return 0;
    }

    return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN();
IMPLEMENT_DYNAMIC_BIND_FN(bind_fn);
#endif // ENGINE_DYNAMIC_SUPPORT

/**
 * \brief An engine entry point. As this is only ever called
 * once, there's no need for locking (indeed - the lock will
 * already be held by our caller!!!)
 */
static ENGINE* ENGINE_ateccx08(void)
{
    eccx08_debug("ENGINE_ateccx08()\n");
    ENGINE *eng = ENGINE_new();

    if (!eng) {
        return NULL;
    }
    if (!bind_helper(eng)) {
        ENGINE_free(eng);
        return NULL;
    }

    return eng;
}

/**
 *  \brief Load ATECCx08 Engine
 */
#ifdef ENGINE_DYNAMIC_SUPPORT
static
#endif
void ENGINE_load_ateccx08(void)
{
    eccx08_debug("ENGINE_load_ateccx08()\n");
    /* Copied from eng_[openssl|dyn].c */
    ENGINE *toadd = ENGINE_ateccx08();
    if (!toadd) return;
    ENGINE_add(toadd);
    ENGINE_free(toadd);
    ERR_clear_error();
}


///////////////////////////////////////////////////////////////////////////////////////

/**
 *  \brief Deinitialize the ateccx08 engine. Destructor (complements the "ENGINE_ateccx08()" constructor)
 *
 * \param[in] e A pointer to Engine structure that completely describes the engine
 * \return For success return 1
 */
int eccx08_destroy(ENGINE *e)
{
    eccx08_debug("eccx08_destroy()\n");
    return 1;
}

/**
 *  \brief Initialization the ateccx08 engine.
 *
 * \param[in] e A pointer to Engine structure that completely describes the engine
 * \return For success return 1
 */
int eccx08_init(ENGINE *e)
{
    eccx08_debug("eccx08_init()\n");
    return 1;
}

/**
 *
 * \brief Complete all functions before deinitialization of the ateccx08 engine
 *
 * \param[in] e A pointer to Engine structure that completely describes the engine
 * \return 1 for success
 */
int eccx08_finish(ENGINE *e)
{
    eccx08_debug("eccx08_finish()\n");
    return 1;
}

/**
 *
 * \brief Call a function of the ateccx08 engine depending on
 * provided command.
 * This is an extension of OpenSSL: there is no openssl cli
 * command to call this function. See run_engine_cmds() function
 * from the tlsutils.c file for details.
 *
 * \param[in] e A pointer to the ENGINE structure
 * \param[in] cmd A command to execute. For the full list of
 *       commands see ECCX08_CMD_* defines in the ecc_meth.h
 *       file
 * \param[in] i An integer parameter of the command
 * \param[in, out] p void * parameter of the command
 * \param[in] f A function pointer parameter of the command
 * \return ATCA_SUCCESS for success
 */
int eccx08_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f)())
{
    int rc = 0;
    eccx08_debug("eccx08_ctrl()\n");
    if ((cmd < ENGINE_CMD_BASE) || (cmd >= ECCX08_CMD_MAX)) { 
        // if cmd < ENGINE_CMD_BASE this is being called by OpenSSL.  
        // In this case no work to do so just return.
        return (1);
    }

    rc = eccx08_cmd_ctrl(e, cmd, i, p, f);
    return rc;
}

