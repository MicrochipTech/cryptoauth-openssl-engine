/**
 * \brief OpenSSL ENGINE Platform Hooks & Global Default Configuration
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

/* This is the user defined encryption key */
uint8_t staticKey[ATCA_KEY_SIZE] = { 0x77 };

/* Get a pointer to the default configuration */
#ifdef ATCA_HAL_KIT_CDC
ATCAIfaceCfg* pCfg = &cfg_atecc508a_kitcdc_default;
#elif ATCA_HAL_KIT_HID
ATCAIfaceCfg* pCfg = &cfg_atecc508a_kithid_default;
#elif ATCA_HAL_I2C
ATCAIfaceCfg* pCfg = &cfg_ateccx08a_i2c_default;
#endif

/* Initialize platform defaults */
int eccx08_platform_init(void)
{
    eccx08_engine_config.device_key_slot = 0;
    eccx08_engine_config.ecdh_key_slot = 2;
    eccx08_engine_config.ecdh_key_count = 1;

    return ENGINE_OPENSSL_SUCCESS;
}

char * eccx08_strip_path(char * in_str)
{
    char * tmp = in_str;
    char * rv;

    if (!in_str)
        return "";
#ifdef _WIN32
    while (tmp = strchr(tmp, '\\'))
#else
    while (tmp = strchr(tmp, '/'))
#endif
    {
        rv = ++tmp;
    }

    return rv;
}
