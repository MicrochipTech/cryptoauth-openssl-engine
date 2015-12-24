/** \file ecc-test-main.c
 * \brief Used to launch CryptoAuthLib tests for TLS
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

//#include "ssl.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "cryptoauthlib.h"
#include "tls/atcatls_tests.h"

// Get a pointer to the default configuration based on the compiler switch
#ifdef ATCA_HAL_KIT_CDC
ATCAIfaceCfg* pCfg = &cfg_ecc508_kitcdc_default;
#elif ATCA_HAL_KIT_HID
ATCAIfaceCfg* pCfg = &cfg_ecc508_kithid_default;
#elif ATCA_HAL_I2C
ATCAIfaceCfg* pCfg = &cfg_ateccx08a_i2c_default;
#endif


/** \brief Main function for running ATECC508 tests.
 * Use this test program to ensure that the Engine can communicate to your ATECC508 
 *
 * \return For success return 0
 */
int main()
{
	uint8_t		runTests = true;

	if (runTests)
	{
		atcatls_test_runner(pCfg);
	}
	return 0;
}
