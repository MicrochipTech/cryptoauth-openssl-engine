/**
 *
 * \copyright Copyright (c) 2015 Atmel Corporation. All rights reserved.
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
 * 3. The name of Atmel may not be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * 4. This software may only be redistributed and used in connection with an
 *    Atmel integrated circuit.
 *
 * THIS SOFTWARE IS PROVIDED BY ATMEL "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT ARE
 * EXPRESSLY AND SPECIFICALLY DISCLAIMED. IN NO EVENT SHALL ATMEL BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * \atmel_crypto_device_library_license_stop
 */

#include "test/unity.h"
#include "test/unity_fixture.h"

#ifdef __GNUC__
// Unity macros trigger this warning
#pragma GCC diagnostic ignored "-Wnested-externs"
#endif

TEST_GROUP_RUNNER(atcacert_date_enc_iso8601_sep)
{
	RUN_TEST_CASE(atcacert_date_enc_iso8601_sep, atcacert_date__atcacert_date_enc_iso8601_sep_good);
	RUN_TEST_CASE(atcacert_date_enc_iso8601_sep, atcacert_date__atcacert_date_enc_iso8601_sep_min);
	RUN_TEST_CASE(atcacert_date_enc_iso8601_sep, atcacert_date__atcacert_date_enc_iso8601_sep_max);
	RUN_TEST_CASE(atcacert_date_enc_iso8601_sep, atcacert_date__atcacert_date_enc_iso8601_sep_bad_year);
	RUN_TEST_CASE(atcacert_date_enc_iso8601_sep, atcacert_date__atcacert_date_enc_iso8601_sep_bad_month);
	RUN_TEST_CASE(atcacert_date_enc_iso8601_sep, atcacert_date__atcacert_date_enc_iso8601_sep_bad_day);
	RUN_TEST_CASE(atcacert_date_enc_iso8601_sep, atcacert_date__atcacert_date_enc_iso8601_sep_bad_hour);
	RUN_TEST_CASE(atcacert_date_enc_iso8601_sep, atcacert_date__atcacert_date_enc_iso8601_sep_bad_min);
	RUN_TEST_CASE(atcacert_date_enc_iso8601_sep, atcacert_date__atcacert_date_enc_iso8601_sep_bad_sec);
	RUN_TEST_CASE(atcacert_date_enc_iso8601_sep, atcacert_date__atcacert_date_enc_iso8601_sep_bad_params);
}

TEST_GROUP_RUNNER(atcacert_date_enc_rfc5280_utc)
{
	RUN_TEST_CASE(atcacert_date_enc_rfc5280_utc, atcacert_date__atcacert_date_enc_rfc5280_utc_good);
	RUN_TEST_CASE(atcacert_date_enc_rfc5280_utc, atcacert_date__atcacert_date_enc_rfc5280_utc_min);
	RUN_TEST_CASE(atcacert_date_enc_rfc5280_utc, atcacert_date__atcacert_date_enc_rfc5280_utc_max);
	RUN_TEST_CASE(atcacert_date_enc_rfc5280_utc, atcacert_date__atcacert_date_enc_rfc5280_utc_y2k);
	RUN_TEST_CASE(atcacert_date_enc_rfc5280_utc, atcacert_date__atcacert_date_enc_rfc5280_utc_bad_year);
	RUN_TEST_CASE(atcacert_date_enc_rfc5280_utc, atcacert_date__atcacert_date_enc_rfc5280_utc_bad_month);
	RUN_TEST_CASE(atcacert_date_enc_rfc5280_utc, atcacert_date__atcacert_date_enc_rfc5280_utc_bad_day);
	RUN_TEST_CASE(atcacert_date_enc_rfc5280_utc, atcacert_date__atcacert_date_enc_rfc5280_utc_bad_hour);
	RUN_TEST_CASE(atcacert_date_enc_rfc5280_utc, atcacert_date__atcacert_date_enc_rfc5280_utc_bad_min);
	RUN_TEST_CASE(atcacert_date_enc_rfc5280_utc, atcacert_date__atcacert_date_enc_rfc5280_utc_bad_sec);
	RUN_TEST_CASE(atcacert_date_enc_rfc5280_utc, atcacert_date__atcacert_date_enc_rfc5280_utc_bad_params);
}

TEST_GROUP_RUNNER(atcacert_date_enc_posix_uint32_be)
{
	RUN_TEST_CASE(atcacert_date_enc_posix_uint32_be, atcacert_date__atcacert_date_enc_posix_uint32_be_good);
	RUN_TEST_CASE(atcacert_date_enc_posix_uint32_be, atcacert_date__atcacert_date_enc_posix_uint32_be_min);
	RUN_TEST_CASE(atcacert_date_enc_posix_uint32_be, atcacert_date__atcacert_date_enc_posix_uint32_be_large);
	RUN_TEST_CASE(atcacert_date_enc_posix_uint32_be, atcacert_date__atcacert_date_enc_posix_uint32_be_max);
	RUN_TEST_CASE(atcacert_date_enc_posix_uint32_be, atcacert_date__atcacert_date_enc_posix_uint32_be_bad_low);
	RUN_TEST_CASE(atcacert_date_enc_posix_uint32_be, atcacert_date__atcacert_date_enc_posix_uint32_be_bad_high);
	RUN_TEST_CASE(atcacert_date_enc_posix_uint32_be, atcacert_date__atcacert_date_enc_posix_uint32_be_bad_params);
}

TEST_GROUP_RUNNER(atcacert_date_enc_posix_uint32_le)
{
	RUN_TEST_CASE(atcacert_date_enc_posix_uint32_le, atcacert_date__atcacert_date_enc_posix_uint32_le_good);
	RUN_TEST_CASE(atcacert_date_enc_posix_uint32_le, atcacert_date__atcacert_date_enc_posix_uint32_le_min);
	RUN_TEST_CASE(atcacert_date_enc_posix_uint32_le, atcacert_date__atcacert_date_enc_posix_uint32_le_large);
	RUN_TEST_CASE(atcacert_date_enc_posix_uint32_le, atcacert_date__atcacert_date_enc_posix_uint32_le_max);
	RUN_TEST_CASE(atcacert_date_enc_posix_uint32_le, atcacert_date__atcacert_date_enc_posix_uint32_le_bad_low);
	RUN_TEST_CASE(atcacert_date_enc_posix_uint32_le, atcacert_date__atcacert_date_enc_posix_uint32_le_bad_high);
	RUN_TEST_CASE(atcacert_date_enc_posix_uint32_le, atcacert_date__atcacert_date_enc_posix_uint32_le_bad_params);
}

TEST_GROUP_RUNNER(atcacert_date_enc_rfc5280_gen)
{
	RUN_TEST_CASE(atcacert_date_enc_rfc5280_gen, atcacert_date__atcacert_date_enc_rfc5280_gen_good);
	RUN_TEST_CASE(atcacert_date_enc_rfc5280_gen, atcacert_date__atcacert_date_enc_rfc5280_gen_min);
	RUN_TEST_CASE(atcacert_date_enc_rfc5280_gen, atcacert_date__atcacert_date_enc_rfc5280_gen_max);
	RUN_TEST_CASE(atcacert_date_enc_rfc5280_gen, atcacert_date__atcacert_date_enc_rfc5280_gen_bad_year);
	RUN_TEST_CASE(atcacert_date_enc_rfc5280_gen, atcacert_date__atcacert_date_enc_rfc5280_gen_bad_month);
	RUN_TEST_CASE(atcacert_date_enc_rfc5280_gen, atcacert_date__atcacert_date_enc_rfc5280_gen_bad_day);
	RUN_TEST_CASE(atcacert_date_enc_rfc5280_gen, atcacert_date__atcacert_date_enc_rfc5280_gen_bad_hour);
	RUN_TEST_CASE(atcacert_date_enc_rfc5280_gen, atcacert_date__atcacert_date_enc_rfc5280_gen_bad_min);
	RUN_TEST_CASE(atcacert_date_enc_rfc5280_gen, atcacert_date__atcacert_date_enc_rfc5280_gen_bad_sec);
	RUN_TEST_CASE(atcacert_date_enc_rfc5280_gen, atcacert_date__atcacert_date_enc_rfc5280_gen_bad_params);
}

TEST_GROUP_RUNNER(atcacert_date_enc_compcert)
{
	RUN_TEST_CASE(atcacert_date_enc_compcert, atcacert_date__atcacert_date_enc_compcert_good);
	RUN_TEST_CASE(atcacert_date_enc_compcert, atcacert_date__atcacert_date_enc_compcert_min);
	RUN_TEST_CASE(atcacert_date_enc_compcert, atcacert_date__atcacert_date_enc_compcert_max);
	RUN_TEST_CASE(atcacert_date_enc_compcert, atcacert_date__atcacert_date_enc_compcert_bad_year);
	RUN_TEST_CASE(atcacert_date_enc_compcert, atcacert_date__atcacert_date_enc_compcert_bad_month);
	RUN_TEST_CASE(atcacert_date_enc_compcert, atcacert_date__atcacert_date_enc_compcert_bad_day);
	RUN_TEST_CASE(atcacert_date_enc_compcert, atcacert_date__atcacert_date_enc_compcert_bad_hour);
	RUN_TEST_CASE(atcacert_date_enc_compcert, atcacert_date__atcacert_date_enc_compcert_bad_expire);
	RUN_TEST_CASE(atcacert_date_enc_compcert, atcacert_date__atcacert_date_enc_compcert_bad_params);
}

TEST_GROUP_RUNNER(atcacert_date_enc)
{
	RUN_TEST_CASE(atcacert_date_enc, atcacert_date__atcacert_date_enc_iso8601_sep);
	RUN_TEST_CASE(atcacert_date_enc, atcacert_date__atcacert_date_enc_rfc5280_utc);
	RUN_TEST_CASE(atcacert_date_enc, atcacert_date__atcacert_date_enc_posix_uint32_be);
	RUN_TEST_CASE(atcacert_date_enc, atcacert_date__atcacert_date_enc_posix_uint32_le);
	RUN_TEST_CASE(atcacert_date_enc, atcacert_date__atcacert_date_enc_rfc5280_gen);
	RUN_TEST_CASE(atcacert_date_enc, atcacert_date__atcacert_date_enc_small_buf);
	RUN_TEST_CASE(atcacert_date_enc, atcacert_date__atcacert_date_enc_bad_format);
	RUN_TEST_CASE(atcacert_date_enc, atcacert_date__atcacert_date_enc_bad_params);
}


TEST_GROUP_RUNNER(atcacert_date_dec_iso8601_sep)
{
	RUN_TEST_CASE(atcacert_date_dec_iso8601_sep, atcacert_date__atcacert_date_dec_iso8601_sep_good);
	RUN_TEST_CASE(atcacert_date_dec_iso8601_sep, atcacert_date__atcacert_date_dec_iso8601_sep_min);
	RUN_TEST_CASE(atcacert_date_dec_iso8601_sep, atcacert_date__atcacert_date_dec_iso8601_sep_max);
	RUN_TEST_CASE(atcacert_date_dec_iso8601_sep, atcacert_date__atcacert_date_dec_iso8601_sep_bad_int);
	RUN_TEST_CASE(atcacert_date_dec_iso8601_sep, atcacert_date__atcacert_date_dec_iso8601_sep_bad_params);
}

TEST_GROUP_RUNNER(atcacert_date_dec_rfc5280_utc)
{
	RUN_TEST_CASE(atcacert_date_dec_rfc5280_utc, atcacert_date__atcacert_date_dec_rfc5280_utc_good);
	RUN_TEST_CASE(atcacert_date_dec_rfc5280_utc, atcacert_date__atcacert_date_dec_rfc5280_utc_min);
	RUN_TEST_CASE(atcacert_date_dec_rfc5280_utc, atcacert_date__atcacert_date_dec_rfc5280_utc_max);
	RUN_TEST_CASE(atcacert_date_dec_rfc5280_utc, atcacert_date__atcacert_date_dec_rfc5280_utc_y2k);
	RUN_TEST_CASE(atcacert_date_dec_rfc5280_utc, atcacert_date__atcacert_date_dec_rfc5280_utc_bad_int);
	RUN_TEST_CASE(atcacert_date_dec_rfc5280_utc, atcacert_date__atcacert_date_dec_rfc5280_utc_bad_params);
}

TEST_GROUP_RUNNER(atcacert_date_dec_posix_uint32_be)
{
	RUN_TEST_CASE(atcacert_date_dec_posix_uint32_be, atcacert_date__atcacert_date_dec_posix_uint32_be_good);
	RUN_TEST_CASE(atcacert_date_dec_posix_uint32_be, atcacert_date__atcacert_date_dec_posix_uint32_be_min);
	RUN_TEST_CASE(atcacert_date_dec_posix_uint32_be, atcacert_date__atcacert_date_dec_posix_uint32_be_int32_max);
	RUN_TEST_CASE(atcacert_date_dec_posix_uint32_be, atcacert_date__atcacert_date_dec_posix_uint32_be_large);
	RUN_TEST_CASE(atcacert_date_dec_posix_uint32_be, atcacert_date__atcacert_date_dec_posix_uint32_be_max);
	RUN_TEST_CASE(atcacert_date_dec_posix_uint32_be, atcacert_date__atcacert_date_dec_posix_uint32_be_bad_params);
}

TEST_GROUP_RUNNER(atcacert_date_dec_posix_uint32_le)
{
	RUN_TEST_CASE(atcacert_date_dec_posix_uint32_le, atcacert_date__atcacert_date_dec_posix_uint32_le_good);
	RUN_TEST_CASE(atcacert_date_dec_posix_uint32_le, atcacert_date__atcacert_date_dec_posix_uint32_le_min);
	RUN_TEST_CASE(atcacert_date_dec_posix_uint32_le, atcacert_date__atcacert_date_dec_posix_uint32_le_int32_max);
	RUN_TEST_CASE(atcacert_date_dec_posix_uint32_le, atcacert_date__atcacert_date_dec_posix_uint32_le_large);
	RUN_TEST_CASE(atcacert_date_dec_posix_uint32_le, atcacert_date__atcacert_date_dec_posix_uint32_le_max);
	RUN_TEST_CASE(atcacert_date_dec_posix_uint32_le, atcacert_date__atcacert_date_dec_posix_uint32_le_bad_params);
}

TEST_GROUP_RUNNER(atcacert_date_dec_rfc5280_gen)
{
	RUN_TEST_CASE(atcacert_date_dec_rfc5280_gen, atcacert_date__atcacert_date_dec_rfc5280_gen_good);
	RUN_TEST_CASE(atcacert_date_dec_rfc5280_gen, atcacert_date__atcacert_date_dec_rfc5280_gen_min);
	RUN_TEST_CASE(atcacert_date_dec_rfc5280_gen, atcacert_date__atcacert_date_dec_rfc5280_gen_max);
	RUN_TEST_CASE(atcacert_date_dec_rfc5280_gen, atcacert_date__atcacert_date_dec_rfc5280_gen_bad_int);
	RUN_TEST_CASE(atcacert_date_dec_rfc5280_gen, atcacert_date__atcacert_date_dec_rfc5280_gen_bad_params);
}

TEST_GROUP_RUNNER(atcacert_date_get_max_date)
{
    RUN_TEST_CASE(atcacert_date_get_max_date, atcacert_date__atcacert_date_get_max_date_iso8601_sep);
    RUN_TEST_CASE(atcacert_date_get_max_date, atcacert_date__atcacert_date_get_max_date_rfc5280_utc);
    RUN_TEST_CASE(atcacert_date_get_max_date, atcacert_date__atcacert_date_get_max_date_posix_uint32_be);
    RUN_TEST_CASE(atcacert_date_get_max_date, atcacert_date__atcacert_date_get_max_date_posix_uint32_le);
    RUN_TEST_CASE(atcacert_date_get_max_date, atcacert_date__atcacert_date_get_max_date_rfc5280_gen);
    RUN_TEST_CASE(atcacert_date_get_max_date, atcacert_date__atcacert_date_get_max_date_new_format);
    RUN_TEST_CASE(atcacert_date_get_max_date, atcacert_date__atcacert_date_get_max_date_bad_params);
}

TEST_GROUP_RUNNER(atcacert_date_dec_compcert)
{
	RUN_TEST_CASE(atcacert_date_dec_compcert, atcacert_date__atcacert_date_dec_compcert_good);
	RUN_TEST_CASE(atcacert_date_dec_compcert, atcacert_date__atcacert_date_dec_compcert_min);
    RUN_TEST_CASE(atcacert_date_dec_compcert, atcacert_date__atcacert_date_dec_compcert_max);
    RUN_TEST_CASE(atcacert_date_dec_compcert, atcacert_date__atcacert_date_dec_compcert_posix_uint32_be);
	RUN_TEST_CASE(atcacert_date_dec_compcert, atcacert_date__atcacert_date_dec_compcert_bad_params);
}

TEST_GROUP_RUNNER(atcacert_date_dec)
{
	RUN_TEST_CASE(atcacert_date_dec, atcacert_date__atcacert_date_dec_iso8601_sep);
	RUN_TEST_CASE(atcacert_date_dec, atcacert_date__atcacert_date_dec_rfc5280_utc);
	RUN_TEST_CASE(atcacert_date_dec, atcacert_date__atcacert_date_dec_posix_uint32_be);
	RUN_TEST_CASE(atcacert_date_dec, atcacert_date__atcacert_date_dec_posix_uint32_le);
	RUN_TEST_CASE(atcacert_date_dec, atcacert_date__atcacert_date_dec_rfc5280_gen);
	RUN_TEST_CASE(atcacert_date_dec, atcacert_date__atcacert_date_dec_small_buf);
	RUN_TEST_CASE(atcacert_date_dec, atcacert_date__atcacert_date_dec_bad_format);
	RUN_TEST_CASE(atcacert_date_dec, atcacert_date__atcacert_date_dec_bad_params);
}