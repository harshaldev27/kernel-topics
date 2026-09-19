/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __QCOM_TZ_ICE_H
#define __QCOM_TZ_ICE_H

#include <linux/types.h>

enum qcom_ice_cipher {
	QCOM_ICE_CIPHER_AES_128_XTS = 0,
	QCOM_ICE_CIPHER_AES_128_CBC = 1,
	QCOM_ICE_CIPHER_AES_256_XTS = 3,
	QCOM_ICE_CIPHER_AES_256_CBC = 4,
};

bool qcom_ice_svc_ops_registered(void);
bool qcom_ice_svc_available(void);
int qcom_ice_svc_invalidate_key(u32 index);
int qcom_ice_svc_set_key(u32 index, const u8 *key, u32 key_size,
			     enum qcom_ice_cipher cipher, u32 data_unit_size);
bool qcom_ice_svc_has_wrapped_key_support(void);
int qcom_ice_svc_derive_sw_secret(const u8 *eph_key, size_t eph_key_size,
				      u8 *sw_secret, size_t sw_secret_size);
int qcom_ice_svc_generate_key(u8 *lt_key, size_t lt_key_size);
int qcom_ice_svc_prepare_key(const u8 *lt_key, size_t lt_key_size,
				 u8 *eph_key, size_t eph_key_size);
int qcom_ice_svc_import_key(const u8 *raw_key, size_t raw_key_size,
				u8 *lt_key, size_t lt_key_size);

#endif /* __QCOM_TZ_ICE_H */
