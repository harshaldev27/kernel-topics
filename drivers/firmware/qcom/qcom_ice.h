/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __QCOM_ICE_INT_H
#define __QCOM_ICE_INT_H

#include <linux/firmware/qcom/qcom_ice.h>

struct device;

/**
 * struct qcom_ice_ops - Qcom ICE service backend ops
 * @drv_name:                    ICE backend driver name.
 * @dev:                         ICE backend device pointer.
 * @is_ice_available:            ICE service available callback.
 * @ice_invalidate_key:          Invalidate keyslot callback.
 * @ice_set_key:                 Program keyslot callback.
 * @ice_has_wrapped_key_support: Wrapped-key support callback.
 * @ice_derive_sw_secret:        Derive software secret callback.
 * @ice_generate_key:            Generate wrapped key callback.
 * @ice_prepare_key:             Prepare wrapped key callback.
 * @ice_import_key:              Import wrapped key callback.
 */
struct qcom_ice_ops {
	const char *drv_name;
	struct device *dev;
	bool (*is_ice_available)(struct device *dev);
	int (*ice_invalidate_key)(struct device *dev, u32 index);
	int (*ice_set_key)(struct device *dev, u32 index, const u8 *key,
		       u32 key_size, enum qcom_ice_cipher cipher,
		       u32 data_unit_size);
	bool (*ice_has_wrapped_key_support)(struct device *dev);
	int (*ice_derive_sw_secret)(struct device *dev, const u8 *eph_key,
				size_t eph_key_size, u8 *sw_secret,
				size_t sw_secret_size);
	int (*ice_generate_key)(struct device *dev, u8 *lt_key,
				    size_t lt_key_size);
	int (*ice_prepare_key)(struct device *dev, const u8 *lt_key,
			   size_t lt_key_size, u8 *eph_key,
			   size_t eph_key_size);
	int (*ice_import_key)(struct device *dev, const u8 *raw_key,
			  size_t raw_key_size, u8 *lt_key,
			  size_t lt_key_size);
};

void qcom_ice_svc_ops_register(struct qcom_ice_ops *ops);
void qcom_ice_svc_ops_unregister(struct qcom_ice_ops *ops);

#endif /* __QCOM_ICE_INT_H */
