// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <linux/firmware/qcom/qcom_ice.h>
#include <linux/kernel.h>
#include <linux/module.h>

#include "qcom_ice.h"

static struct qcom_ice_ops *ops_ptr;

bool qcom_ice_svc_ops_registered(void)
{
	/*
	 * The barrier for ops_ptr is intended to synchronize the data stores
	 * for the ops data structure when client drivers are in parallel
	 * checking for ICE service availability.
	 */
	return !!smp_load_acquire(&ops_ptr);
}
EXPORT_SYMBOL_GPL(qcom_ice_svc_ops_registered);

bool qcom_ice_svc_available(void)
{
	if (!ops_ptr)
		return false;

	return ops_ptr->is_ice_available(ops_ptr->dev);
}
EXPORT_SYMBOL_GPL(qcom_ice_svc_available);

int qcom_ice_svc_invalidate_key(u32 index)
{
	if (!ops_ptr)
		return -ENODEV;

	return ops_ptr->ice_invalidate_key(ops_ptr->dev, index);
}
EXPORT_SYMBOL_GPL(qcom_ice_svc_invalidate_key);

int qcom_ice_svc_set_key(u32 index, const u8 *key, u32 key_size,
			     enum qcom_ice_cipher cipher, u32 data_unit_size)
{
	if (!ops_ptr)
		return -ENODEV;

	return ops_ptr->ice_set_key(ops_ptr->dev, index, key, key_size,
					cipher, data_unit_size);
}
EXPORT_SYMBOL_GPL(qcom_ice_svc_set_key);

bool qcom_ice_svc_has_wrapped_key_support(void)
{
	if (!ops_ptr)
		return false;

	return ops_ptr->ice_has_wrapped_key_support(ops_ptr->dev);
}
EXPORT_SYMBOL_GPL(qcom_ice_svc_has_wrapped_key_support);

int qcom_ice_svc_derive_sw_secret(const u8 *eph_key, size_t eph_key_size,
			      u8 *sw_secret, size_t sw_secret_size)
{
	if (!ops_ptr)
		return -ENODEV;

	return ops_ptr->ice_derive_sw_secret(ops_ptr->dev, eph_key, eph_key_size,
					 sw_secret, sw_secret_size);
}
EXPORT_SYMBOL_GPL(qcom_ice_svc_derive_sw_secret);

int qcom_ice_svc_generate_key(u8 *lt_key, size_t lt_key_size)
{
	if (!ops_ptr)
		return -ENODEV;

	return ops_ptr->ice_generate_key(ops_ptr->dev, lt_key, lt_key_size);
}
EXPORT_SYMBOL_GPL(qcom_ice_svc_generate_key);

int qcom_ice_svc_prepare_key(const u8 *lt_key, size_t lt_key_size,
			 u8 *eph_key, size_t eph_key_size)
{
	if (!ops_ptr)
		return -ENODEV;

	return ops_ptr->ice_prepare_key(ops_ptr->dev, lt_key, lt_key_size,
				    eph_key, eph_key_size);
}
EXPORT_SYMBOL_GPL(qcom_ice_svc_prepare_key);

int qcom_ice_svc_import_key(const u8 *raw_key, size_t raw_key_size,
			u8 *lt_key, size_t lt_key_size)
{
	if (!ops_ptr)
		return -ENODEV;

	return ops_ptr->ice_import_key(ops_ptr->dev, raw_key, raw_key_size,
				   lt_key, lt_key_size);
}
EXPORT_SYMBOL_GPL(qcom_ice_svc_import_key);

void qcom_ice_svc_ops_register(struct qcom_ice_ops *ops)
{
	if (!qcom_ice_svc_ops_registered())
		/* Paired with smp_load_acquire() in qcom_ice_svc_ops_registered() */
		smp_store_release(&ops_ptr, ops);
	else
		pr_err("qcom_ice: ops already registered (%s), rejecting %s\n",
		       ops_ptr->drv_name, ops->drv_name);
}
EXPORT_SYMBOL_GPL(qcom_ice_svc_ops_register);

void qcom_ice_svc_ops_unregister(struct qcom_ice_ops *ops)
{
	/* Paired with smp_load_acquire() in qcom_ice_svc_ops_registered() */
	if (READ_ONCE(ops_ptr) == ops)
		smp_store_release(&ops_ptr, NULL);
}
EXPORT_SYMBOL_GPL(qcom_ice_svc_ops_unregister);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Qualcomm ICE service");
