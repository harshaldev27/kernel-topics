// SPDX-License-Identifier: GPL-2.0
/*
 * Qualcomm ICE PTA kernel test driver
 *
 * Userspace interface:
 *   echo <cmd> > /proc/qcom_ice_pta_test
 *
 * Commands:
 *   1: PTA_CMD_ICE_GENERATE_KEY
 *   2: PTA_CMD_ICE_EXPORT_KEY (prepare key blob)
 *   3: PTA_CMD_ICE_IMPORT_KEY (drive software secret)
 *   4: PTA_CMD_ICE_SET_CONFIG_KEY (program slot 0)
 *   5: PTA_CMD_ICE_INVALIDATE_KEY (slot 0)
 *   6: PTA_CMD_ICE_GET_RAW_SECRET (derive 32-byte raw secret)
 */

#include <linux/clk.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/tee_drv.h>
#include <linux/uaccess.h>
#include <linux/uuid.h>

#define DRV_NAME "qcom_ice_pta_test"
#define PROC_NODE_NAME "qcom_ice_pta_test"

#define TEE_NUM_PARAMS 4

#define ICE_HWKM_BLOB_SIZE 68U
#define ICE_RAW_SECRET_SIZE 32U
#define ICE_SW_SECRET_SIZE 32U
#define ICE_TEST_SLOT 0U

#define PTA_CMD_ICE_INVALIDATE_KEY 0
#define PTA_CMD_ICE_SET_CONFIG_KEY 1
#define PTA_CMD_ICE_GENERATE_KEY 2
#define PTA_CMD_ICE_IMPORT_KEY 3
#define PTA_CMD_ICE_EXPORT_KEY 4
#define PTA_CMD_ICE_GET_RAW_SECRET 5

#define ICE_TEST_CMD_GENERATE 1
#define ICE_TEST_CMD_PREPARE 2
#define ICE_TEST_CMD_IMPORT_SW 3
#define ICE_TEST_CMD_PROGRAM_SLOT 4
#define ICE_TEST_CMD_INVALIDATE_SLOT 5
#define ICE_TEST_CMD_GET_RAW_SECRET 6

static const uuid_t ice_pta_uuid =
	UUID_INIT(0x29e87b9e, 0x012a, 0x4878,
		  0xa1, 0xe1, 0xa1, 0xb9, 0x0a, 0x21, 0x5b, 0x16);

struct qcom_ice_pta_test {
	struct tee_context *ctx;
	u32 session_id;
	struct proc_dir_entry *proc;
	struct clk *core_clk;
	struct clk *iface_clk;
	bool clocks_enabled;

	/* L4 wrapped key from generate/import */
	struct tee_shm *blob_shm;
	/* Ephemerally wrapped L4 key from prepare/export */
	struct tee_shm *blob_tmp_shm;
	struct tee_shm *secret_shm;

	bool l4_key_valid;
	bool eph_key_valid;
};

static int optee_ctx_match(struct tee_ioctl_version_data *ver, const void *data)
{
	return ver->impl_id == TEE_IMPL_ID_OPTEE;
}

static int ice_pta_invoke(struct qcom_ice_pta_test *t,
			  u32 func,
			  struct tee_param params[TEE_NUM_PARAMS])
{
	struct tee_ioctl_invoke_arg inv_arg = {
		.func = func,
		.session = t->session_id,
		.num_params = TEE_NUM_PARAMS,
	};
	int rc = 0;

	rc = tee_client_invoke_func(t->ctx, &inv_arg, params);
	pr_info(DRV_NAME ": cmd=%u rc=%d pta_ret=0x%x origin=0x%x\n",
		func, rc, inv_arg.ret, inv_arg.ret_origin);

	if (rc < 0)
		return rc;
	if (inv_arg.ret)
		return -EIO;

	return 0;
}

static void ice_test_log_blob(const u8 *blob, size_t size, const char *tag)
{
	if (!blob)
		return;

	print_hex_dump(KERN_INFO, DRV_NAME ": blob ",
		       DUMP_PREFIX_OFFSET, 16, 1,
		       blob, size, false);
	pr_info(DRV_NAME ": dumped %s (%zu bytes)\n", tag, size);
}

static int ice_test_generate(struct qcom_ice_pta_test *t)
{
	struct tee_param p[TEE_NUM_PARAMS] = { };
	int rc = 0;

	p[0].attr = TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_OUTPUT;
	p[0].u.memref.shm = t->blob_shm;
	p[0].u.memref.shm_offs = 0;
	p[0].u.memref.size = ICE_HWKM_BLOB_SIZE;

	rc = ice_pta_invoke(t, PTA_CMD_ICE_GENERATE_KEY, p);
	if (!rc) {
		u8 *blob = tee_shm_get_va(t->blob_shm, 0);

		t->l4_key_valid = true;
		t->eph_key_valid = false;
		pr_info(DRV_NAME ": generated L4 wrapped key size=%zu\n",
			(size_t)p[0].u.memref.size);
		if (IS_ERR(blob))
			return PTR_ERR(blob);
		ice_test_log_blob(blob, p[0].u.memref.size, "generate");
	}

	return rc;
}

static int ice_test_prepare(struct qcom_ice_pta_test *t)
{
	struct tee_param p[TEE_NUM_PARAMS] = { };
	void *src = NULL;
	void *dst = NULL;
	int rc = 0;

	if (!t->l4_key_valid)
		return -EINVAL;

	src = tee_shm_get_va(t->blob_shm, 0);
	if (IS_ERR(src))
		return PTR_ERR(src);

	dst = tee_shm_get_va(t->blob_tmp_shm, 0);
	if (IS_ERR(dst))
		return PTR_ERR(dst);

	memcpy(dst, src, ICE_HWKM_BLOB_SIZE);

	p[0].attr = TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT;
	p[0].u.memref.shm = t->blob_tmp_shm;
	p[0].u.memref.shm_offs = 0;
	p[0].u.memref.size = ICE_HWKM_BLOB_SIZE;

	p[1].attr = TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_OUTPUT;
	p[1].u.memref.shm = t->blob_tmp_shm;
	p[1].u.memref.shm_offs = 0;
	p[1].u.memref.size = ICE_HWKM_BLOB_SIZE;

	rc = ice_pta_invoke(t, PTA_CMD_ICE_EXPORT_KEY, p);
	if (!rc) {
		t->eph_key_valid = true;
		pr_info(DRV_NAME ": prepared/exported ephemeral wrapped key size=%zu\n",
			(size_t)p[1].u.memref.size);
		ice_test_log_blob(dst, p[1].u.memref.size, "prepare-ephemeral");
	}

	return rc;
}

static int ice_test_import_sw_secret(struct qcom_ice_pta_test *t)
{
	struct tee_param p[TEE_NUM_PARAMS] = { };
	u8 sw_secret[ICE_SW_SECRET_SIZE];
	size_t i = 0;
	int rc = 0;

	for (i = 0; i < ARRAY_SIZE(sw_secret); i++)
		sw_secret[i] = (u8)(0xA0 + i);

	p[0].attr = TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT;
	p[0].u.memref.shm = t->secret_shm;
	p[0].u.memref.shm_offs = 0;
	p[0].u.memref.size = ARRAY_SIZE(sw_secret);

	p[1].attr = TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_OUTPUT;
	p[1].u.memref.shm = t->blob_shm;
	p[1].u.memref.shm_offs = 0;
	p[1].u.memref.size = ICE_HWKM_BLOB_SIZE;

	{
		void *secret_va = tee_shm_get_va(t->secret_shm, 0);

		if (IS_ERR(secret_va))
			return PTR_ERR(secret_va);
		memcpy(secret_va, sw_secret, ARRAY_SIZE(sw_secret));
	}

	rc = ice_pta_invoke(t, PTA_CMD_ICE_IMPORT_KEY, p);
	if (!rc) {
		u8 *blob = tee_shm_get_va(t->blob_shm, 0);

		t->l4_key_valid = true;
		t->eph_key_valid = false;
		pr_info(DRV_NAME ": imported SW secret and got L4 wrapped key size=%zu\n",
			(size_t)p[1].u.memref.size);
		if (IS_ERR(blob))
			return PTR_ERR(blob);
		ice_test_log_blob(blob, p[1].u.memref.size, "import");
	}

	memzero_explicit(sw_secret, sizeof(sw_secret));
	return rc;
}

static int ice_test_program_slot(struct qcom_ice_pta_test *t)
{
	struct tee_param p[TEE_NUM_PARAMS] = { };

	if (!t->eph_key_valid)
		return -EINVAL;

	p[0].attr = TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT;
	p[0].u.value.a = ICE_TEST_SLOT;
	p[0].u.value.b = 0;

	p[1].attr = TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT;
	p[1].u.value.a = 0;
	p[1].u.value.b = 0;

	p[2].attr = TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT;
	p[2].u.memref.shm = t->blob_tmp_shm;
	p[2].u.memref.shm_offs = 0;
	p[2].u.memref.size = ICE_HWKM_BLOB_SIZE;

	return ice_pta_invoke(t, PTA_CMD_ICE_SET_CONFIG_KEY, p);
}

static int ice_test_invalidate_slot(struct qcom_ice_pta_test *t)
{
	struct tee_param p[TEE_NUM_PARAMS] = { };

	p[0].attr = TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT;
	p[0].u.value.a = ICE_TEST_SLOT;
	p[0].u.value.b = 0;

	return ice_pta_invoke(t, PTA_CMD_ICE_INVALIDATE_KEY, p);
}

static int ice_test_get_raw_secret(struct qcom_ice_pta_test *t)
{
	struct tee_param p[TEE_NUM_PARAMS] = { };
	u8 *raw_secret = NULL;
	int rc = 0;

	if (!t->eph_key_valid)
		return -EINVAL;

	p[0].attr = TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT;
	p[0].u.memref.shm = t->blob_tmp_shm;
	p[0].u.memref.shm_offs = 0;
	p[0].u.memref.size = ICE_HWKM_BLOB_SIZE;

	p[1].attr = TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_OUTPUT;
	p[1].u.memref.shm = t->secret_shm;
	p[1].u.memref.shm_offs = 0;
	p[1].u.memref.size = ICE_RAW_SECRET_SIZE;

	rc = ice_pta_invoke(t, PTA_CMD_ICE_GET_RAW_SECRET, p);
	if (!rc) {
		raw_secret = tee_shm_get_va(t->secret_shm, 0);
		pr_info(DRV_NAME ": derived raw secret size=%zu\n",
			(size_t)p[1].u.memref.size);
		if (IS_ERR(raw_secret))
			return PTR_ERR(raw_secret);
		ice_test_log_blob(raw_secret, p[1].u.memref.size, "raw-secret");
	}

	return rc;
}

static int ice_test_run_cmd(struct qcom_ice_pta_test *t, int cmd)
{
	switch (cmd) {
	case ICE_TEST_CMD_GENERATE:
		return ice_test_generate(t);
	case ICE_TEST_CMD_PREPARE:
		return ice_test_prepare(t);
	case ICE_TEST_CMD_IMPORT_SW:
		return ice_test_import_sw_secret(t);
	case ICE_TEST_CMD_PROGRAM_SLOT:
		return ice_test_program_slot(t);
	case ICE_TEST_CMD_INVALIDATE_SLOT:
		return ice_test_invalidate_slot(t);
	case ICE_TEST_CMD_GET_RAW_SECRET:
		return ice_test_get_raw_secret(t);
	default:
		return -EINVAL;
	}
}

static ssize_t ice_test_proc_write(struct file *file, const char __user *buf,
				   size_t count, loff_t *ppos)
{
	struct qcom_ice_pta_test *t = pde_data(file_inode(file));
	char kbuf[32];
	int cmd = 0;
	int rc = 0;
	size_t n = min(count, sizeof(kbuf) - 1);

	if (!t)
		return -ENODEV;

	if (copy_from_user(kbuf, buf, n))
		return -EFAULT;
	kbuf[n] = '\0';
	strim(kbuf);

	rc = kstrtoint(kbuf, 0, &cmd);
	if (rc)
		return rc;

	rc = ice_test_run_cmd(t, cmd);
	if (rc) {
		pr_err(DRV_NAME ": command %d failed: %d\n", cmd, rc);
		return rc;
	}

	pr_info(DRV_NAME ": command %d done\n", cmd);
	return count;
}

static const struct proc_ops ice_test_proc_ops = {
	.proc_write = ice_test_proc_write,
};

static int qcom_ice_pta_test_get_clks(struct platform_device *pdev,
				      struct qcom_ice_pta_test *t)
{
	t->core_clk = devm_clk_get_optional(&pdev->dev, "ice_core_clk");
	if (IS_ERR(t->core_clk))
		return PTR_ERR(t->core_clk);
	if (!t->core_clk)
		t->core_clk = devm_clk_get_optional(&pdev->dev, "ice");
	if (IS_ERR(t->core_clk))
		return PTR_ERR(t->core_clk);
	if (!t->core_clk)
		t->core_clk = devm_clk_get_optional(&pdev->dev, "core");
	if (IS_ERR(t->core_clk))
		return PTR_ERR(t->core_clk);
	if (!t->core_clk)
		t->core_clk = devm_clk_get_optional(&pdev->dev, NULL);
	if (IS_ERR(t->core_clk))
		return PTR_ERR(t->core_clk);

	t->iface_clk = devm_clk_get_optional(&pdev->dev, "iface");
	if (IS_ERR(t->iface_clk))
		return PTR_ERR(t->iface_clk);

	return 0;
}

static int qcom_ice_pta_test_enable_clks(struct qcom_ice_pta_test *t)
{
	int rc = 0;

	if (t->core_clk) {
		rc = clk_prepare_enable(t->core_clk);
		if (rc)
			return rc;
	}

	if (t->iface_clk) {
		rc = clk_prepare_enable(t->iface_clk);
		if (rc) {
			if (t->core_clk)
				clk_disable_unprepare(t->core_clk);
			return rc;
		}
	}

	t->clocks_enabled = true;
	return 0;
}

static void qcom_ice_pta_test_disable_clks(struct qcom_ice_pta_test *t)
{
	if (!t->clocks_enabled)
		return;

	if (t->iface_clk)
		clk_disable_unprepare(t->iface_clk);
	if (t->core_clk)
		clk_disable_unprepare(t->core_clk);
	t->clocks_enabled = false;
}

static int qcom_ice_pta_test_init_shm(struct qcom_ice_pta_test *t)
{
	t->blob_shm = tee_shm_alloc_kernel_buf(t->ctx, ICE_HWKM_BLOB_SIZE);
	if (IS_ERR(t->blob_shm))
		return PTR_ERR(t->blob_shm);

	t->blob_tmp_shm = tee_shm_alloc_kernel_buf(t->ctx, ICE_HWKM_BLOB_SIZE);
	if (IS_ERR(t->blob_tmp_shm))
		return PTR_ERR(t->blob_tmp_shm);

	t->secret_shm = tee_shm_alloc_kernel_buf(t->ctx, ICE_SW_SECRET_SIZE);
	if (IS_ERR(t->secret_shm))
		return PTR_ERR(t->secret_shm);

	return 0;
}

static void qcom_ice_pta_test_free_shm(struct qcom_ice_pta_test *t)
{
	if (t->secret_shm && !IS_ERR(t->secret_shm))
		tee_shm_free(t->secret_shm);
	if (t->blob_tmp_shm && !IS_ERR(t->blob_tmp_shm))
		tee_shm_free(t->blob_tmp_shm);
	if (t->blob_shm && !IS_ERR(t->blob_shm))
		tee_shm_free(t->blob_shm);
}

static int qcom_ice_pta_test_probe(struct platform_device *pdev)
{
	struct tee_ioctl_open_session_arg sess_arg = {
		.clnt_login = TEE_IOCTL_LOGIN_REE_KERNEL,
	};
	struct qcom_ice_pta_test *t = NULL;
	int rc = 0;

	dev_info(&pdev->dev, "probe start\n");

	t = devm_kzalloc(&pdev->dev, sizeof(*t), GFP_KERNEL);
	if (!t)
		return -ENOMEM;

	rc = qcom_ice_pta_test_get_clks(pdev, t);
	if (rc) {
		dev_err(&pdev->dev, "failed to get clocks rc=%d\n", rc);
		return rc;
	}

	dev_info(&pdev->dev, "opening OP-TEE context\n");
	t->ctx = tee_client_open_context(NULL, optee_ctx_match, NULL, NULL);
	if (IS_ERR(t->ctx)) {
		rc = PTR_ERR(t->ctx);
		t->ctx = NULL;
		if (rc == -ENOENT) {
			dev_info(&pdev->dev,
				 "OP-TEE context not ready yet, deferring probe\n");
			return -EPROBE_DEFER;
		}
		dev_err(&pdev->dev, "tee_client_open_context failed rc=%d\n", rc);
		return rc;
	}
	dev_info(&pdev->dev, "OP-TEE context opened\n");

	export_uuid(sess_arg.uuid, &ice_pta_uuid);
	dev_info(&pdev->dev, "opening PTA session\n");
	rc = tee_client_open_session(t->ctx, &sess_arg, NULL);
	if (rc < 0 || sess_arg.ret) {
		dev_err(&pdev->dev,
			"open_session rc=%d ret=0x%x origin=0x%x\n",
			rc, sess_arg.ret, sess_arg.ret_origin);
		if (rc == -ENOENT || rc == -ENODEV) {
			dev_info(&pdev->dev,
				 "OP-TEE/PTA not ready yet, deferring probe\n");
			rc = -EPROBE_DEFER;
		} else {
			rc = rc ? rc : -EIO;
		}
		goto err_ctx;
	}

	t->session_id = sess_arg.session;
	dev_info(&pdev->dev, "PTA session opened id=%u\n", t->session_id);

	rc = qcom_ice_pta_test_enable_clks(t);
	if (rc) {
		dev_err(&pdev->dev, "failed to enable clocks rc=%d\n", rc);
		goto err_sess;
	}
	dev_info(&pdev->dev, "ICE clocks enabled\n");

	dev_info(&pdev->dev, "allocating SHM\n");
	rc = qcom_ice_pta_test_init_shm(t);
	if (rc) {
		dev_err(&pdev->dev, "SHM init failed rc=%d\n", rc);
		goto err_sess;
	}

	dev_info(&pdev->dev, "creating /proc/%s\n", PROC_NODE_NAME);
	t->proc = proc_create_data(PROC_NODE_NAME, 0200, NULL,
				   &ice_test_proc_ops, t);
	if (!t->proc) {
		rc = -ENOMEM;
		dev_err(&pdev->dev, "proc_create_data failed rc=%d\n", rc);
		goto err_shm;
	}

	platform_set_drvdata(pdev, t);
	dev_info(&pdev->dev, "probed. Use: echo <1..6> > /proc/%s\n",
		 PROC_NODE_NAME);
	return 0;

err_shm:
	qcom_ice_pta_test_free_shm(t);
err_sess:
	qcom_ice_pta_test_disable_clks(t);
	tee_client_close_session(t->ctx, t->session_id);
err_ctx:
	tee_client_close_context(t->ctx);
	return rc;
}

static void qcom_ice_pta_test_remove(struct platform_device *pdev)
{
	struct qcom_ice_pta_test *t = platform_get_drvdata(pdev);

	if (!t)
		return;

	if (t->proc)
		proc_remove(t->proc);

	qcom_ice_pta_test_free_shm(t);
	qcom_ice_pta_test_disable_clks(t);

	if (t->ctx) {
		if (t->session_id)
			tee_client_close_session(t->ctx, t->session_id);
		tee_client_close_context(t->ctx);
	}

	return;
}

static const struct of_device_id qcom_ice_pta_test_of_match[] = {
	{ .compatible = "qcom,ice-pta-test" },
	{ }
};
MODULE_DEVICE_TABLE(of, qcom_ice_pta_test_of_match);

static struct platform_driver qcom_ice_pta_test_driver = {
	.probe = qcom_ice_pta_test_probe,
	.remove = qcom_ice_pta_test_remove,
	.driver = {
		.name = DRV_NAME,
		.of_match_table = qcom_ice_pta_test_of_match,
	},
};

builtin_platform_driver(qcom_ice_pta_test_driver);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Qualcomm ICE PTA kernel test driver");
MODULE_AUTHOR("QGenie");
