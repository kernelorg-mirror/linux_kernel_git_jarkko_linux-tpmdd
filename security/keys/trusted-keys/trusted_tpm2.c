// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2004 IBM Corporation
 * Copyright (C) 2014 Intel Corporation
 */

#include <linux/asn1_encoder.h>
#include <linux/oid_registry.h>
#include <linux/string.h>
#include <linux/err.h>
#include <linux/tpm.h>

#include <keys/trusted-type.h>
#include <keys/trusted_tpm.h>

#include <linux/unaligned.h>

#include "tpm2key.asn1.h"

static u32 tpm2key_oid[] = { 2, 23, 133, 10, 1, 5 };

static int tpm2_key_encode(struct trusted_key_payload *payload,
			   struct trusted_key_options *options,
			   u8 *src, u32 len)
{
	struct trusted_key_tpm *private = options->private;
	const int SCRATCH_SIZE = PAGE_SIZE;
	u8 *scratch __free(kfree) = NULL;
	u8 *work, *work1;
	u8 *end_work;
	u8 *priv, *pub;
	u32 priv_len, pub_len;
	int ret;

	if (len < 4)
		return -EINVAL;

	priv_len = get_unaligned_be16(src) + 2;
	if (priv_len + 2 > len)
		return -EIO;

	priv = src;
	src += priv_len;

	pub_len = get_unaligned_be16(src) + 2;
	if (pub_len + priv_len > len)
		return -EIO;

	pub = src;

	scratch = kmalloc(SCRATCH_SIZE, GFP_KERNEL);
	if (!scratch)
		return -ENOMEM;

	work = scratch;
	end_work = scratch + SCRATCH_SIZE;

	work = asn1_encode_oid(work, end_work, tpm2key_oid,
			       asn1_oid_len(tpm2key_oid));

	if (private->blobauth_len == 0) {
		unsigned char bool[3], *w = bool;
		/* tag 0 is emptyAuth */
		w = asn1_encode_boolean(w, w + sizeof(bool), true);
		if (WARN(IS_ERR(w), "BUG: Boolean failed to encode"))
			return PTR_ERR(w);

		work = asn1_encode_tag(work, end_work, 0, bool, w - bool);
	}

	/*
	 * Assume both octet strings will encode to a 2 byte definite length
	 *
	 * Note: For a well behaved TPM, this warning should never
	 * trigger, so if it does there's something nefarious going on
	 */
	if (WARN(work - scratch + pub_len + priv_len + 14 > SCRATCH_SIZE,
		 "BUG: scratch buffer is too small")) {
		return -EINVAL;
	}

	work = asn1_encode_integer(work, end_work, private->keyhandle);
	work = asn1_encode_octet_string(work, end_work, pub, pub_len);
	work = asn1_encode_octet_string(work, end_work, priv, priv_len);

	work1 = payload->blob;
	work1 = asn1_encode_sequence(work1, work1 + sizeof(payload->blob),
				     scratch, work - scratch);
	if (IS_ERR(work1)) {
		ret = PTR_ERR(work1);
		pr_err("BUG: ASN.1 encoder failed with %d\n", ret);
		return ret;
	}

	return work1 - payload->blob;
}

struct tpm2_key_context {
	u32 parent;
	const u8 *pub;
	u32 pub_len;
	const u8 *priv;
	u32 priv_len;
	bool has_policy;
};

static int tpm2_key_decode(struct trusted_key_payload *payload,
			   struct trusted_key_options *options,
			   u8 **buf, unsigned int *blob_len)
{
	struct trusted_key_tpm *private = options->private;
	int ret;
	struct tpm2_key_context ctx;
	u8 *blob;

	memset(&ctx, 0, sizeof(ctx));

	ret = asn1_ber_decoder(&tpm2key_decoder, &ctx, payload->blob,
			       payload->blob_len);
	if (ret < 0)
		return ret;

	if (ctx.has_policy && !private->policyhandle)
		return -EOPNOTSUPP;

	if (ctx.priv_len + ctx.pub_len > MAX_BLOB_SIZE)
		return -EINVAL;

	blob = kmalloc(ctx.priv_len + ctx.pub_len, GFP_KERNEL);
	if (!blob)
		return -ENOMEM;

	*buf = blob;
	*blob_len = ctx.priv_len + ctx.pub_len;
	if (!private->keyhandle)
		private->keyhandle = ctx.parent;

	memcpy(blob, ctx.priv, ctx.priv_len);
	blob += ctx.priv_len;

	memcpy(blob, ctx.pub, ctx.pub_len);

	return 0;
}

int tpm2_key_policy(void *context, size_t hdrlen,
		    unsigned char tag,
		    const void *value, size_t vlen)
{
	struct tpm2_key_context *ctx = context;

	ctx->has_policy = true;
	return 0;
}

int tpm2_key_secret(void *context, size_t hdrlen,
		    unsigned char tag,
		    const void *value, size_t vlen)
{
	return -EOPNOTSUPP;
}

int tpm2_key_auth_policy(void *context, size_t hdrlen,
			 unsigned char tag,
			 const void *value, size_t vlen)
{
	return -EOPNOTSUPP;
}

int tpm2_key_rsa_parent(void *context, size_t hdrlen,
			unsigned char tag,
			const void *value, size_t vlen)
{
	const u8 *v = value;

	if (vlen != 1)
		return -EBADMSG;
	if (*v)
		return -EOPNOTSUPP;

	return 0;
}

int tpm2_key_parent(void *context, size_t hdrlen,
		  unsigned char tag,
		  const void *value, size_t vlen)
{
	struct tpm2_key_context *ctx = context;
	const u8 *v = value;
	size_t i;

	if (vlen > 1 && v[0] == 0) {
		v++;
		vlen--;
	}
	if (!vlen || vlen > sizeof(u32))
		return -EBADMSG;

	ctx->parent = 0;
	for (i = 0; i < vlen; i++) {
		ctx->parent <<= 8;
		ctx->parent |= v[i];
	}

	return 0;
}

int tpm2_key_type(void *context, size_t hdrlen,
		unsigned char tag,
		const void *value, size_t vlen)
{
	enum OID oid = look_up_OID(value, vlen);

	if (oid != OID_TPMSealedData) {
		char buffer[50];

		sprint_oid(value, vlen, buffer, sizeof(buffer));
		pr_debug("OID is \"%s\" which is not TPMSealedData\n",
			 buffer);
		return -EINVAL;
	}

	return 0;
}
int tpm2_key_pub(void *context, size_t hdrlen,
	       unsigned char tag,
	       const void *value, size_t vlen)
{
	struct tpm2_key_context *ctx = context;

	ctx->pub = value;
	ctx->pub_len = vlen;

	return 0;
}

int tpm2_key_priv(void *context, size_t hdrlen,
		unsigned char tag,
		const void *value, size_t vlen)
{
	struct tpm2_key_context *ctx = context;

	ctx->priv = value;
	ctx->priv_len = vlen;

	return 0;
}

/**
 * tpm2_load_parent() - resolve a parent handle for TPM 2.0 child operations
 *
 * @chip: TPM chip to use
 * @parent: persistent/volatile object handle or hierarchy handle
 * @handle: returned usable parent handle
 * @name: buffer populated with the parent handle name
 * @name_size: returned byte length of @name
 * @created: set to true if a temporary primary key was created and must be flushed
 *
 * Return: 0 on success, negative errno on failure.
 */
static int tpm2_load_parent(struct tpm_chip *chip, u32 parent, u32 *handle,
			    u8 name[TPM2_MAX_NAME_SIZE], u16 *name_size,
			    bool *created)
{
	int rc;

	*created = false;
	if (tpm2_handle_mso(parent) != TPM2_MSO_PERMANENT) {
		*handle = parent;
		rc = tpm2_read_public(chip, parent, name);
		if (rc < 0)
			return rc;
		*name_size = rc;
		return 0;
	}

	if (parent != TPM2_RH_OWNER &&
	    parent != TPM2_RH_NULL &&
	    parent != TPM2_RH_PLATFORM)
		return -EINVAL;

	rc = tpm2_create_primary(chip, parent, handle, name);
	if (rc)
		return tpm_ret_to_err(rc);

	*name_size = TPM2_NULL_NAME_SIZE;
	*created = true;
	return 0;
}

/**
 * tpm2_seal_trusted() - seal the payload of a trusted key
 *
 * @chip: TPM chip to use
 * @payload: the key data in clear and encrypted form
 * @options: authentication values and other options
 *
 * Return: < 0 on error and 0 on success.
 */
int tpm2_seal_trusted(struct tpm_chip *chip,
		      struct trusted_key_payload *payload,
		      struct trusted_key_options *options)
{
	struct trusted_key_tpm *private = options->private;
	u8 parent_name[TPM2_MAX_NAME_SIZE];
	off_t offset = TPM_HEADER_SIZE;
	struct tpm_buf *buf __free(kfree) = NULL;
	struct tpm_buf *sized __free(kfree) = NULL;
	bool created_parent = false;
	u16 parent_name_size;
	u32 parent_handle;
	int blob_len = 0;
	u32 size;
	int hash;
	u32 flags;
	int rc;

	hash = tpm2_find_hash_alg(private->hash);
	if (hash < 0)
		return hash;

	if (!private->keyhandle)
		return -EINVAL;

	rc = tpm_try_get_ops(chip);
	if (rc)
		return rc;

	rc = tpm2_load_parent(chip, private->keyhandle, &parent_handle,
			      parent_name, &parent_name_size, &created_parent);
	if (rc)
		goto out_put;

	rc = tpm2_start_auth_session(chip);
	if (rc)
		goto out_parent;

	buf = kzalloc(TPM_BUFSIZE, GFP_KERNEL);
	if (!buf) {
		rc = -ENOMEM;
		tpm2_end_auth_session(chip);
		goto out_parent;
	}

	tpm_buf_init(buf, TPM_BUFSIZE);
	tpm_buf_reset(buf, TPM2_ST_SESSIONS, TPM2_CC_CREATE);

	sized = kzalloc(TPM_BUFSIZE, GFP_KERNEL);
	if (!sized) {
		rc = -ENOMEM;
		tpm2_end_auth_session(chip);
		goto out_parent;
	}

	tpm_buf_init_sized(sized, TPM_BUFSIZE);

	rc = tpm_buf_append_name(chip, buf, parent_handle, parent_name,
				 parent_name_size);
	if (rc)
		goto out;

	tpm_buf_append_hmac_session(chip, buf, TPM2_SA_DECRYPT,
				    private->keyauth, TPM_DIGEST_SIZE);
	/* sensitive */
	tpm_buf_append_u16(sized, private->blobauth_len);

	if (private->blobauth_len)
		tpm_buf_append(sized, private->blobauth, private->blobauth_len);

	tpm_buf_append_u16(sized, payload->key_len);
	tpm_buf_append(sized, payload->key, payload->key_len);
	tpm_buf_append(buf, sized->data, sized->length);

	/* public */
	tpm_buf_reset_sized(sized);
	tpm_buf_append_u16(sized, TPM_ALG_KEYEDHASH);
	tpm_buf_append_u16(sized, hash);

	/* key properties */
	flags = 0;
	flags |= private->policydigest_len ? 0 : TPM2_OA_USER_WITH_AUTH;
	flags |= payload->migratable ? 0 : (TPM2_OA_FIXED_TPM | TPM2_OA_FIXED_PARENT);
	tpm_buf_append_u32(sized, flags);

	/* policy */
	tpm_buf_append_u16(sized, private->policydigest_len);
	if (private->policydigest_len)
		tpm_buf_append(sized, private->policydigest,
			       private->policydigest_len);

	/* public parameters */
	tpm_buf_append_u16(sized, TPM_ALG_NULL);
	tpm_buf_append_u16(sized, 0);

	tpm_buf_append(buf, sized->data, sized->length);

	/* outside info */
	tpm_buf_append_u16(buf, 0);

	/* creation PCR */
	tpm_buf_append_u32(buf, 0);

	if (buf->flags & TPM_BUF_INVALID) {
		rc = -E2BIG;
		tpm2_end_auth_session(chip);
		goto out;
	}

	rc = tpm_buf_fill_hmac_session(chip, buf);
	if (rc)
		goto out;

	rc = tpm_transmit_cmd(chip, buf, 4, "sealing data");
	rc = tpm_buf_check_hmac_response(chip, buf, rc);
	if (rc)
		goto out;

	if (!tpm_buf_read_u32(buf, &offset, &size)) {
		rc = -EIO;
		goto out;
	}

	if (buf->length - offset < size) {
		rc = -EFAULT;
		goto out;
	}

	blob_len = tpm2_key_encode(payload, options, &buf->data[offset], size);
	if (blob_len < 0)
		rc = blob_len;

out:
	if (!rc)
		payload->blob_len = blob_len;

out_parent:
	if (created_parent)
		tpm2_flush_context(chip, parent_handle);
out_put:
	tpm_put_ops(chip);
	return tpm_ret_to_err(rc);
}

/**
 * tpm2_load_cmd() - execute a TPM2_Load command
 *
 * @chip: TPM chip to use
 * @payload: the key data in clear and encrypted form
 * @options: authentication values and other options
 * @blob_handle: returned blob handle
 *
 * Return: 0 on success.
 *        -E2BIG on wrong payload size.
 *        -EPERM on tpm error status.
 *        < 0 error from tpm_send.
 */
static int tpm2_load_cmd(struct tpm_chip *chip,
			 struct trusted_key_payload *payload,
			 struct trusted_key_options *options,
			 u32 *blob_handle)
{
	u8 *blob_ref __free(kfree) = NULL;
	struct trusted_key_tpm *private = options->private;
	u8 parent_name[TPM2_MAX_NAME_SIZE];
	struct tpm_buf *buf __free(kfree) = NULL;
	bool created_parent = false;
	u16 parent_name_size;
	unsigned int private_len;
	unsigned int public_len;
	unsigned int blob_len;
	u32 parent_handle;
	u8 *blob, *pub;
	int rc;
	u32 attrs;

	rc = tpm2_key_decode(payload, options, &blob, &blob_len);
	if (rc) {
		if (rc != -EBADMSG ||
		    (payload->blob_len &&
		     payload->blob[0] == (ASN1_CONS_BIT | ASN1_SEQ)))
			return rc;

		/* old form */
		blob = payload->blob;
		blob_len = payload->blob_len;
		payload->old_format = 1;
	} else {
		/* Bind for cleanup: */
		blob_ref = blob;
	}

	/* new format carries keyhandle but old format doesn't */
	if (!private->keyhandle)
		return -EINVAL;

	/* must be big enough for at least the two be16 size counts */
	if (blob_len < 4)
		return -EINVAL;

	private_len = get_unaligned_be16(blob);

	/* must be big enough for following public_len */
	if (private_len + 2 + 2 > blob_len)
		return -E2BIG;

	public_len = get_unaligned_be16(blob + 2 + private_len);
	if (private_len + 2 + public_len + 2 > blob_len)
		return -E2BIG;

	if (public_len < 8)
		return -EINVAL;

	pub = blob + 2 + private_len + 2;
	/* key attributes are always at offset 4 */
	attrs = get_unaligned_be32(pub + 4);

	if ((attrs & (TPM2_OA_FIXED_TPM | TPM2_OA_FIXED_PARENT)) ==
	    (TPM2_OA_FIXED_TPM | TPM2_OA_FIXED_PARENT))
		payload->migratable = 0;
	else
		payload->migratable = 1;

	blob_len = private_len + public_len + 4;
	if (blob_len > payload->blob_len)
		return -E2BIG;

	rc = tpm2_load_parent(chip, private->keyhandle, &parent_handle,
			      parent_name, &parent_name_size, &created_parent);
	if (rc)
		return rc;

	rc = tpm2_start_auth_session(chip);
	if (rc)
		goto out;

	buf = kzalloc(TPM_BUFSIZE, GFP_KERNEL);
	if (!buf) {
		tpm2_end_auth_session(chip);
		rc = -ENOMEM;
		goto out;
	}

	tpm_buf_init(buf, TPM_BUFSIZE);
	tpm_buf_reset(buf, TPM2_ST_SESSIONS, TPM2_CC_LOAD);

	rc = tpm_buf_append_name(chip, buf, parent_handle, parent_name,
				 parent_name_size);
	if (rc)
		goto out;

	tpm_buf_append_hmac_session(chip, buf, 0, private->keyauth,
				    TPM_DIGEST_SIZE);

	tpm_buf_append(buf, blob, blob_len);

	if (buf->flags & TPM_BUF_INVALID) {
		tpm2_end_auth_session(chip);
		rc = -E2BIG;
		goto out;
	}

	rc = tpm_buf_fill_hmac_session(chip, buf);
	if (rc)
		goto out;

	rc = tpm_transmit_cmd(chip, buf, 4, "loading blob");
	rc = tpm_buf_check_hmac_response(chip, buf, rc);
	if (!rc)
		*blob_handle = be32_to_cpup(
			(__be32 *)&buf->data[TPM_HEADER_SIZE]);

out:
	if (created_parent)
		tpm2_flush_context(chip, parent_handle);

	return tpm_ret_to_err(rc);
}

/**
 * tpm2_unseal_cmd() - execute a TPM2_Unseal command
 *
 * @chip: TPM chip to use
 * @payload: the key data in clear and encrypted form
 * @options: authentication values and other options
 * @blob_handle: blob handle
 *
 * Return: 0 on success
 *         -EPERM on tpm error status
 *         < 0 error from tpm_send
 */
static int tpm2_unseal_cmd(struct tpm_chip *chip,
			   struct trusted_key_payload *payload,
			   struct trusted_key_options *options,
			   u32 blob_handle)
{
	struct trusted_key_tpm *private = options->private;
	u8 blob_name[TPM2_MAX_NAME_SIZE];
	struct tpm_buf *buf __free(kfree) = NULL;
	unsigned int data_len;
	u16 blob_name_size;
	u8 *data;
	int rc;

	rc = tpm2_read_public(chip, blob_handle, blob_name);
	if (rc < 0)
		return rc;

	blob_name_size = rc;

	rc = tpm2_start_auth_session(chip);
	if (rc)
		return rc;

	buf = kzalloc(TPM_BUFSIZE, GFP_KERNEL);
	if (!buf) {
		tpm2_end_auth_session(chip);
		return -ENOMEM;
	}

	tpm_buf_init(buf, TPM_BUFSIZE);
	tpm_buf_reset(buf, TPM2_ST_SESSIONS, TPM2_CC_UNSEAL);

	rc = tpm_buf_append_name(chip, buf, blob_handle, blob_name,
				 blob_name_size);
	if (rc)
		return rc;

	if (!private->policyhandle) {
		tpm_buf_append_hmac_session(chip, buf, TPM2_SA_ENCRYPT,
					    private->blobauth,
					    private->blobauth_len);
	} else {
		/*
		 * FIXME: The policy session was generated outside the
		 * kernel so we don't known the nonce and thus can't
		 * calculate a HMAC on it.  Therefore, the user can
		 * only really use TPM2_PolicyPassword and we must
		 * send down the plain text password, which could be
		 * intercepted.  We can still encrypt the returned
		 * key, but that's small comfort since the interposer
		 * could repeat our actions with the exfiltrated
		 * password.
		 */
		tpm_buf_append_u32(buf, 9 + private->blobauth_len);
		tpm_buf_append_u32(buf, private->policyhandle);
		tpm_buf_append_u16(buf, 0);
		tpm_buf_append_u8(buf, 0);
		tpm_buf_append_u16(buf, private->blobauth_len);
		tpm_buf_append(buf, private->blobauth, private->blobauth_len);

		if (tpm2_chip_auth(chip))
			tpm_buf_append_hmac_session(chip, buf, TPM2_SA_ENCRYPT,
						    NULL, 0);
	}

	rc = tpm_buf_fill_hmac_session(chip, buf);
	if (rc)
		return rc;

	rc = tpm_transmit_cmd(chip, buf, 6, "unsealing");
	rc = tpm_buf_check_hmac_response(chip, buf, rc);

	if (!rc) {
		unsigned int min_len = payload->old_format ? MIN_KEY_SIZE : 1;

		data_len = be16_to_cpup(
			(__be16 *)&buf->data[TPM_HEADER_SIZE + 4]);
		if (data_len < min_len || data_len > MAX_KEY_SIZE)
			return -EFAULT;

		if (tpm_buf_length(buf) < TPM_HEADER_SIZE + 6 + data_len)
			return -EFAULT;
		data = &buf->data[TPM_HEADER_SIZE + 6];

		if (payload->old_format) {
			/* migratable flag is at the end of the key */
			memcpy(payload->key, data, data_len - 1);
			payload->key_len = data_len - 1;
			payload->migratable = data[data_len - 1];
		} else {
			/*
			 * migratable flag already collected from key
			 * attributes
			 */
			memcpy(payload->key, data, data_len);
			payload->key_len = data_len;
		}
	}

	return tpm_ret_to_err(rc);
}

/**
 * tpm2_unseal_trusted() - unseal the payload of a trusted key
 *
 * @chip: TPM chip to use
 * @payload: the key data in clear and encrypted form
 * @options: authentication values and other options
 *
 * Return: Same as with tpm_send.
 */
int tpm2_unseal_trusted(struct tpm_chip *chip,
			struct trusted_key_payload *payload,
			struct trusted_key_options *options)
{
	u32 blob_handle;
	int rc;

	rc = tpm_try_get_ops(chip);
	if (rc)
		return rc;

	rc = tpm2_load_cmd(chip, payload, options, &blob_handle);
	if (rc)
		goto out;

	rc = tpm2_unseal_cmd(chip, payload, options, blob_handle);
	tpm2_flush_context(chip, blob_handle);

out:
	tpm_put_ops(chip);
	return tpm_ret_to_err(rc);
}
