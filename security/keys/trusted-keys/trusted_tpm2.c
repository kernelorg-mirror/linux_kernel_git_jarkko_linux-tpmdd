// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2004 IBM Corporation
 * Copyright (C) 2014 Intel Corporation
 */

#include <crypto/hash_info.h>
#include <crypto/internal/ecc.h>
#include <linux/cleanup.h>
#include <linux/keyctl.h>
#include <linux/slab.h>
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
	enum OID oid;
	const u8 *pub;
	u32 pub_len;
	const u8 *priv;
	u32 priv_len;
	bool has_policy;
};

static int tpm2_key_decode(const struct trusted_key_payload *payload,
			   const struct trusted_key_tpm *private,
			   u32 *parent, u8 **buf, unsigned int *blob_len,
			   enum OID *oid)
{
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

	if (ctx.priv_len < 2 || ctx.pub_len < 2)
		return -EBADMSG;

	if (get_unaligned_be16(ctx.priv) + 2 != ctx.priv_len ||
	    get_unaligned_be16(ctx.pub) + 2 != ctx.pub_len)
		return -EBADMSG;

	if (ctx.priv_len + ctx.pub_len > MAX_BLOB_SIZE)
		return -EINVAL;

	blob = kmalloc(ctx.priv_len + ctx.pub_len, GFP_KERNEL);
	if (!blob)
		return -ENOMEM;

	*buf = blob;
	*blob_len = ctx.priv_len + ctx.pub_len;
	if (oid)
		*oid = ctx.oid;
	if (parent)
		*parent = ctx.parent;

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
	struct tpm2_key_context *ctx = context;
	enum OID oid = look_up_OID(value, vlen);

	if (oid == OID_TPMSealedData || oid == OID_TPMLoadableKey) {
		ctx->oid = oid;
		return 0;
	}

	if (IS_ENABLED(CONFIG_DEBUG_KERNEL)) {
		char buffer[50];

		sprint_oid(value, vlen, buffer, sizeof(buffer));
		pr_debug("OID \"%s\" is not supported\n", buffer);
	}

	return -EINVAL;
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

static int tpm2_asym_parse_rsa_public(struct trusted_key_tpm *private,
				      struct tpm_buf *buf, off_t *offset)
{
	u32 exponent;
	u16 mod_size;

	switch (private->scheme) {
	case TPM_ALG_NULL:
		private->scheme_hash = TPM_ALG_NULL;
		break;
	case TPM_ALG_RSASSA:
		if (!(private->attrs & TPM2_OA_SIGN))
			return -EBADMSG;
		if (!tpm_buf_read_u16(buf, offset, &private->scheme_hash))
			return -EBADMSG;
		break;
	case TPM_ALG_RSAES:
		if (!(private->attrs & TPM2_OA_DECRYPT))
			return -EBADMSG;
		private->scheme_hash = TPM_ALG_NULL;
		break;
	case TPM_ALG_OAEP:
		if (!(private->attrs & TPM2_OA_DECRYPT))
			return -EBADMSG;
		if (!tpm_buf_read_u16(buf, offset, &private->scheme_hash))
			return -EBADMSG;
		break;
	default:
		return -EOPNOTSUPP;
	}

	if (!tpm_buf_read_u16(buf, offset, &private->key_bits))
		return -EBADMSG;
	if (private->key_bits != 2048 &&
	    private->key_bits != 3072 &&
	    private->key_bits != 4096)
		return -EOPNOTSUPP;

	if (!tpm_buf_read_u32(buf, offset, &exponent))
		return -EBADMSG;
	if (exponent != 0 && exponent != 0x00010001)
		return -EOPNOTSUPP;

	if (!tpm_buf_read_u16(buf, offset, &mod_size))
		return -EBADMSG;
	if (mod_size != private->key_bits / 8)
		return -EBADMSG;
	if (mod_size > tpm_buf_length(buf) - *offset)
		return -EBADMSG;
	*offset += mod_size;

	return *offset == tpm_buf_length(buf) ? 0 : -EBADMSG;
}

static int tpm2_asym_parse_ecc_public(struct trusted_key_tpm *private,
				      struct tpm_buf *buf, off_t *offset)
{
	u16 curve_id, kdf, x_size, y_size;

	if (!(private->attrs & TPM2_OA_SIGN))
		return -EINVAL;

	switch (private->scheme) {
	case TPM_ALG_NULL:
		private->scheme_hash = TPM_ALG_NULL;
		break;
	case TPM_ALG_ECDSA:
		if (!tpm_buf_read_u16(buf, offset, &private->scheme_hash))
			return -EBADMSG;
		break;
	default:
		return -EOPNOTSUPP;
	}

	if (!tpm_buf_read_u16(buf, offset, &curve_id))
		return -EBADMSG;

	switch (curve_id) {
	case TPM2_ECC_NIST_P256:
		private->key_bits = 256;
		private->coord_size = 32;
		break;
	case TPM2_ECC_NIST_P384:
		private->key_bits = 384;
		private->coord_size = 48;
		break;
	case TPM2_ECC_NIST_P521:
		private->key_bits = 521;
		private->coord_size = 66;
		break;
	default:
		return -EOPNOTSUPP;
	}

	if (!tpm_buf_read_u16(buf, offset, &kdf))
		return -EBADMSG;
	if (kdf != TPM_ALG_NULL)
		return -EOPNOTSUPP;

	if (!tpm_buf_read_u16(buf, offset, &x_size))
		return -EBADMSG;
	if (!x_size || x_size > private->coord_size ||
	    x_size > tpm_buf_length(buf) - *offset)
		return -EBADMSG;
	*offset += x_size;

	if (!tpm_buf_read_u16(buf, offset, &y_size))
		return -EBADMSG;
	if (!y_size || y_size > private->coord_size ||
	    y_size > tpm_buf_length(buf) - *offset)
		return -EBADMSG;
	*offset += y_size;

	return *offset == tpm_buf_length(buf) ? 0 : -EBADMSG;
}

static int tpm2_asym_parse_public(struct trusted_key_tpm *private,
				  const u8 *pub, unsigned int pub_len)
{
	struct tpm_buf *buf __free(kfree) = NULL;
	u16 name_alg, policy_len, symmetric;
	off_t offset = 2;

	buf = kzalloc(TPM_BUFSIZE, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	tpm_buf_init_sized(buf, TPM_BUFSIZE);
	tpm_buf_append(buf, pub, pub_len);
	if (buf->flags & TPM_BUF_INVALID)
		return -EBADMSG;

	if (!tpm_buf_read_u16(buf, &offset, &private->alg_type) ||
	    !tpm_buf_read_u16(buf, &offset, &name_alg))
		return -EBADMSG;
	if (name_alg == TPM_ALG_ERROR || name_alg == TPM_ALG_NULL)
		return -EBADMSG;

	if (!tpm_buf_read_u32(buf, &offset, &private->attrs))
		return -EBADMSG;
	if (private->attrs & TPM2_OA_RESTRICTED)
		return -EINVAL;
	if (!(private->attrs & (TPM2_OA_SIGN | TPM2_OA_DECRYPT)))
		return -EINVAL;

	if (!tpm_buf_read_u16(buf, &offset, &policy_len))
		return -EBADMSG;
	if (policy_len && !private->policyhandle)
		return -EOPNOTSUPP;
	if (policy_len > tpm_buf_length(buf) - offset)
		return -EBADMSG;
	offset += policy_len;

	if (!tpm_buf_read_u16(buf, &offset, &symmetric))
		return -EBADMSG;
	if (symmetric != TPM_ALG_NULL)
		return -EBADMSG;

	if (!tpm_buf_read_u16(buf, &offset, &private->scheme))
		return -EBADMSG;

	switch (private->alg_type) {
	case TPM_ALG_RSA:
		return tpm2_asym_parse_rsa_public(private, buf, &offset);
	case TPM_ALG_ECC:
		return tpm2_asym_parse_ecc_public(private, buf, &offset);
	default:
		return -EOPNOTSUPP;
	}
}

static int tpm2_load_blob(struct tpm_chip *chip,
			  struct trusted_key_tpm *private,
			  const u8 *blob, unsigned int blob_len,
			  u32 *blob_handle)
{
	u8 parent_name[TPM2_MAX_NAME_SIZE];
	struct tpm_buf *buf __free(kfree) = NULL;
	bool created_parent = false;
	u16 parent_name_size;
	u32 parent_handle;
	int rc;

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
		*blob_handle = get_unaligned_be32(&buf->data[TPM_HEADER_SIZE]);

out:
	if (created_parent)
		tpm2_flush_context(chip, parent_handle);

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
	unsigned int private_len;
	unsigned int public_len;
	unsigned int blob_len;
	enum OID oid = OID_TPMSealedData;
	u32 parent = 0;
	u8 *blob, *pub;
	int rc;
	u32 attrs;

	rc = tpm2_key_decode(payload, private, &parent, &blob, &blob_len, &oid);
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
		if (!private->keyhandle)
			private->keyhandle = parent;
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

	if (oid == OID_TPMLoadableKey) {
		if (!IS_ENABLED(CONFIG_TRUSTED_KEYS_ASYMMETRIC))
			return -EOPNOTSUPP;

		rc = tpm2_asym_parse_public(private, pub, public_len);
		if (rc)
			return rc;
		payload->migratable = 0;
		payload->key_len = 0;
	}

	return tpm2_load_blob(chip, private, blob, blob_len, blob_handle);
}

static void tpm2_buf_append_key_auth(struct tpm_chip *chip,
				     struct tpm_buf *buf,
				     struct trusted_key_tpm *private,
				     u8 hmac_attrs)
{
	if (!private->policyhandle) {
		tpm_buf_append_hmac_session(chip, buf, hmac_attrs,
					    private->blobauth,
					    private->blobauth_len);
		return;
	}

	/*
	 * FIXME: The policy session was generated outside the kernel so we
	 * don't know the nonce and thus can't calculate a HMAC on it.
	 * Therefore, the user can only really use TPM2_PolicyPassword and we
	 * must send down the plain text password, which could be intercepted.
	 */
	tpm_buf_append_u32(buf, 9 + private->blobauth_len);
	tpm_buf_append_u32(buf, private->policyhandle);
	tpm_buf_append_u16(buf, 0);
	tpm_buf_append_u8(buf, 0);
	tpm_buf_append_u16(buf, private->blobauth_len);
	tpm_buf_append(buf, private->blobauth, private->blobauth_len);

	if (tpm2_chip_auth(chip))
		tpm_buf_append_hmac_session(chip, buf, hmac_attrs, NULL, 0);
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

	tpm2_buf_append_key_auth(chip, buf, private, TPM2_SA_ENCRYPT);

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
	struct trusted_key_tpm *private = options->private;
	u32 blob_handle;
	int rc;

	rc = tpm_try_get_ops(chip);
	if (rc)
		return rc;

	rc = tpm2_load_cmd(chip, payload, options, &blob_handle);
	if (rc)
		goto out;

	if (!private->alg_type)
		rc = tpm2_unseal_cmd(chip, payload, options, blob_handle);
	tpm2_flush_context(chip, blob_handle);

out:
	tpm_put_ops(chip);
	return tpm_ret_to_err(rc);
}

#ifdef CONFIG_TRUSTED_KEYS_ASYMMETRIC
static int tpm2_asym_load(struct tpm_chip *chip,
			  const struct trusted_key_payload *payload,
			  struct trusted_key_tpm *private,
			  u32 *key_handle)
{
	u8 *blob __free(kfree) = NULL;
	unsigned int blob_len;
	int rc;

	rc = tpm2_key_decode(payload, private, NULL, &blob, &blob_len, NULL);
	if (rc)
		return rc;

	return tpm2_load_blob(chip, private, blob, blob_len, key_handle);
}

static int tpm2_asym_hash_lookup(const struct trusted_key_tpm *private,
				 const char *hash_algo,
				 int *hash_id, int *tpm_hash)
{
	int id, alg;

	if (!hash_algo)
		return -EINVAL;

	id = match_string(hash_algo_name, HASH_ALGO__LAST, hash_algo);
	if (id < 0)
		return -ENOPKG;

	alg = tpm2_find_hash_alg(id);
	if (alg < 0)
		return -ENOPKG;

	if (private->scheme_hash != TPM_ALG_NULL && alg != private->scheme_hash)
		return -EINVAL;

	if (hash_id)
		*hash_id = id;
	if (tpm_hash)
		*tpm_hash = alg;
	return 0;
}

static int tpm2_asym_sig_scheme(const struct trusted_key_tpm *private,
				const char *encoding, const char *hash_algo,
				u16 *scheme, int *hash_id, int *tpm_hash)
{
	if (!(private->attrs & TPM2_OA_SIGN))
		return -EOPNOTSUPP;
	if (!encoding)
		return -EINVAL;

	switch (private->alg_type) {
	case TPM_ALG_RSA:
		if (strcmp(encoding, "pkcs1") != 0)
			return -ENOPKG;
		if (private->scheme != TPM_ALG_NULL &&
		    private->scheme != TPM_ALG_RSASSA)
			return -ENOPKG;
		*scheme = TPM_ALG_RSASSA;
		break;
	case TPM_ALG_ECC:
		if (strcmp(encoding, "x962") != 0)
			return -ENOPKG;
		if (private->scheme != TPM_ALG_NULL &&
		    private->scheme != TPM_ALG_ECDSA)
			return -ENOPKG;
		*scheme = TPM_ALG_ECDSA;
		break;
	default:
		return -EOPNOTSUPP;
	}

	return tpm2_asym_hash_lookup(private, hash_algo, hash_id, tpm_hash);
}

static int tpm2_asym_enc_scheme(const struct trusted_key_tpm *private,
				const char *encoding, const char *hash_algo,
				u16 *scheme, u16 *scheme_hash)
{
	int tpm_hash, ret;

	if (private->alg_type != TPM_ALG_RSA ||
	    !(private->attrs & TPM2_OA_DECRYPT))
		return -EOPNOTSUPP;
	if (!encoding)
		return -EINVAL;

	if (strcmp(encoding, "pkcs1") == 0) {
		if (private->scheme != TPM_ALG_NULL &&
		    private->scheme != TPM_ALG_RSAES)
			return -ENOPKG;
		*scheme = TPM_ALG_RSAES;
		*scheme_hash = TPM_ALG_NULL;
		return 0;
	}

	if (strcmp(encoding, "oaep") == 0) {
		if (private->scheme != TPM_ALG_NULL &&
		    private->scheme != TPM_ALG_OAEP)
			return -ENOPKG;
		ret = tpm2_asym_hash_lookup(private, hash_algo, NULL,
					    &tpm_hash);
		if (ret)
			return ret;
		*scheme = TPM_ALG_OAEP;
		*scheme_hash = tpm_hash;
		return 0;
	}

	if (strcmp(encoding, "raw") == 0) {
		if (hash_algo)
			return -EINVAL;
		if (private->scheme != TPM_ALG_NULL)
			return -ENOPKG;
		*scheme = TPM_ALG_NULL;
		*scheme_hash = TPM_ALG_NULL;
		return 0;
	}

	return -ENOPKG;
}

static int tpm2_asym_rsa_encrypt(struct tpm_chip *chip,
				 const struct trusted_key_payload *payload,
				 struct trusted_key_tpm *private,
				 struct kernel_pkey_params *params,
				 const void *in, void *out)
{
	struct tpm_buf *buf __free(kfree) = NULL;
	u16 ciphertext_len, scheme, scheme_hash;
	u32 key_handle;
	off_t offset;
	int rc;

	rc = tpm2_asym_enc_scheme(private, params->encoding, params->hash_algo,
				  &scheme, &scheme_hash);
	if (rc)
		return rc;
	buf = kzalloc(TPM_BUFSIZE, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	rc = tpm_try_get_ops(chip);
	if (rc)
		return rc;

	rc = tpm2_asym_load(chip, payload, private, &key_handle);
	if (rc)
		goto out_ops;

	tpm_buf_init(buf, TPM_BUFSIZE);
	tpm_buf_reset(buf, TPM2_ST_NO_SESSIONS, TPM2_CC_RSA_ENCRYPT);
	tpm_buf_append_u32(buf, key_handle);
	tpm_buf_append_u16(buf, params->in_len);
	tpm_buf_append(buf, in, params->in_len);
	tpm_buf_append_u16(buf, scheme);
	if (scheme == TPM_ALG_OAEP)
		tpm_buf_append_u16(buf, scheme_hash);
	tpm_buf_append_u16(buf, 0);
	if (buf->flags & TPM_BUF_INVALID) {
		rc = -E2BIG;
		goto out_key;
	}

	rc = tpm_transmit_cmd(chip, buf, 2, "TPM2_RSA_Encrypt");
	if (rc) {
		rc = tpm_ret_to_err(rc);
		goto out_key;
	}

	offset = TPM_HEADER_SIZE;
	if (!tpm_buf_read_u16(buf, &offset, &ciphertext_len) ||
	    offset + ciphertext_len > buf->length) {
		rc = -EIO;
		goto out_key;
	}
	if (params->out_len < ciphertext_len) {
		rc = -EMSGSIZE;
		goto out_key;
	}

	memcpy(out, &buf->data[offset], ciphertext_len);
	rc = ciphertext_len;

out_key:
	tpm2_flush_context(chip, key_handle);
out_ops:
	tpm_put_ops(chip);
	return rc;
}

static int tpm2_asym_rsa_decrypt(struct tpm_chip *chip,
				 const struct trusted_key_payload *payload,
				 struct trusted_key_tpm *private,
				 struct kernel_pkey_params *params,
				 const void *in, void *out)
{
	u8 key_name[TPM2_MAX_NAME_SIZE];
	struct tpm_buf *buf __free(kfree) = NULL;
	u16 decrypted_len, key_name_size, scheme, scheme_hash;
	u32 key_handle, param_size;
	off_t offset;
	int rc;

	rc = tpm2_asym_enc_scheme(private, params->encoding, params->hash_algo,
				  &scheme, &scheme_hash);
	if (rc)
		return rc;
	buf = kzalloc(TPM_BUFSIZE, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	rc = tpm_try_get_ops(chip);
	if (rc)
		return rc;

	rc = tpm2_asym_load(chip, payload, private, &key_handle);
	if (rc)
		goto out_ops;

	rc = tpm2_read_public(chip, key_handle, key_name);
	if (rc < 0)
		goto out_key;
	key_name_size = rc;

	rc = tpm2_start_auth_session(chip);
	if (rc)
		goto out_key;

	tpm_buf_init(buf, TPM_BUFSIZE);
	tpm_buf_reset(buf, TPM2_ST_SESSIONS, TPM2_CC_RSA_DECRYPT);

	rc = tpm_buf_append_name(chip, buf, key_handle, key_name,
				 key_name_size);
	if (rc)
		goto out_key;

	tpm2_buf_append_key_auth(chip, buf, private,
				 TPM2_SA_DECRYPT | TPM2_SA_ENCRYPT);
	tpm_buf_append_u16(buf, params->in_len);
	tpm_buf_append(buf, in, params->in_len);
	tpm_buf_append_u16(buf, scheme);
	if (scheme == TPM_ALG_OAEP)
		tpm_buf_append_u16(buf, scheme_hash);
	tpm_buf_append_u16(buf, 0);
	if (buf->flags & TPM_BUF_INVALID) {
		tpm2_end_auth_session(chip);
		rc = -E2BIG;
		goto out_key;
	}

	rc = tpm_buf_fill_hmac_session(chip, buf);
	if (rc)
		goto out_key;

	rc = tpm_transmit_cmd(chip, buf, 6, "TPM2_RSA_Decrypt");
	rc = tpm_buf_check_hmac_response(chip, buf, rc);
	if (rc) {
		rc = tpm_ret_to_err(rc);
		goto out_key;
	}

	offset = TPM_HEADER_SIZE;
	if (!tpm_buf_read_u32(buf, &offset, &param_size) ||
	    !tpm_buf_read_u16(buf, &offset, &decrypted_len) ||
	    param_size < 2 + decrypted_len ||
	    param_size > buf->length - (offset - 2)) {
		rc = -EIO;
		goto out_key;
	}
	if (params->out_len < decrypted_len) {
		rc = -EMSGSIZE;
		goto out_key;
	}

	memcpy(out, &buf->data[offset], decrypted_len);
	rc = decrypted_len;

out_key:
	tpm2_flush_context(chip, key_handle);
out_ops:
	tpm_put_ops(chip);
	return rc;
}

static int tpm2_asym_parse_ecdsa_sig(struct tpm_buf *buf, off_t *offset,
				     size_t param_end,
				     struct kernel_pkey_params *params,
				     void *out)
{
	u8 der[2 * (2 + ECC_MAX_BYTES + 1)];
	u16 r_size, s_size;
	u8 *encoded, *ptr;
	const u8 *r, *s;

	if (!tpm_buf_read_u16(buf, offset, &r_size) ||
	    !r_size || r_size > ECC_MAX_BYTES ||
	    *offset + r_size > param_end)
		return -EIO;
	r = &buf->data[*offset];
	*offset += r_size;

	if (!tpm_buf_read_u16(buf, offset, &s_size) ||
	    !s_size || s_size > ECC_MAX_BYTES ||
	    *offset + s_size > param_end)
		return -EIO;
	s = &buf->data[*offset];
	*offset += s_size;

	ptr = der;
	ptr = asn1_encode_integer_bytes(ptr, der + sizeof(der), r, r_size);
	ptr = asn1_encode_integer_bytes(ptr, der + sizeof(der), s, s_size);
	if (IS_ERR(ptr))
		return PTR_ERR(ptr);

	encoded = asn1_encode_sequence(out, (u8 *)out + params->out_len,
				       der, ptr - der);
	if (IS_ERR(encoded))
		return PTR_ERR(encoded) == -EINVAL ? -EMSGSIZE : PTR_ERR(encoded);

	return encoded - (u8 *)out;
}

static int tpm2_asym_parse_signature(struct tpm_buf *buf, u16 scheme,
				     int tpm_hash,
				     struct kernel_pkey_params *params,
				     void *out)
{
	off_t offset = TPM_HEADER_SIZE;
	u16 sig_alg, hash_alg, sig_len;
	size_t param_end;
	u32 param_size;

	if (!tpm_buf_read_u32(buf, &offset, &param_size) ||
	    param_size < 4 || param_size > buf->length - offset)
		return -EIO;
	param_end = offset + param_size;

	if (!tpm_buf_read_u16(buf, &offset, &sig_alg) ||
	    !tpm_buf_read_u16(buf, &offset, &hash_alg) ||
	    sig_alg != scheme || hash_alg != tpm_hash)
		return -EIO;

	switch (scheme) {
	case TPM_ALG_RSASSA:
		if (!tpm_buf_read_u16(buf, &offset, &sig_len) ||
		    offset + sig_len > param_end)
			return -EIO;
		if (sig_len > params->out_len)
			return -EMSGSIZE;
		memcpy(out, &buf->data[offset], sig_len);
		return sig_len;
	case TPM_ALG_ECDSA:
		return tpm2_asym_parse_ecdsa_sig(buf, &offset, param_end,
						 params, out);
	default:
		return -EOPNOTSUPP;
	}
}

static int tpm2_asym_sign(struct tpm_chip *chip,
			  const struct trusted_key_payload *payload,
			  struct trusted_key_tpm *private,
			  struct kernel_pkey_params *params,
			  const void *in, void *out)
{
	u8 key_name[TPM2_MAX_NAME_SIZE];
	struct tpm_buf *buf __free(kfree) = NULL;
	int hash_id, tpm_hash, rc;
	u16 key_name_size, scheme;
	u32 key_handle;

	rc = tpm2_asym_sig_scheme(private, params->encoding, params->hash_algo,
				  &scheme, &hash_id, &tpm_hash);
	if (rc)
		return rc;
	if (params->in_len != hash_digest_size[hash_id])
		return -EINVAL;

	buf = kzalloc(TPM_BUFSIZE, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	rc = tpm_try_get_ops(chip);
	if (rc)
		return rc;

	rc = tpm2_asym_load(chip, payload, private, &key_handle);
	if (rc)
		goto out_ops;

	rc = tpm2_read_public(chip, key_handle, key_name);
	if (rc < 0)
		goto out_key;
	key_name_size = rc;

	rc = tpm2_start_auth_session(chip);
	if (rc)
		goto out_key;

	tpm_buf_init(buf, TPM_BUFSIZE);
	tpm_buf_reset(buf, TPM2_ST_SESSIONS, TPM2_CC_SIGN);

	rc = tpm_buf_append_name(chip, buf, key_handle, key_name,
				 key_name_size);
	if (rc)
		goto out_key;

	tpm2_buf_append_key_auth(chip, buf, private, TPM2_SA_DECRYPT);

	/* digest (TPM2B_DIGEST) */
	tpm_buf_append_u16(buf, params->in_len);
	tpm_buf_append(buf, in, params->in_len);

	/* inScheme (TPMT_SIG_SCHEME) */
	tpm_buf_append_u16(buf, scheme);
	tpm_buf_append_u16(buf, tpm_hash);

	/* validation (TPMT_TK_HASHCHECK): NULL ticket */
	tpm_buf_append_u16(buf, TPM2_ST_HASHCHECK);
	tpm_buf_append_u32(buf, TPM2_RH_NULL);
	tpm_buf_append_u16(buf, 0);

	if (buf->flags & TPM_BUF_INVALID) {
		tpm2_end_auth_session(chip);
		rc = -E2BIG;
		goto out_key;
	}

	rc = tpm_buf_fill_hmac_session(chip, buf);
	if (rc)
		goto out_key;

	rc = tpm_transmit_cmd(chip, buf, 4, "TPM2_Sign");
	rc = tpm_buf_check_hmac_response(chip, buf, rc);
	if (rc) {
		rc = tpm_ret_to_err(rc);
		goto out_key;
	}

	rc = tpm2_asym_parse_signature(buf, scheme, tpm_hash, params, out);

out_key:
	tpm2_flush_context(chip, key_handle);
out_ops:
	tpm_put_ops(chip);
	return rc;
}

static int tpm2_asym_decode_der_int(const u8 **p, const u8 *end,
				    u16 max_len, const u8 **out, u16 *out_len)
{
	u32 len;

	if (*p >= end || *(*p)++ != ASN1_INT)
		return -EBADMSG;
	if (*p >= end)
		return -EBADMSG;

	len = *(*p)++;
	if (!len || len >= 0x80 || *p + len > end)
		return -EBADMSG;

	/* Negative DER INTEGER or non-minimal zero padding */
	if (**p & 0x80)
		return -EBADMSG;
	if (len > 1 && (*p)[0] == 0x00 && !((*p)[1] & 0x80))
		return -EBADMSG;
	if (len > 1 && **p == 0x00) {
		(*p)++;
		len--;
	}
	if (len > max_len)
		return -EBADMSG;

	*out = *p;
	*out_len = len;
	*p += len;
	return 0;
}

static int tpm2_asym_decode_ecdsa_sig(const u8 *der, u32 der_len,
				      u16 coord_size,
				      const u8 **r, u16 *r_len,
				      const u8 **s, u16 *s_len)
{
	const u8 *end = der + der_len;
	const u8 *p = der;
	u32 seq_len;
	int ret;

	if (p >= end || *p++ != (ASN1_CONS_BIT | ASN1_SEQ))
		return -EBADMSG;
	if (p >= end)
		return -EBADMSG;

	if (*p < 0x80) {
		seq_len = *p++;
	} else if (*p == 0x81) {
		if (++p >= end)
			return -EBADMSG;
		seq_len = *p++;
		if (seq_len < 0x80)
			return -EBADMSG;
	} else {
		return -EBADMSG;
	}

	if (p + seq_len != end)
		return -EBADMSG;

	ret = tpm2_asym_decode_der_int(&p, end, coord_size, r, r_len);
	if (ret)
		return ret;

	ret = tpm2_asym_decode_der_int(&p, end, coord_size, s, s_len);
	if (ret)
		return ret;

	return p == end ? 0 : -EBADMSG;
}

static unsigned int tpm2_asym_der_len_size(unsigned int len)
{
	if (len < 128)
		return 1;
	if (len <= 255)
		return 2;
	return 3;
}

static int tpm2_asym_rsa_query(const struct trusted_key_tpm *private,
			       const struct kernel_pkey_params *params,
			       struct kernel_pkey_query *info)
{
	u16 max_data_size = TPM2_MAX_DIGEST_SIZE;
	u16 mod_size = private->key_bits / 8;
	int hash_id, ret;

	if (!params->encoding)
		return -EINVAL;

	memset(info, 0, sizeof(*info));
	info->key_size = private->key_bits;

	if (strcmp(params->encoding, "pkcs1") == 0) {
		if (params->hash_algo) {
			ret = tpm2_asym_hash_lookup(private, params->hash_algo,
						    &hash_id, NULL);
			if (ret)
				return ret;
			max_data_size = hash_digest_size[hash_id];
		}

		if ((private->attrs & TPM2_OA_SIGN) &&
		    (private->scheme == TPM_ALG_NULL ||
		     private->scheme == TPM_ALG_RSASSA)) {
			info->max_data_size = max_data_size;
			info->max_sig_size = mod_size;
			info->supported_ops |= KEYCTL_SUPPORTS_SIGN |
					       KEYCTL_SUPPORTS_VERIFY;
		}
		if ((private->attrs & TPM2_OA_DECRYPT) &&
		    (private->scheme == TPM_ALG_NULL ||
		     private->scheme == TPM_ALG_RSAES)) {
			info->max_enc_size = mod_size;
			info->max_dec_size = mod_size;
			info->supported_ops |= KEYCTL_SUPPORTS_ENCRYPT |
					       KEYCTL_SUPPORTS_DECRYPT;
		}
		return info->supported_ops ? 0 : -ENOPKG;
	}

	if (strcmp(params->encoding, "oaep") == 0) {
		if (!(private->attrs & TPM2_OA_DECRYPT) ||
		    (private->scheme != TPM_ALG_NULL &&
		     private->scheme != TPM_ALG_OAEP))
			return -ENOPKG;

		ret = tpm2_asym_hash_lookup(private, params->hash_algo, NULL, NULL);
		if (ret)
			return ret;

		/* keyutils can size the output buffer from either limit. */
		info->max_enc_size = mod_size;
		info->max_dec_size = mod_size;
		info->supported_ops = KEYCTL_SUPPORTS_ENCRYPT |
				      KEYCTL_SUPPORTS_DECRYPT;
		return 0;
	}

	if (strcmp(params->encoding, "raw") == 0) {
		if (params->hash_algo)
			return -EINVAL;
		if (!(private->attrs & TPM2_OA_DECRYPT) ||
		    private->scheme != TPM_ALG_NULL)
			return -ENOPKG;

		info->max_data_size = mod_size;
		info->max_enc_size = mod_size;
		info->max_dec_size = mod_size;
		info->supported_ops = KEYCTL_SUPPORTS_ENCRYPT |
				      KEYCTL_SUPPORTS_DECRYPT;
		return 0;
	}

	return -ENOPKG;
}

static int tpm2_asym_ecc_query(const struct trusted_key_tpm *private,
			       const struct kernel_pkey_params *params,
			       struct kernel_pkey_query *info)
{
	u16 max_data_size = TPM2_MAX_DIGEST_SIZE;
	unsigned int int_len, seq_payload;
	int hash_id, ret;

	if (!params->encoding || strcmp(params->encoding, "x962") != 0)
		return -ENOPKG;

	if (params->hash_algo) {
		ret = tpm2_asym_hash_lookup(private, params->hash_algo,
					    &hash_id, NULL);
		if (ret)
			return ret;
		max_data_size = hash_digest_size[hash_id];
	}

	int_len = private->coord_size + 1;
	seq_payload = 2 * (1 + tpm2_asym_der_len_size(int_len) + int_len);

	memset(info, 0, sizeof(*info));
	info->key_size = private->key_bits;
	info->max_sig_size = 1 + tpm2_asym_der_len_size(seq_payload) +
			     seq_payload;
	info->max_data_size = max_data_size;
	info->supported_ops = KEYCTL_SUPPORTS_SIGN | KEYCTL_SUPPORTS_VERIFY;
	return 0;
}

/**
 * tpm2_asym_query() - query capabilities of an asymmetric TPM 2.0 trusted key
 *
 * @payload: trusted key payload
 * @params: public-key operation parameters
 * @info: returned key capabilities and maximum sizes
 *
 * Return: 0 on success, negative errno on failure.
 */
int tpm2_asym_query(const struct trusted_key_payload *payload,
		    const struct kernel_pkey_params *params,
		    struct kernel_pkey_query *info)
{
	const struct trusted_key_tpm *private = payload->private;

	switch (private->alg_type) {
	case TPM_ALG_RSA:
		return tpm2_asym_rsa_query(private, params, info);
	case TPM_ALG_ECC:
		return tpm2_asym_ecc_query(private, params, info);
	default:
		return -EOPNOTSUPP;
	}
}

/**
 * tpm2_asym_eds_op() - encrypt, decrypt, or sign with an asymmetric TPM 2.0 key
 *
 * @chip: TPM chip to use
 * @payload: trusted key payload
 * @params: public-key operation parameters
 * @in: input plaintext, ciphertext, or digest buffer
 * @out: output ciphertext, plaintext, or signature buffer
 *
 * Return: output byte count on success, negative errno on failure.
 */
int tpm2_asym_eds_op(struct tpm_chip *chip,
		     const struct trusted_key_payload *payload,
		     struct kernel_pkey_params *params,
		     const void *in, void *out)
{
	struct trusted_key_tpm *private = payload->private;

	switch (params->op) {
	case kernel_pkey_encrypt:
		return tpm2_asym_rsa_encrypt(chip, payload, private,
					     params, in, out);
	case kernel_pkey_decrypt:
		return tpm2_asym_rsa_decrypt(chip, payload, private,
					     params, in, out);
	case kernel_pkey_sign:
		return tpm2_asym_sign(chip, payload, private, params, in, out);
	default:
		return -EOPNOTSUPP;
	}
}

/**
 * tpm2_asym_verify_signature() - verify a signature with an asymmetric TPM 2.0 key
 *
 * @chip: TPM chip to use
 * @payload: trusted key payload
 * @params: public-key operation parameters
 * @in: digest buffer
 * @in2: signature buffer
 *
 * Return: 0 on valid signature, negative errno on failure.
 */
int tpm2_asym_verify_signature(struct tpm_chip *chip,
			       const struct trusted_key_payload *payload,
			       struct kernel_pkey_params *params,
			       const void *in, const void *in2)
{
	struct trusted_key_tpm *private = payload->private;
	struct tpm_buf *buf __free(kfree) = NULL;
	int hash_id, tpm_hash, rc;
	u16 scheme, r_len, s_len;
	const u8 *r, *s;
	u32 key_handle;

	rc = tpm2_asym_sig_scheme(private, params->encoding, params->hash_algo,
				  &scheme, &hash_id, &tpm_hash);
	if (rc)
		return rc;
	if (params->in_len != hash_digest_size[hash_id])
		return -EINVAL;

	if (scheme == TPM_ALG_ECDSA) {
		rc = tpm2_asym_decode_ecdsa_sig(in2, params->in2_len,
						private->coord_size,
						&r, &r_len, &s, &s_len);
		if (rc)
			return rc;
	}

	buf = kzalloc(TPM_BUFSIZE, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	rc = tpm_try_get_ops(chip);
	if (rc)
		return rc;

	rc = tpm2_asym_load(chip, payload, private, &key_handle);
	if (rc)
		goto out_ops;

	tpm_buf_init(buf, TPM_BUFSIZE);
	tpm_buf_reset(buf, TPM2_ST_NO_SESSIONS, TPM2_CC_VERIFY_SIGNATURE);
	tpm_buf_append_u32(buf, key_handle);
	tpm_buf_append_u16(buf, params->in_len);
	tpm_buf_append(buf, in, params->in_len);
	tpm_buf_append_u16(buf, scheme);
	tpm_buf_append_u16(buf, tpm_hash);

	if (scheme == TPM_ALG_RSASSA) {
		tpm_buf_append_u16(buf, params->in2_len);
		tpm_buf_append(buf, in2, params->in2_len);
	} else {
		tpm_buf_append_u16(buf, r_len);
		tpm_buf_append(buf, r, r_len);
		tpm_buf_append_u16(buf, s_len);
		tpm_buf_append(buf, s, s_len);
	}

	if (buf->flags & TPM_BUF_INVALID) {
		rc = -E2BIG;
		goto out_key;
	}

	rc = tpm_transmit_cmd(chip, buf, 0, "TPM2_VerifySignature");
	if (rc > 0)
		rc = -EKEYREJECTED;

out_key:
	tpm2_flush_context(chip, key_handle);
out_ops:
	tpm_put_ops(chip);
	return rc;
}
#endif
