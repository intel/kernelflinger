/*
 * Copyright (c) 2017, Intel Corporation
 * All rights reserved.
 *
 * Authors: Anisha Kulkarni <anisha.dattatraya.kulkarni@intel.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer
 *      in the documentation and/or other materials provided with the
 *      distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <efi.h>
#include <lib.h>
#include "Tcg2Protocol.h"
#include "Tpm2CommandLib.h"
#include "tpm2_security.h"
#include "Tpm2Help.h"
#include "security.h"

#ifdef BUILD_ANDROID_THINGS
#define MAX_NV_NUMBER		6
#define NV_INDEX_AT_PERM_ATTR		0x01500046
#else
#define MAX_NV_NUMBER		5
#endif
#define NV_INDEX_TRUSTYOS_SEED		0x01500047
#define NV_INDEX_VBMETA_KEY_HASH	0x01500048
#define NV_INDEX_FB_BL_POLICY		0x01500049
#define NV_INDEX_BOOTLOADER		0x0150004A
#define NV_INDEX_RPMB_KEY		0x0150004B

#define PCR_7   7

#define Set_PcrSelect_Bit(pcrSelection, pcr) \
				(pcrSelection).pcrSelect[((pcr)/8)] |= (1 << ((pcr) % 8));

#define DIGEST_SIZE 32

typedef struct {
	TPMI_RH_NV_INDEX nv_index;
	TPMA_NV attribute;
} attribute_matrix_t;

static const attribute_matrix_t config_table[MAX_NV_NUMBER] =
{
#ifdef BUILD_ANDROID_THINGS
	{NV_INDEX_AT_PERM_ATTR,
		{.TPMA_NV_POLICYREAD = 1,
		.TPMA_NV_POLICYWRITE = 1,
		.TPMA_NV_WRITEALL = 1,
		.TPMA_NV_READ_STCLEAR = 1,
		}
	},
#endif
	{NV_INDEX_TRUSTYOS_SEED,
		{.TPMA_NV_POLICYREAD = 1, /* The Index data may be read if the authPolicy is satisfied. */
		.TPMA_NV_POLICYWRITE = 1, /* Authorizations to change the Index contents that require
					USER role may be provided with a policy session. */
		.TPMA_NV_WRITEALL = 1, /* A partial write of the Index data is not allowed. The write size
					shall match the defined space size.  */
		.TPMA_NV_WRITEDEFINE = 1, /* TPM2_NV_WriteLock may be used to prevent further writes
					to this location regardless of TPM reset/restart. */
		.TPMA_NV_READ_STCLEAR = 1, /* TPM2_NV_ReadLock may be used to SET TPMA_NV_READLOCKED
					for this Index. When TPMA_NV_READLOCKED is set after calling TPM2_NV_ReadLock,
					Reads of this Index are blocked until the next TPM Reset or TPM Restart*/
		}
	},
	{NV_INDEX_VBMETA_KEY_HASH,
		{.TPMA_NV_POLICYREAD = 1,
		.TPMA_NV_POLICYWRITE = 1,
		.TPMA_NV_WRITEALL = 1,
		.TPMA_NV_READ_STCLEAR = 1,
		}
	},
	{NV_INDEX_FB_BL_POLICY,
		{.TPMA_NV_POLICYREAD = 1,
		.TPMA_NV_POLICYWRITE = 1,
		.TPMA_NV_WRITEALL = 1,
		.TPMA_NV_BITS = 1,
		}
	},
	{NV_INDEX_BOOTLOADER,
		{.TPMA_NV_POLICYREAD = 1,
		.TPMA_NV_POLICYWRITE = 1,
		.TPMA_NV_WRITE_STCLEAR = 1,
		.TPMA_NV_READ_STCLEAR = 1,
		}
	},
	{NV_INDEX_RPMB_KEY,
		{.TPMA_NV_POLICYREAD = 1, /* The Index data may be read if the authPolicy is satisfied. */
		.TPMA_NV_POLICYWRITE = 1, /* Authorizations to change the Index contents that require
					USER role may be provided with a policy session. */
		.TPMA_NV_WRITEALL = 1, /* A partial write of the Index data is not allowed. The write size
					shall match the defined space size.  */
		.TPMA_NV_WRITEDEFINE = 1, /* TPM2_NV_WriteLock may be used to prevent further writes
					to this location regardless of TPM reset/restart. */
		.TPMA_NV_READ_STCLEAR = 1, /* TPM2_NV_ReadLock may be used to SET TPMA_NV_READLOCKED
					for this Index. When TPMA_NV_READLOCKED is set after calling TPM2_NV_ReadLock,
					Reads of this Index are blocked until the next TPM Reset or TPM Restart*/
		}
	},
};

#define MAX_ROLLBACK_INDEX_SLOT_TPM		8
#define NV_INDEX_BOOTLOADER_STRUCT_VER	1
#define NV_INDEX_BOOTLOADER_SIZE	512
typedef struct {
	UINT8	struct_ver;
	UINT8	lock_state;
	UINT8	reserved[6];
	uint64_t rollback_index[MAX_ROLLBACK_INDEX_SLOT_TPM];
} tpm2_bootloader_t;

#define NV_INDEX_RPMB_KEY_SIZE	32

static EFI_STATUS build_pcr_policy(TPMI_SH_AUTH_SESSION *sessionhandle,
				TPM2B_DIGEST *policy_digest,
				TPMS_AUTH_COMMAND *policy_session,
				BOOLEAN is_trial)
{
	EFI_STATUS ret = EFI_SUCCESS;
	TPM2B_ENCRYPTED_SECRET encryptedSalt;
	TPMT_SYM_DEF symmetric = {.algorithm = TPM_ALG_NULL};
	TPM2B_NONCE nonceCaller, nonceTpm;
	TPM2B_DIGEST pcrDigest;
	TPML_PCR_SELECTION pcrs;
	TPML_DIGEST pcrValues;
	UINT32 pcrUpdateCounter;
	TPML_PCR_SELECTION pcrSelectionOut;

	encryptedSalt.size = 0;
	nonceCaller.size = DIGEST_SIZE;
	ret = Tpm2GetRandom(DIGEST_SIZE, &nonceCaller);
	if(EFI_ERROR(ret)) {
		error(L"failed to get random: %d", ret);
		return ret;
	}

	nonceTpm.size = sizeof(nonceTpm) - sizeof(UINT16);

	ret = Tpm2StartAuthSession(TPM_RH_NULL,
				TPM_RH_NULL,
				&nonceCaller,
				&encryptedSalt,
				is_trial ? TPM_SE_TRIAL : TPM_SE_POLICY,
				&symmetric,
				TPM_ALG_SHA256,
				sessionhandle,
				&nonceTpm);

	memset(nonceCaller.buffer, 0, DIGEST_SIZE);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"StartAuthSession failed");
		return ret;
	}

	pcrs.count = 1;
	pcrs.pcrSelections[0].hash = TPM_ALG_SHA1;
	pcrs.pcrSelections[0].sizeofSelect = 3;
	pcrs.pcrSelections[0].pcrSelect[0] = 0;
	pcrs.pcrSelections[0].pcrSelect[1] = 0;
	pcrs.pcrSelections[0].pcrSelect[2] = 0;
	Set_PcrSelect_Bit(pcrs.pcrSelections[0], PCR_7);

	//1. Read PCRs (&pcrSelectionOut MUST NOT be NULL!!!!!)
	ret = Tpm2PcrRead(&pcrs, &pcrUpdateCounter, &pcrSelectionOut, &pcrValues);
	if(EFI_ERROR(ret)) {
		efi_perror(ret, L"Tpm2PcrRead failed");
		return ret;
	}

	if(pcrSelectionOut.count <= 0) {
		error(L"pcrSelectionOut.count <= 0");
		return EFI_INVALID_PARAMETER;
	}

	// 2. Hash those PCRs together
	pcrDigest.size = sizeof(pcrDigest) - sizeof(UINT16);
	ret = Tpm2HashSequence(TPM_ALG_SHA256, pcrValues.count, &pcrValues.digests[0], &pcrDigest);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"HashSequence failed");
		return ret;
	}

	//3. Apply selected PCRs' pcrDigest (as approvedPcrDigest) to policyDigest
	ret = Tpm2PolicyPCR(*sessionhandle, &pcrDigest, &pcrs);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"PolicyPCR failed");
		return ret;
	}

	//4. Get policyDigest hash
	if(policy_digest) {
		ret = Tpm2PolicyGetDigest(*sessionhandle, policy_digest);
		if (EFI_ERROR(ret)) {
			efi_perror(ret, L"PolicyGetDigest failed");
			return ret;
		}
	}

	if (is_trial) {
		// Need to flush the session here for trial policy only
		ret = Tpm2FlushContext(*sessionhandle);
		if (EFI_ERROR(ret)) {
			efi_perror(ret, L"FlushContext failed if trailsession");
			return ret;
		}
	}

	//5. Apply policy session handle
	if(policy_session) {
		policy_session->sessionHandle = *sessionhandle;
		policy_session->hmac.size = 0;
		policy_session->nonce.size = 0;
		*((UINT8 *)((void *)&( policy_session->sessionAttributes))) = 0;
		policy_session->sessionAttributes.continueSession = 1;
	}

	return EFI_SUCCESS;
}

EFI_STATUS tpm2_create_nvindex(TPMI_RH_NV_INDEX nv_index,
			       TPMA_NV attributes,
			       UINT32 data_size)
{
	EFI_STATUS ret;
	TPMI_RH_PROVISION auth_handle = TPM_RH_OWNER;
	TPMI_SH_AUTH_SESSION session_handle = 0;
	TPM2B_DIGEST policy_digest;
	TPM2B_NV_PUBLIC public_info;
	TPM2B_AUTH nv_auth;

	nv_auth.size = 0;
	public_info.size = sizeof(TPMI_RH_NV_INDEX)
			   + sizeof(TPMI_ALG_HASH) + sizeof(TPMA_NV)
			   + sizeof(UINT16) + sizeof(UINT16);

	public_info.nvPublic.nvIndex = nv_index;
	public_info.nvPublic.nameAlg = TPM_ALG_SHA256;
	public_info.nvPublic.attributes = attributes;
	public_info.nvPublic.authPolicy.size = 0;
	public_info.nvPublic.dataSize = data_size;

	ret = build_pcr_policy(&session_handle, &policy_digest, NULL, TRUE);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"build PCR policy failed");
		return ret;
	}
	public_info.nvPublic.authPolicy.size = policy_digest.size;
	// enable policy for this index now
	memcpy(public_info.nvPublic.authPolicy.buffer, policy_digest.buffer, policy_digest.size);
	public_info.size += public_info.nvPublic.authPolicy.size;

	return Tpm2NvDefineSpace(auth_handle, NULL,
				 &nv_auth, &public_info);
}

EFI_STATUS tpm2_write_nvindex(TPMI_RH_NV_INDEX nv_index,
			      UINT16 data_size, BYTE *data, UINT16 offset)
{
	EFI_STATUS ret = EFI_SUCCESS;
	TPMS_AUTH_COMMAND session_data = {0};
	TPMI_SH_AUTH_SESSION session_handle = 0;
	TPM2B_MAX_BUFFER nv_write_data;
	UINT16 left_size = data_size;
	UINT16 written_size = 0;
	UINT16 cur_size;

	ret = build_pcr_policy(&session_handle, NULL, &session_data, FALSE);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"build PCR policy failed");
		return ret;
	}

	// Make sure the data buffer not overflow, maybe write data several times.
	// But if attributes->TPMA_NV_WRITEALL == 1, then write will failed.
	while (left_size > 0) {
		cur_size = (left_size > sizeof(nv_write_data.buffer)) ? sizeof(nv_write_data.buffer) : left_size;
		nv_write_data.size = cur_size;
		memcpy(nv_write_data.buffer, data + written_size, nv_write_data.size);
		ret = Tpm2NvWrite(nv_index, nv_index,
			   &session_data, &nv_write_data, written_size + offset);
		if (EFI_ERROR(ret)) {
			error(L"Write TPM NV index failed, index: 0x%x, size: %d, written_size: %d, ret: %d",
					nv_index, nv_write_data.size, written_size, ret);
			break;
		}
		left_size -= cur_size;
		written_size += cur_size;
	}
	memset(&nv_write_data, 0, sizeof(nv_write_data));

	ret = Tpm2FlushContext(session_handle);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"tpm2_write_nvindex - FlushContext failed");
		return ret;
	}

	return ret;
}

EFI_STATUS tpm2_read_lock_nvindex(TPMI_RH_NV_INDEX nv_index)
{
	EFI_STATUS ret = EFI_SUCCESS;
	TPMS_AUTH_COMMAND session_data = {0};
	TPMI_SH_AUTH_SESSION session_handle = 0;

	ret = build_pcr_policy(&session_handle, NULL, &session_data, FALSE);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"build PCR policy failed");
		return ret;
	}

	ret = Tpm2NvReadLock(nv_index, nv_index, &session_data);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Tpm2NvReadLock nv_index 0x%x failed", nv_index);
		return ret;
	}
	debug(L"Tpm2NvReadLock nv_index 0x%x success", nv_index);

	ret = Tpm2FlushContext(session_handle);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"tpm2_read_lock_nvindex - FlushContext failed");
		return ret;
	}

	return ret;
}

EFI_STATUS tpm2_write_lock_nvindex(TPMI_RH_NV_INDEX nv_index)
{
	EFI_STATUS ret = EFI_SUCCESS;
	TPMS_AUTH_COMMAND session_data = {0};
	TPMI_SH_AUTH_SESSION session_handle = 0;

	ret = build_pcr_policy(&session_handle, NULL, &session_data, FALSE);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"build PCR policy failed");
		return ret;
	}

	ret = Tpm2NvWriteLock(nv_index, nv_index, &session_data);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Tpm2NvWriteLock nv_index 0x%x failed", nv_index);
		return ret;
	}
	debug(L"Tpm2NvWriteLock nv_index 0x%x success", nv_index);

	ret = Tpm2FlushContext(session_handle);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"tpm2_write_lock_nvindex - FlushContext failed");
		return ret;
	}

	return ret;
}

EFI_STATUS tpm2_read_nvindex(TPMI_RH_NV_INDEX nv_index,
				UINT16 *data_size, BYTE *data, UINT16 offset)
{
	EFI_STATUS ret;
	TPMS_AUTH_COMMAND session_data = {0};
	TPMI_SH_AUTH_SESSION session_handle = 0;
	TPM2B_MAX_BUFFER nv_read_data;
	UINT16 left_size = *data_size;
	UINT16 read_size = 0;
	UINT16 cur_size;

	ret = build_pcr_policy(&session_handle, NULL, &session_data, FALSE);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"build PCR policy failed");
		return ret;
	}

	while (left_size > 0) {
		cur_size = (left_size > sizeof(nv_read_data.buffer)) ? sizeof(nv_read_data.buffer) : left_size;
		nv_read_data.size = cur_size;

		ret = Tpm2NvRead(nv_index, nv_index, &session_data, nv_read_data.size, read_size + offset, &nv_read_data);
		if (EFI_ERROR(ret)) {
			efi_perror(ret, L"Read NVIndex failed");
			return ret;
		}
		if (nv_read_data.size > cur_size) {
			// Overflow?
			error(L"Overflow after read the NVindex");
			return EFI_ABORTED;
		}
		if (nv_read_data.size == 0) {
			// No data read
			break;
		}
		memcpy(data + read_size, nv_read_data.buffer, nv_read_data.size);
		left_size -= nv_read_data.size;
		read_size += nv_read_data.size;
	}
	*data_size = read_size;
	memset(&nv_read_data, 0, sizeof(nv_read_data));

	ret = Tpm2FlushContext(session_handle);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"tpm2_read_nvindex - FlushContext failed");
		return ret;
	}

	return EFI_SUCCESS;
}

static EFI_STATUS tpm2_set_nvbits(TPMI_RH_NV_INDEX nv_index, UINT64 set_bits)
{
	EFI_STATUS ret;
	TPMS_AUTH_COMMAND session_data = {0};
	TPMI_SH_AUTH_SESSION session_handle = 0;

	ret = build_pcr_policy(&session_handle, NULL, &session_data, FALSE);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"build PCR policy failed");
		return ret;
	}

	ret = Tpm2NvSetBits(nv_index, nv_index, &session_data, set_bits);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"set nvbits failed");
		return ret;
	}

	ret = Tpm2FlushContext(session_handle);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"tpm2_set_nvbits - FlushContext failed");
		return ret;
	}

	return EFI_SUCCESS;
}

static EFI_STATUS create_index_and_write_lock(TPM_NV_INDEX nv_index, TPMA_NV attributes,
					      UINT16 data_size, BYTE *data)
{
	EFI_STATUS ret;

	ret = tpm2_create_nvindex(nv_index, attributes, data_size);
	if (EFI_ERROR(ret)) {
		error(L"NV Index failed to create, index: 0x%x, size: %d, ret: %d", nv_index, data_size, ret);
		return ret;
	}

	ret = tpm2_write_nvindex(nv_index, data_size, data, 0);
	if (EFI_ERROR(ret)) {
		error(L"Write to NV Index failed, index: 0x%x, size: %d, ret: %d", nv_index, data_size, ret);
		return ret;
	}

	ret = tpm2_write_lock_nvindex(nv_index);
	if (EFI_ERROR(ret))
		error(L"Write lock to NV Index failed, index: 0x%x, ret: %d", nv_index, ret);

	return ret;
}

EFI_STATUS tpm2_get_capability(
		IN      TPM_CAP                   Capability,
		IN      UINT32                    Property,
		IN      UINT32                    PropertyCount,
		OUT     TPMI_YES_NO               *MoreData,
		OUT     TPMS_CAPABILITY_DATA      *CapabilityData
		)
{
	EFI_STATUS ret;
	UINT32 i;

	ret = Tpm2GetCapability(Capability, Property, PropertyCount, MoreData, CapabilityData);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Call Tpm2GetCapability failed");
		return ret;
	}
	debug(L"TPM2 capability: 0x%08x, data.tpmProperties.count: %d, more data: %d",
			SwapBytes32(CapabilityData->capability), SwapBytes32(CapabilityData->data.tpmProperties.count), *MoreData);
	for (i = 0; i < SwapBytes32(CapabilityData->data.tpmProperties.count); i++) {
		debug(L"prop %d: property: 0x%08x, value: 0x%08x", i,
				SwapBytes32(CapabilityData->data.tpmProperties.tpmProperty[i].property),
				SwapBytes32(CapabilityData->data.tpmProperties.tpmProperty[i].value));
	}

	return ret;
}

EFI_STATUS tpm2_get_lockauth(BOOLEAN *lockauth)
{
	EFI_STATUS ret;
	TPMI_YES_NO more_data;
	TPMS_CAPABILITY_DATA cap_data;
	UINT32 value;
	TPMA_PERMANENT per;

	ret = tpm2_get_capability(TPM_CAP_TPM_PROPERTIES, TPM_PT_PERMANENT, 1, &more_data, &cap_data);
	if (EFI_ERROR(ret))
		return ret;

	if (SwapBytes32(cap_data.data.tpmProperties.count) <= 0) {
		// Can't read the data
		error(L"Get empty TPM capability data of TPM_PT_PERMANENT");
		ret = EFI_NOT_FOUND;
		return ret;
	}

	value = SwapBytes32(cap_data.data.tpmProperties.tpmProperty[0].value);
	per = *(TPMA_PERMANENT *)&value;

	*lockauth = per.lockoutAuthSet;

	return ret;
}

EFI_STATUS tpm2_check_lockauth(void)
{
	EFI_STATUS ret;
	BOOLEAN lockauth;
	// Verify the LOCKOUT_AUTH
	ret = tpm2_get_lockauth(&lockauth);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Check TPM LOCKOUT_AUTH failed");
		return ret;
	}

	if (!lockauth) {
		// Show a warning if not set
		error(L"TPM LOCKOUT_AUTH is not set, set it can get higher security");
	}

	return ret;
}

EFI_STATUS tpm2_fuse_random_data(TPMI_RH_NV_INDEX nv_index, UINT16 data_size)
{
	EFI_STATUS ret;
	TPM2B_DIGEST data;
	UINT8 read_buf[2048];
	UINT16 read_size;
	UINT16 config_index;

	if (data_size >= sizeof(read_buf)) {
		error(L"Data size is too large to create random data nv index: 0x%08x, size: %d", nv_index, data_size);
		return EFI_INVALID_PARAMETER;
	}
	if (nv_index < config_table[0].nv_index || nv_index > config_table[MAX_NV_NUMBER - 1].nv_index)
		return EFI_INVALID_PARAMETER;

	ret = Tpm2GetRandom(data_size, &data);
	if (EFI_ERROR(ret)) {
		error(L"Tpm2GetRandom failed");
		goto out;
	}

	config_index = nv_index - config_table[0].nv_index;
	ret = create_index_and_write_lock(nv_index, config_table[config_index].attribute,
					data_size, data.buffer);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to create and write random data, nv index: 0x%08x", nv_index);
		goto out;
	}
	debug(L"Success create and write random data nv index: 0x%08x", nv_index);

	// Read the data again to verify it
	read_size = data_size;
	ret = tpm2_read_nvindex(nv_index, &read_size, read_buf, 0);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Read trusty seed back failed just after write it");
		goto out;
	}
	if (read_size != data_size || memcmp(data.buffer, read_buf, data_size)) {
		error(L"Security error! Read random data back but verify failed!");
		ret = EFI_SECURITY_VIOLATION;
		goto out;
	}

	tpm2_check_lockauth();
out:
	// Always clear the memory
	// Maybe be optimized?
	memset(data.buffer, 0, sizeof(data.buffer));
	memset(read_buf, 0, sizeof(read_buf));
	return ret;
}

static EFI_STATUS check_provision_status(void)
{
	EFI_STATUS ret = EFI_SUCCESS;
	TPM2B_NV_PUBLIC NvPublic;
	TPM2B_NAME NvName;
#ifdef BUILD_ANDROID_THINGS
	TPMI_RH_NV_INDEX start_nv_index = NV_INDEX_AT_PERM_ATTR;
#else
	TPMI_RH_NV_INDEX start_nv_index = NV_INDEX_TRUSTYOS_SEED;
#endif
	UINT32 index_offset = 0;
	attribute_matrix_t matrix, expected_table[MAX_NV_NUMBER];

	memcpy(expected_table, config_table, sizeof(attribute_matrix_t) * MAX_NV_NUMBER);
	for(index_offset = 0; index_offset < MAX_NV_NUMBER; index_offset ++) {
		ret = Tpm2NvReadPublic(start_nv_index + index_offset, &NvPublic, &NvName);
		if(EFI_ERROR(ret)) {
			error(L"Tpm2NvReadPublic TPM NV index %x ret: %d", start_nv_index + index_offset, ret);
			return ret;
		}
		matrix.nv_index = NvPublic.nvPublic.nvIndex;
		/* TPMA_NV_WRITTEN = 1, Index has been written.
		TPMA_NV_WRITELOCKED =1, Index cannot be written.
		Check these two additional attributes after provision. They are set by TPM.
		*/
		expected_table[index_offset].attribute.TPMA_NV_WRITTEN = 1;
		expected_table[index_offset].attribute.TPMA_NV_WRITELOCKED = 1;
		matrix.attribute = NvPublic.nvPublic.attributes;
		if(memcmp(&matrix, &(expected_table[index_offset]), sizeof(attribute_matrix_t)))
			return EFI_DEVICE_ERROR;
	}

	return EFI_SUCCESS;
}

EFI_STATUS tpm2_fuse_provision_seed(void)
{
	EFI_STATUS ret = EFI_SUCCESS;

	// Check secure boot is enabled
	if (!is_platform_secure_boot_enabled()) {
		error(L"Secure boot is disabled, does not fuse trusty seed to TPM");
		return EFI_SECURITY_VIOLATION;
	}

	ret = tpm2_delete_index(NV_INDEX_TRUSTYOS_SEED);
	if (EFI_ERROR(ret) && ret != EFI_NOT_FOUND) {
		error(L"failed to delete NV_INDEX_TRUSTYOS_SEED");
		return ret;
	}
	return tpm2_fuse_random_data(NV_INDEX_TRUSTYOS_SEED, TRUSTY_SEED_SIZE);
}

EFI_STATUS tpm2_fuse_provision_rpmb_key(void)
{
	EFI_STATUS ret = EFI_SUCCESS;

	// Check secure boot is enabled
	if (!is_platform_secure_boot_enabled()) {
		error(L"Secure boot is disabled, does not fuse RPMB key to TPM");
		return EFI_SECURITY_VIOLATION;
	}

	ret = tpm2_delete_index(NV_INDEX_RPMB_KEY);
	if (EFI_ERROR(ret) && ret != EFI_NOT_FOUND) {
		error(L"failed to delete NV_INDEX_RPMB_KEY");
		return ret;
	}
	return tpm2_fuse_random_data(NV_INDEX_RPMB_KEY, NV_INDEX_RPMB_KEY_SIZE);
}

EFI_STATUS tpm2_fuse_lock_owner(void)
{
	TPMS_AUTH_COMMAND session_data = {0};
	TPM2B_AUTH owner_auth;
	EFI_STATUS ret;

	/* Check the provison and secure boot status */
	if (!is_platform_secure_boot_enabled() || EFI_ERROR(check_provision_status())) {
		error(L"Provision is not completed or secure boot is not enabled, DO NOT LOCK OWNER");
		return EFI_DEVICE_ERROR;
	}

	session_data.sessionHandle = TPM_RS_PW;
	session_data.nonce.size = 0;
	session_data.hmac.size = 0;
	*((UINT8 *)((void *)&session_data.sessionAttributes)) = 0;

	ret = Tpm2GetRandom(DIGEST_SIZE, &owner_auth);
	if(EFI_ERROR(ret)) {
		error(L"failed to get random: %d", ret);
		goto out;
	}

	ret = Tpm2HierarchyChangeAuth(TPM_RH_OWNER, &session_data, &owner_auth);
	if(EFI_ERROR(ret)) {
		error(L"failed to Tpm2HierarchyChangeAuth: %d", ret);
		goto out;
	}

out:
	memset(owner_auth.buffer, 0, DIGEST_SIZE);
	return ret;
}

#ifndef USER
EFI_STATUS tpm2_show_index(UINT32 index, uint8_t *out_buffer, UINTN out_buffer_size)
{
	EFI_STATUS ret;
	TPM2B_NV_PUBLIC NvPublic;
	TPM2B_NAME NvName;

	ret = Tpm2NvReadPublic(index, &NvPublic, &NvName);
	if (EFI_ERROR(ret)) {
		error(L"Read TPM NV index %x ret: %d", index, ret);
		return ret;
	}
	efi_snprintf(out_buffer, out_buffer_size, (CHAR8 *)
		"Read TPM NV index %x success, public size: %d, nvIndex: 0x%x, nameAlg: %d, attributes: 0x%x, data size: %d, name size: %d",
		index,
		NvPublic.size, NvPublic.nvPublic.nvIndex, NvPublic.nvPublic.nameAlg,
		NvPublic.nvPublic.attributes, NvPublic.nvPublic.dataSize, NvName.size);

	return EFI_SUCCESS;
}
#endif // USER

EFI_STATUS tpm2_delete_index(UINT32 index)
{
	EFI_STATUS ret = Tpm2NvUndefineSpace(TPM_RH_OWNER, index, NULL);

	if (EFI_ERROR(ret))
		error(L"Delete TPM NV index failed, index: %x, ret: %d", index, ret);

	return ret;
}

EFI_STATUS extend_trusty_seed_pcr_policy()
{
	EFI_STATUS                ret;
	TPML_DIGEST_VALUES        Digests;
	UINT32                    DigestSize = 0;
	TPMI_DH_PCR               PcrHandle;

	Digests.count = 1;
	Digests.digests[0].hashAlg = TPM_ALG_SHA256;
	PcrHandle = PCR_7;

	DigestSize = GetHashSizeFromAlgo (Digests.digests[0].hashAlg);
	memset((UINT8*)&Digests.digests[0].digest, 0, DigestSize);
	ret =  Tpm2PcrExtend(PcrHandle, &Digests);
	if (EFI_ERROR(ret)) {
		error(L"Extend PCR fail");
		return ret;
	}
	return EFI_SUCCESS;
}

EFI_STATUS tpm2_read_trusty_seed(UINT8 seed[TRUSTY_SEED_SIZE])
{
	EFI_STATUS ret;
	EFI_STATUS ret2;
	UINT16 seed_size = TRUSTY_SEED_SIZE;

	ret = tpm2_read_nvindex(NV_INDEX_TRUSTYOS_SEED, &seed_size, seed, 0);
	ret2 = tpm2_read_lock_nvindex(NV_INDEX_TRUSTYOS_SEED);  // Lock anyway
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Read trusty seed failed");
		goto out;
	}
	if (EFI_ERROR(ret2)) {
		efi_perror(ret2, L"Security error! Set trusty seed read lock failed!");
		// die?
		ret = ret2;
		goto out;
	}
	if (seed_size != TRUSTY_SEED_SIZE) {
		efi_perror(ret, L"Read trusty seed failed, read %d bytes data, but expect %d",
				TRUSTY_SEED_SIZE, seed_size);
		ret = EFI_COMPROMISED_DATA;
		goto out;
	}

	debug(L"Success read RPMB key from TPM");

	return EFI_SUCCESS;

out:
	memset(seed, 0, TRUSTY_SEED_SIZE);
	return ret;
}

EFI_STATUS tpm2_read_rpmb_key(UINT8 *rpmb_key, UINTN *key_size)
{
	EFI_STATUS ret;
	EFI_STATUS ret2;
	UINT16 real_key_size = min(*key_size, NV_INDEX_RPMB_KEY_SIZE);

	if (*key_size < 32)
		return EFI_INVALID_PARAMETER;

	ret = tpm2_read_nvindex(NV_INDEX_RPMB_KEY, &real_key_size, rpmb_key, 0);
	ret2 = tpm2_read_lock_nvindex(NV_INDEX_RPMB_KEY);  // Lock anyway
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Read RPMB key failed");
		goto out;
	}
	if (EFI_ERROR(ret2)) {
		efi_perror(ret2, L"Security error! Set RPMB key read lock failed!");
		// die?
		ret = ret2;
		goto out;
	}
	*key_size = real_key_size;

	return EFI_SUCCESS;

out:
	memset(rpmb_key, 0, real_key_size);
	return ret;
}

#ifdef BUILD_ANDROID_THINGS
EFI_STATUS tpm2_fuse_perm_attr(void *data, uint32_t size)
{
	EFI_STATUS ret;
	UINT16 config_index;

	if (size > 2048) {
		error(L"AT Permanent attributes exceeds maximum size");
		return EFI_INVALID_PARAMETER;
	}

	config_index = NV_INDEX_AT_PERM_ATTR - config_table[0].nv_index;
	ret = create_index_and_write_lock(NV_INDEX_AT_PERM_ATTR, config_table[config_index].attribute, size, data);
	if (EFI_ERROR(ret))
		return ret;

	debug(L"AT Permanent attributes fused succesfully");
	return ret;
}
#endif

EFI_STATUS tpm2_fuse_vbmeta_key_hash(void *data, uint32_t size)
{
	EFI_STATUS ret;
	UINT16 config_index;

	if (size != 32) {
		error(L"VBMETA Key Hash size is not 32 bytes");
		return EFI_INVALID_PARAMETER;
	}

	config_index = NV_INDEX_VBMETA_KEY_HASH - config_table[0].nv_index;
	ret = create_index_and_write_lock(NV_INDEX_VBMETA_KEY_HASH, config_table[config_index].attribute, size, data);
	if (EFI_ERROR(ret))
		return ret;

	debug(L"VBMETA Key Hash created successfully");
	return ret;
}

EFI_STATUS tpm2_fuse_bootloader_policy(void *data, uint32_t size)
{
	EFI_STATUS ret;
	UINT16 config_index;
	UINT64 set_bits = 0;

	if (size != sizeof(set_bits)) {
		error(L"bootloader policy size is not 8 bytes");
		return EFI_INVALID_PARAMETER;
	}

	config_index = NV_INDEX_FB_BL_POLICY - config_table[0].nv_index;
	ret = tpm2_create_nvindex(NV_INDEX_FB_BL_POLICY, config_table[config_index].attribute, sizeof(set_bits));
	if (EFI_ERROR(ret) && (ret != EFI_ALREADY_STARTED))
		return ret;

	memcpy(&set_bits, data, size);
	ret = tpm2_set_nvbits(NV_INDEX_FB_BL_POLICY, set_bits);
	if (EFI_ERROR(ret))
		return ret;

	debug(L"Bootloader policy created successfully");
	return ret;
}

EFI_STATUS tpm2_fuse_bootloader(void)
{
	EFI_STATUS ret;
	UINT16 config_index;
	BYTE data[NV_INDEX_BOOTLOADER_SIZE];
	BYTE data_read[NV_INDEX_BOOTLOADER_SIZE];
	UINT16 data_read_size = NV_INDEX_BOOTLOADER_SIZE;
	tpm2_bootloader_t *bootloader = (tpm2_bootloader_t *)data;

	config_index = NV_INDEX_BOOTLOADER - config_table[0].nv_index;
	ret = tpm2_create_nvindex(NV_INDEX_BOOTLOADER, config_table[config_index].attribute, NV_INDEX_BOOTLOADER_SIZE);
	if (EFI_ERROR(ret)) {
		error(L"NV Index failed to create, index: 0x%x, size: %d, ret: %d",
				NV_INDEX_BOOTLOADER, NV_INDEX_BOOTLOADER_SIZE, ret);
		return ret;
	}

	memset(data, 0, sizeof(data));
	bootloader->struct_ver = NV_INDEX_BOOTLOADER_STRUCT_VER;
	bootloader->lock_state = LOCKED; // default status is locked

	// Read the data again to verify it
	ret = tpm2_write_nvindex(NV_INDEX_BOOTLOADER, NV_INDEX_BOOTLOADER_SIZE, data, 0);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Write bootloader nv index failed, ret: %d, ret");
		goto out;
	}
	debug(L"Success create and write bootloader nv index");

	// Read the data again to verify it
	ret = tpm2_read_nvindex(NV_INDEX_BOOTLOADER, &data_read_size, data_read, 0);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Read bootloader nv index back failed just after write it");
		goto out;
	}

	if (memcmp(data, data_read, sizeof(data))) {
		error(L"Security error! Read bootloader nv index back but verify failed!");
		ret = EFI_SECURITY_VIOLATION;
		goto out;
	}

out:
	return ret;
}

EFI_STATUS tpm2_check_bootloader_index(void)
{
	EFI_STATUS ret;
	TPM2B_NV_PUBLIC NvPublic;
	TPM2B_NAME NvName;
	UINT8 state;

	// Check the SEED nvindex
	ret = Tpm2NvReadPublic(NV_INDEX_BOOTLOADER, &NvPublic, &NvName);
	if (!EFI_ERROR(ret)) {
		// Success
		if (NvPublic.nvPublic.dataSize == NV_INDEX_BOOTLOADER_SIZE) {
			debug(L"Bootloader nv index already fused");

			// Try to read current state
			return tpm2_read_device_state(&state);
		}

		// Find it, but the data is empty wrong.
		error(L"Find bootloader nv index, but the data is wrong");
		return EFI_COMPROMISED_DATA;
	}

	if (ret != EFI_NOT_FOUND) {
		efi_perror(ret, L"Read bootloader nv index failed");
		return ret;
	}

	// Can't find it, try to init it now
	ret = tpm2_fuse_bootloader();
	if (EFI_ERROR(ret))
		efi_perror(ret, L"Failed to fuse trusty seed");

	return ret;
}

EFI_STATUS tpm2_check_rpmb_key_index(void)
{
	EFI_STATUS ret;
	TPM2B_NV_PUBLIC NvPublic;
	TPM2B_NAME NvName;

	// Check the RPMB key nvindex
	ret = Tpm2NvReadPublic(NV_INDEX_RPMB_KEY, &NvPublic, &NvName);
	if (!EFI_ERROR(ret)) {
		// Success
		if (NvPublic.nvPublic.dataSize == NV_INDEX_RPMB_KEY_SIZE) {
			debug(L"RPMB key nv index already fused");

			return EFI_SUCCESS;
		}

		// Find it, but the data is empty wrong.
		error(L"Find RPMB key nv index, but the data is wrong");
		return EFI_COMPROMISED_DATA;
	}

	if (ret != EFI_NOT_FOUND) {
		efi_perror(ret, L"Read RPMB key nv index failed");
		return ret;
	}

	// Can't find it, try to init it now
	ret = tpm2_fuse_random_data(NV_INDEX_RPMB_KEY, NV_INDEX_RPMB_KEY_SIZE);
	if (EFI_ERROR(ret))
		efi_perror(ret, L"Failed to fuse RPMB key");

	return ret;
}

EFI_STATUS tpm2_check_trusty_seed_index(void)
{
	EFI_STATUS ret;
	TPM2B_NV_PUBLIC NvPublic;
	TPM2B_NAME NvName;

	// Check the SEED nvindex
	ret = Tpm2NvReadPublic(NV_INDEX_TRUSTYOS_SEED, &NvPublic, &NvName);
	if (!EFI_ERROR(ret)) {
		// Success
		if (NvPublic.nvPublic.dataSize == TRUSTY_SEED_SIZE) {
			debug(L"Trusty seed already fused");

			return EFI_SUCCESS;
		}

		// Find it, but the data is empty wrong.
		error(L"Find trusty seed nv index, but the data is wrong");
		return EFI_COMPROMISED_DATA;
	}

	if (ret != EFI_NOT_FOUND) {
		efi_perror(ret, L"Read trusty seed index failed");
		return ret;
	}

	// Can't find it, try to init it now
	ret = tpm2_fuse_random_data(NV_INDEX_TRUSTYOS_SEED, TRUSTY_SEED_SIZE);
	if (EFI_ERROR(ret))
		efi_perror(ret, L"Failed to fuse trusty seed");

	return ret;
}

EFI_STATUS tpm2_read_device_state(UINT8 *state)
{
	EFI_STATUS ret;
	UINT16 data_size = sizeof(UINT8);

	ret = tpm2_read_nvindex(NV_INDEX_BOOTLOADER, &data_size, (BYTE *)state, 1);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Read device state from TPM failed");
		goto out;
	}

	if (data_size != sizeof(UINT8)) {
		error(L"Read device state from TPM, but data size is wrong: %d", data_size);
		ret = EFI_COMPROMISED_DATA;
		goto out;
	}
	debug(L"Read device state from TPM success, state: %d", *state);

out:
	return ret;
}

EFI_STATUS tpm2_write_device_state(UINT8 state)
{
	EFI_STATUS ret;

	ret = tpm2_write_nvindex(NV_INDEX_BOOTLOADER, sizeof(UINT8), (BYTE *)&state, 1);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Write device state %d to TPM failed", state);
		goto out;
	}

	debug(L"Write device state %d to TPM success", state);
out:
	return ret;
}

EFI_STATUS tpm2_read_rollback_index(size_t rollback_index_slot, uint64_t *out_rollback_index)
{
	EFI_STATUS ret;
	UINT16 data_size = sizeof(uint64_t);

	if (rollback_index_slot >= MAX_ROLLBACK_INDEX_SLOT_TPM) {
		error(L"The rollback index slot is too large to write into TPM: %d", rollback_index_slot);
		ret = EFI_INVALID_PARAMETER;
		goto out;
	}

	ret = tpm2_read_nvindex(NV_INDEX_BOOTLOADER, &data_size, (BYTE *)out_rollback_index, rollback_index_slot * sizeof(uint64_t) + 8);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Read rollback index from TPM failed");
		goto out;
	}

	if (data_size != sizeof(uint64_t)) {
		error(L"Read rollback index from TPM, but data size is wrong: %d", data_size);
		ret = EFI_COMPROMISED_DATA;
		goto out;
	}

	debug(L"Read rollback index from TPM success, index slot: %d, index: 0x%llx", rollback_index_slot, *out_rollback_index);
out:
	return ret;
}

EFI_STATUS tpm2_write_rollback_index(size_t rollback_index_slot, uint64_t rollback_index)
{
	EFI_STATUS ret;

	if (rollback_index_slot >= MAX_ROLLBACK_INDEX_SLOT_TPM) {
		error(L"The rollback index slot is too large to write into TPM: %d", rollback_index_slot);
		ret = EFI_INVALID_PARAMETER;
		goto out;
	}

	ret = tpm2_write_nvindex(NV_INDEX_BOOTLOADER, sizeof(uint64_t), (BYTE *)&rollback_index, rollback_index_slot * sizeof(uint64_t) + 8);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Write rollback index failed");
		goto out;
	}

	debug(L"Write rollback index to TPM success, index slot: %d, index: 0x%llx", rollback_index_slot, rollback_index);
out:
	return ret;
}

EFI_STATUS tpm2_init(void)
{
	EFI_STATUS ret;

	ret = tpm2_check_lockauth();
	if (EFI_ERROR(ret)) {
		// The BIOS does not support TPM protocol, or the device has not TPM device
		return ret;
	}

	ret = tpm2_check_bootloader_index();
	if (EFI_ERROR(ret))
		return ret;

	ret = tpm2_check_rpmb_key_index();
	if (EFI_ERROR(ret))
		return ret;

	return tpm2_check_trusty_seed_index();
}

EFI_STATUS tpm2_end(void)
{
	EFI_STATUS ret;
	tpm2_write_lock_nvindex(NV_INDEX_BOOTLOADER);
	tpm2_read_lock_nvindex(NV_INDEX_BOOTLOADER);
	tpm2_read_lock_nvindex(NV_INDEX_TRUSTYOS_SEED);
	tpm2_read_lock_nvindex(NV_INDEX_RPMB_KEY);

	ret = extend_trusty_seed_pcr_policy();
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Extend trusty seed pcr policy fail");
	}

	return EFI_SUCCESS;
}
