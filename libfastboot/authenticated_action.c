/*
 * Copyright (c) 2015, Intel Corporation
 * All rights reserved.
 *
 * Author: Jeremy Compostella <jeremy.compostella@intel.com>
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

#include <lib.h>
#include <vars.h>
#include <security.h>

#include "authenticated_action.h"
#include "fastboot_flashing.h"

#define NONCE_RANDOM_BYTE_LENGTH	16
#define NONCE_EXPIRATION_SEC		5 * 60 * 60;

typedef struct action {
	UINT8 id;
	const char *name;
	EFI_STATUS (*do_it)(void);
} action_t;

static UINT8 VERSION = 0;
static CHAR8 current_nonce[3 + NONCE_RANDOM_BYTE_LENGTH * 2 + 4 + SERIALNO_MAX_SIZE + 1];
static const struct action *current_action;
static UINT64 expiration_ctime;

static EFI_STATUS force_unlock(void)
{
	return change_device_state(UNLOCKED, FALSE);
}

static const action_t ACTIONS[] = {
	{ 0, "force-unlock", force_unlock }
};

static void clear_nonce(void)
{
	expiration_ctime = 0;
	memset_s(current_nonce, sizeof(current_nonce), 0, sizeof(current_nonce));
}

char *authenticated_action_new_nonce(char *action_name)
{
	CHAR8 random[NONCE_RANDOM_BYTE_LENGTH];
	CHAR8 randomstr[NONCE_RANDOM_BYTE_LENGTH * 2 + 1];
	const struct action *action = NULL;
	EFI_STATUS ret;
	EFI_TIME now;
	UINTN i;

	clear_nonce();

	for (i = 0; i < ARRAY_SIZE(ACTIONS); i++)
		if (!strcmp((CHAR8 *)ACTIONS[i].name, (CHAR8 *)action_name)) {
			action = &ACTIONS[i];
			break;
		}

	if (!action)
		return NULL;

	ret = uefi_call_wrapper(RT->GetTime, 2, &now, NULL);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to get the current time");
		return NULL;
	}

	if (efi_time_to_ctime(&now) == 0) {
		error(L"Failed to get a valid current timestamp");
		return NULL;
	}

	ret = generate_random_numbers(random, sizeof(random));
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to generate random numbers");
		return NULL;
	}

	ret = bytes_to_hex_stra(random, sizeof(random), randomstr, sizeof(randomstr));
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to convert bytes to hexadecimal string");
		return NULL;
	}

	current_action = action;
	expiration_ctime = efi_time_to_ctime(&now) + NONCE_EXPIRATION_SEC;
	efi_snprintf(current_nonce, sizeof(current_nonce),
		     (CHAR8 *)"%02x:%a:%02x:%a", VERSION, (CHAR8 *)get_serial_number(),
		     action->id, randomstr);

	return (char *)current_nonce;
}

static EFI_STATUS verify_payload(char *payload, UINTN size)
{
	char *host_random;

	if (payload[size - 1] != '\0' ||
	    memcmp(payload, current_nonce, strlen(current_nonce)) ||
	    payload[strlen(current_nonce)] != ':')
		goto parse_error;

	host_random = payload + strlen(current_nonce) + 1;
	if (strlen((CHAR8 *)host_random) != NONCE_RANDOM_BYTE_LENGTH * 2)
		goto parse_error;

	return EFI_SUCCESS;

parse_error:
	debug(L"Failed to parse the token response payload");
	return EFI_INVALID_PARAMETER;
}

static BOOLEAN nonce_is_expired()
{
	EFI_STATUS ret;
	EFI_TIME now;

	ret = uefi_call_wrapper(RT->GetTime, 2, &now, NULL);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to get the current time");
		goto expired;
	}

	if (efi_time_to_ctime(&now) >= expiration_ctime) {
		error(L"Nonce is expired");
		goto expired;
	}

	return FALSE;

expired:
	clear_nonce();
	return TRUE;
}

static EFI_STATUS verify_token(void *data, UINTN size)
{
	EFI_STATUS ret;
	unsigned char *oak_data;
	UINTN oak_size;
	char *payload;
	int payload_size;

	ret = get_oak_hash(&oak_data, &oak_size);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to read OAK EFI variable");
		return EFI_SECURITY_VIOLATION;
	}

	ret = verify_pkcs7(oak_data, oak_size, data, size,
			   (VOID **)&payload, &payload_size);
	FreePool(oak_data);
	if (EFI_ERROR(ret)) {
		error(L"PKCS7 Verification failed");
		return EFI_SECURITY_VIOLATION;
	}

	ret = verify_payload(payload, payload_size);
	FreePool(payload);
	if (EFI_ERROR(ret)) {
		error(L"Token payload verification failed");
		return EFI_SECURITY_VIOLATION;
	}

	return EFI_SUCCESS;
}

EFI_STATUS authenticated_action(void *data, UINTN size)
{
	EFI_STATUS ret;

	if (!data)
		return EFI_INVALID_PARAMETER;

	if (nonce_is_expired()) {
		memset_s(data, size, 0, size);
		return EFI_TIMEOUT;
	}

	ret = verify_token(data, size);
	clear_nonce();
	memset_s(data, size, 0, size);
	if (EFI_ERROR(ret))
		return ret;

	return current_action->do_it();
}
