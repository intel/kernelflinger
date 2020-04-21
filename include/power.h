/*
 * Copyright (c) 2013, Intel Corporation
 * All rights reserved.
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
 * This file defines bootlogic data structures, try to keep it without
 * any external definitions in order to ease export of it.
 */

#ifndef _POWER_H_
#define _POWER_H_

/** RSCI Definitions **/

/* Wake sources */
enum wake_sources {
	WAKE_NOT_APPLICABLE,
	WAKE_BATTERY_INSERTED,
	WAKE_USB_CHARGER_INSERTED,
	WAKE_ACDC_CHARGER_INSERTED,
	WAKE_POWER_BUTTON_PRESSED,
	WAKE_RTC_TIMER,
	WAKE_BATTERY_REACHED_IA_THRESHOLD,
	WAKE_ERROR = -1,
};

enum reset_sources {
	RESET_NOT_APPLICABLE,
	RESET_OS_INITIATED,
	RESET_FORCED,
	RESET_FW_UPDATE,
	RESET_KERNEL_WATCHDOG,
	RESET_SECURITY_WATCHDOG,
	RESET_SECURITY_INITIATED,
	RESET_EC_WATCHDOG = 8,
	RESET_PMIC_WATCHDOG,
	RESET_SHORT_POWER_LOSS = 11,
	RESET_PLATFORM_SPECIFIC,
	RESET_UNKNOWN = 0xFF,
	RESET_ERROR = -1,
};

enum reset_types {
	NOT_APPLICABLE,
	WARM_RESET,
	COLD_RESET,
	GLOBAL_RESET = 7
};

enum wake_sources rsci_get_wake_source(void);

enum reset_sources rsci_get_reset_source(void);

enum reset_types rsci_get_reset_type(void);

UINT32 rsci_get_reset_extra_info(void);

#if DEBUG_MESSAGES
const CHAR16 *wake_source_string(enum wake_sources ws);
const CHAR16 *reset_source_string(enum reset_sources rs);
const CHAR16 *reset_type_string(enum reset_types rt);
#endif

#endif /* _POWER_H_ */
