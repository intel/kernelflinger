/*
 * Copyright (c) 2015, Intel Corporation
 * All rights reserved.
 *
 * Author: Andrew Boie <andrew.p.boie@intel.com>
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

#ifndef KERNELFLINGER_VERSION_H
#define KERNELFLINGER_VERSION_H

#define WIDE_STR2(x) L ## x
#define WIDE_STR(x) WIDE_STR2(x)

#if defined(USER)
#define BUILD_VARIANT           ""
#elif defined(USERDEBUG)
#define BUILD_VARIANT           "-userdebug"
#else
#define BUILD_VARIANT           "-eng"
#endif

#ifdef FASTBOOT_FOR_NON_ANDROID
#define KERNELFLINGER_VERSION_8	"fastboot-NonAndroid-1.0" BUILD_VARIANT
#else
#define KERNELFLINGER_VERSION_8	"kernelflinger-07.02" BUILD_VARIANT
#endif
#define KERNELFLINGER_VERSION   WIDE_STR(KERNELFLINGER_VERSION_8)

#endif
