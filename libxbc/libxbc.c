/*
 * Copyright (C) 2021 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "libxbc.h"

/*
 * Simple checksum for a buffer.
 *
 * @param addr pointer to the start of the buffer.
 * @param size size of the buffer in bytes.
 * @return check sum result.
 */
static uint32_t checksum(const unsigned char* const buffer, uint32_t size) {
    uint32_t sum = 0;
    for (uint32_t i = 0; i < size; i++) {
        sum += buffer[i];
    }
    return sum;
}

/*
 * Check if the bootconfig trailer is present within the bootconfig section.
 *
 * @param bootconfig_end_addr address of the end of the bootconfig section. If
 *        the trailer is present, it will be directly preceding this address.
 * @return true if the trailer is present, false if not.
 */
static BOOLEAN isTrailerPresent(uint64_t bootconfig_end_addr) {
    return !strncmp((CHAR8 *)(bootconfig_end_addr - BOOTCONFIG_MAGIC_SIZE),
                    BOOTCONFIG_MAGIC, BOOTCONFIG_MAGIC_SIZE);
}

/*
 * Add a string of boot config parameters to memory appended by the trailer.
 */
int32_t addBootConfigParameters(char* params, uint32_t params_size,
    uint64_t bootconfig_start_addr, uint32_t bootconfig_size) {
    if (!params || !bootconfig_start_addr) {
        return -1;
    }
    if (params_size == 0) {
        return 0;
    }
    int32_t applied_bytes = 0;
    int32_t new_size = 0;
    uint64_t end = bootconfig_start_addr + bootconfig_size;

    if (isTrailerPresent(end)) {
      end -= BOOTCONFIG_TRAILER_SIZE;
      applied_bytes -= BOOTCONFIG_TRAILER_SIZE;
      memcpy_s(&new_size, BOOTCONFIG_SIZE_SIZE, (void *)end, BOOTCONFIG_SIZE_SIZE);
    } else {
      new_size = bootconfig_size;
    }

    // params
    memcpy_s((void*)end, params_size, params, params_size);

    applied_bytes += params_size;
    applied_bytes += addBootConfigTrailer(bootconfig_start_addr,
        bootconfig_size + applied_bytes);

    return applied_bytes;
}

/*
 * Add boot config trailer.
 */
int32_t addBootConfigTrailer(uint64_t bootconfig_start_addr,
                            uint32_t bootconfig_size) {
    if (!bootconfig_start_addr) {
        return -1;
    }
    if (bootconfig_size == 0) {
        return 0;
    }
    uint64_t end = bootconfig_start_addr + bootconfig_size;

    if (isTrailerPresent(end)) {
        // no need to overwrite the current trailers
        return 0;
    }

    // size
    memcpy_s((void *)(end), BOOTCONFIG_SIZE_SIZE, &bootconfig_size, BOOTCONFIG_SIZE_SIZE);

    // checksum
    uint32_t sum =
        checksum((unsigned char*)bootconfig_start_addr, bootconfig_size);
    memcpy_s((void *)(end + BOOTCONFIG_SIZE_SIZE), BOOTCONFIG_CHECKSUM_SIZE, &sum,
        BOOTCONFIG_CHECKSUM_SIZE);

    // magic
    memcpy_s((void *)(end + BOOTCONFIG_SIZE_SIZE + BOOTCONFIG_CHECKSUM_SIZE),
           BOOTCONFIG_MAGIC_SIZE, BOOTCONFIG_MAGIC, BOOTCONFIG_MAGIC_SIZE);

    return BOOTCONFIG_TRAILER_SIZE;
}
