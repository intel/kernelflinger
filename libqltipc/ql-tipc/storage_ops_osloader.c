/*
 * Copyright (C) 2016 The Android Open Source Project
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <trusty/rpmb.h>
#include <trusty/trusty_dev.h>
#include <trusty/util.h>

#include "libkernelflinger/protocol/SdHostIo.h"
#include "include/rpmb.h"
#include "include/rpmb_storage_common.h"

void *rpmb_storage_get_ctx(void)
{
    EFI_STATUS ret;
    static void* rpmb_dev;

    ret = get_storage_protocol(&rpmb_dev, NULL);
    if (EFI_ERROR(ret)) {
        trusty_error("Failed to get emmc.\n");
        return NULL;
    }

    return rpmb_dev;
}

/*
 *                rel_write       write      read
 * RPMB_READ          0             1        1~N
 * RPMB_WRITE        1~N            1         1
 * GET_COUNTER        0             1         1
 * PROGRAM_KEY        1             1         1
 */
int rpmb_storage_send(void *rpmb_dev, const void *rel_write_data, size_t rel_write_size,
                        const void *write_data, size_t write_size,
                        void *read_buf, size_t read_size)
{
    int ret = -1;

    if (rel_write_size) {
        int nframe = rel_write_size/RPMB_FRAME_SIZE;
        rpmb_data_frame rel_write_frame[nframe];
        memcpy(rel_write_frame, rel_write_data, sizeof(rel_write_frame));
        if (rel_write_frame[0].req_resp == swap16(RPMB_REQ_DATA_WRITE)) {
            if (write_size/RPMB_FRAME_SIZE &&
                   ((rpmb_data_frame *)write_data)->req_resp
                       == swap16(RPMB_REQ_RESULT_READ)) {
                ret = write_rpmb_data_frame(rpmb_dev, rel_write_frame, nframe,
                                 read_buf, read_size/RPMB_FRAME_SIZE);
            } else {
                ret = write_rpmb_data_frame(rpmb_dev, rel_write_frame, nframe, NULL, 0);
            }
        } else if (rel_write_frame[0].req_resp
                                    == swap16(RPMB_REQ_PROGRAM_KEY)) {
            if (write_size/RPMB_FRAME_SIZE &&
                   ((rpmb_data_frame *)write_data)->req_resp
                        == swap16(RPMB_REQ_RESULT_READ)) {
                ret = program_rpmb_key_frame(rpmb_dev, rel_write_frame, 1,
                                       read_buf, read_size/RPMB_FRAME_SIZE);
            } else {
                ret = program_rpmb_key_frame(rpmb_dev, rel_write_frame, 1, NULL, 0);
            }
        }
    } else if (write_size) {
        rpmb_data_frame write_frame[write_size/RPMB_FRAME_SIZE];
        memcpy(write_frame, write_data, sizeof(write_frame));
        if (write_frame[0].req_resp == swap16(RPMB_REQ_DATA_READ)) {
            ret = read_rpmb_data_frame(rpmb_dev, write_frame, 1,
                            read_buf, read_size/RPMB_FRAME_SIZE);
        }
        else if (write_frame[0].req_resp == swap16(RPMB_REQ_GET_COUNTER)) {
            ret = get_rpmb_counter_frame(rpmb_dev, write_frame, 1, read_buf, 1);
        }
    }

    return ret;
}
