/*
 * Copyright (C) 2017 The Android Open Source Project
 * Copyright (C) 2017 Intel Corporation
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

#include <openssl/hmac.h>

#include <trusty/rpmb.h>
#include <trusty/rpmb_sim.h>
#include <trusty/util.h>
#include <interface/storage/storage.h>

#include "libkernelflinger/protocol/SdHostIo.h"
#include "include/rpmb.h"

struct rpmb_packet {
    uint8_t              pad[196];
    uint8_t              key_mac[32];
    uint8_t              data[256];
    uint8_t              nonce[16];
    uint32_t             write_counter;
    uint16_t             address;
    uint16_t             block_count;
    uint16_t             result;
    uint16_t             req_resp;
};

enum rpmb_response {
    RPMB_RESP_PROGRAM_KEY               = 0x0100,
    RPMB_RESP_GET_COUNTER               = 0x0200,
    RPMB_RESP_DATA_WRITE                = 0x0300,
    RPMB_RESP_DATA_READ                 = 0x0400,
};

/*
 * 0~6 is magic
 * 7~38 is rpmb key
 * 39~41 is write counter
 */
#define KEY_MAGIC               "key_sim"
#define KEY_MAGIC_ADDR          0
#define KEY_MAGIC_LENGTH        7

#define KEY_ADDR                7
#define KEY_LENGTH              32

#define WRITER_COUNTER_ADDR     39

/* teedata size is 32M. But here only 256K~4M are available to use. */
#define TEEDATA_SIZE            (4*1024*1024) //4M
#define TEEDATA_BLOCK_COUNT     (TEEDATA_SIZE/256)



static int rpmb_sim_read(void *buffer, uint32_t size, uint32_t offset)
{
    int ret = simulate_read_rpmb_data(offset, buffer, size);
    if (EFI_ERROR(ret)) {
        trusty_error("rpmb_sim_read: failed.\n");
        return -1;
    }

    return 0;
}

static int rpmb_sim_write(void *buffer, uint32_t size, uint32_t offset)
{
    int ret = simulate_write_rpmb_data(offset, buffer, size);

    if (EFI_ERROR(ret)) {
        trusty_error("rpmb_sim_write: failed.\n");
        return -1;
    }

    return 0;
}

static int get_counter(uint32_t *counter)
{
    int rc = 0;

    rc = rpmb_sim_read(counter, sizeof(*counter), WRITER_COUNTER_ADDR);
    if (rc < 0) {
        trusty_error("get_counter failed.\n");
        return -1;
    }

    swap32(*counter);

    return 0;
}

static int set_counter(const uint32_t *counter)
{
    int rc = 0;
    uint32_t cnt = *counter;

    swap32(cnt);
    rc = rpmb_sim_write(&cnt, sizeof(cnt), WRITER_COUNTER_ADDR);
    if (rc < 0) {
        trusty_error("set_counter failed.\n");
        return -1;
    }

    return 0;
}

static int is_key_programmed(void)
{
    int rc = 0;
    uint8_t magic[KEY_MAGIC_LENGTH] = {0};

    rc = rpmb_sim_read(magic, KEY_MAGIC_LENGTH, KEY_MAGIC_ADDR);
    if (rc < 0) {
        trusty_error("is_key_programmed read magic failed.\n");
        return 0;
    }

    if (memcmp(KEY_MAGIC, magic, KEY_MAGIC_LENGTH))
        return 0;

    return 1;
}

int is_use_sim_rpmb(void)
{
    return is_key_programmed();
}

static int get_key(uint8_t *key)
{
    int rc = 0;

    rc = rpmb_sim_read(key, 32, KEY_ADDR);
    if (rc < 0) {
        trusty_error("get_key failed.\n");
        return -1;
    }

    return 0;
}

static int program_key(const uint8_t *key)
{
    int rc = 0;
    uint8_t key_temp[32];

    memcpy(&key_temp, key, 32);
    rc = rpmb_sim_write(key_temp, 32, KEY_ADDR);
    if (rc < 0) {
        trusty_error("program_key failed at set key.\n");
        return -1;
    }

    rc = rpmb_sim_write(KEY_MAGIC, KEY_MAGIC_LENGTH, KEY_MAGIC_ADDR);
    if (rc < 0) {
        trusty_error("program_key failed at set magic.\n");
        return -1;
    }

    return 0;
}

static int rpmb_mac(uint8_t *key, const struct rpmb_packet *packet,
                    int packet_count, uint8_t *mac)
{
    int i;
    int hmac_ret;
    unsigned int md_len;
    HMAC_CTX hmac_ctx;

    HMAC_CTX_init(&hmac_ctx);
    hmac_ret = HMAC_Init_ex(&hmac_ctx, key, 32, EVP_sha256(), NULL);
    if (!hmac_ret) {
        trusty_error("HMAC_Init_ex failed\n");
        goto err;
    }

    for (i = 0; i < packet_count; i++) {
        hmac_ret = HMAC_Update(&hmac_ctx, packet[i].data, 284);
        if (!hmac_ret) {
            trusty_error("HMAC_Update failed\n");
            goto err;
        }
    }

    hmac_ret = HMAC_Final(&hmac_ctx, mac, &md_len);
    if (md_len != 32) {
        trusty_error("bad md_len %d != %zd\n", md_len, 32);
        hmac_ret = 0;
        goto err;
    }

    if (!hmac_ret) {
        trusty_error("HMAC_Final failed\n");
        goto err;
    }

err:
    HMAC_CTX_cleanup(&hmac_ctx);

    return hmac_ret ? 0 : -1;
}

static int rpmb_program_key(const struct rpmb_packet *in_frame, uint32_t in_cnt,
                            struct rpmb_packet *out_frame, uint32_t out_cnt)
{
    int ret = 0;
    int err = RPMB_RES_WRITE_FAILURE;
    uint32_t counter = 0;

    if (in_cnt == 0  || in_frame == NULL)
        return -1;

    if (is_key_programmed())
        err = RPMB_RES_GENERAL_FAILURE;
    else
        ret = program_key(in_frame->key_mac);

    if (ret)
        goto out;

    ret = set_counter(&counter);
    if (ret)
        goto out;

    err = RPMB_RES_OK;

out:
    if (out_frame) {
        memset(out_frame, 0, out_cnt*sizeof(*out_frame));
        out_frame->req_resp = swap16(RPMB_RESP_PROGRAM_KEY);
        out_frame->result = swap16(err);
    }

    return ret;
}

static int rpmb_write(const struct rpmb_packet *in_frame, uint32_t in_cnt,
                      struct rpmb_packet *out_frame, uint32_t out_cnt)
{
    int ret = 0;
    int err = RPMB_RES_WRITE_FAILURE;
    uint32_t i;
    uint8_t key[32];
    uint8_t mac[32];
    uint32_t counter;
    uint16_t addr;
    uint16_t block_count;
    uint8_t data[256*in_cnt];

    if (in_cnt == 0  || in_frame == NULL)
        return -1;

    if (in_frame[0].req_resp != swap16(RPMB_REQ_DATA_WRITE))
        return -1;

    if (in_cnt > 2) {
        err = RPMB_RES_GENERAL_FAILURE;
        goto out;
    }

    addr = swap16(in_frame[0].address);
    block_count  = swap16(in_frame[0].block_count);

    if (addr >= TEEDATA_BLOCK_COUNT) {
        err = RPMB_RES_ADDRESS_FAILURE;
        goto out;
    }

    if (addr + block_count > TEEDATA_BLOCK_COUNT)
        goto out;

    if (block_count == 0 || block_count > in_cnt) {
        ret = -1;
        err = RPMB_RES_GENERAL_FAILURE;
        goto out;
    }

    if (!is_key_programmed()) {
        err = RPMB_RES_NO_AUTH_KEY_PROGRAM;
        goto out;
    }

    if (get_counter(&counter))
        goto out;

    if (counter == 0xFFFFFFFF) {
        err = RPMB_RES_WRITE_COUNTER_EXPIRED;
        goto out;
    }

    if (counter != swap32(in_frame[0].write_counter)) {
        err = RPMB_RES_COUNTER_FAILURE;
        goto out;
    }

    if (get_key(key)) {
        err = RPMB_RES_GENERAL_FAILURE;
        goto out;
    }

    if (rpmb_mac(key, in_frame, in_cnt, mac)) {
        err = RPMB_RES_GENERAL_FAILURE;
        goto out;
    }

    if (memcmp(in_frame[in_cnt - 1].key_mac, mac, 32)) {
        trusty_error("rpmb_write wrong mac.\n");
        err = RPMB_RES_AUTH_FAILURE;
        goto out;
    }

    for (i = 0; i < in_cnt; i++)
        memcpy(data + i * 256, in_frame[i].data, 256);

    if (rpmb_sim_write(data, sizeof(data), 256 * addr) < 0) {
        trusty_error("rpmb_write rpmb_sim_write failed.\n");
        goto out;
    }

    ++counter;
    if (set_counter(&counter)) {
        trusty_error("rpmb_write set_counter failed.\n");
        goto out;
    }

    err = RPMB_RES_OK;

out:
    if (out_frame) {
        memset(out_frame, 0, out_cnt*sizeof(*out_frame));
        out_frame->req_resp = swap16(RPMB_RESP_DATA_WRITE);
        out_frame->result = swap16(err);
        if (err == RPMB_RES_OK) {
            out_frame->address = swap16(addr);
            out_frame->write_counter = swap32(counter);
            rpmb_mac(key, out_frame, 1, out_frame->key_mac);
        }
    }

    return ret;
}

static int rpmb_read(const struct rpmb_packet *in_frame, uint32_t in_cnt,
                     struct rpmb_packet *out_frame, uint32_t out_cnt)
{
    int ret = 0;
    uint32_t i;
    int err = RPMB_RES_READ_FAILURE;
    uint8_t key[32];
    uint8_t mac[32];
    uint16_t addr;
    uint8_t data[256*out_cnt];

    if (in_cnt != 1 || in_frame == NULL)
        return -1;

    if (in_frame->req_resp != swap16(RPMB_REQ_DATA_READ))
        return -1;

    addr = swap16(in_frame->address);

    if (addr >= TEEDATA_BLOCK_COUNT) {
        err = RPMB_RES_ADDRESS_FAILURE;
        goto out;
    }

    if (addr + out_cnt > TEEDATA_BLOCK_COUNT)
        goto out;

    if (!is_key_programmed()) {
        err = RPMB_RES_NO_AUTH_KEY_PROGRAM;
        goto out;
    }

    if (rpmb_sim_read(data, sizeof(data), 256 * addr) < 0) {
        trusty_error("rpmb_read rpmb_sim_read failed.\n");
        goto out;
    }

    err = RPMB_RES_OK;

out:
    if (out_frame) {
        memset(out_frame, 0, out_cnt*sizeof(*out_frame));
        for (i = 0; i < out_cnt; i++) {
            memcpy(out_frame[i].nonce, in_frame[0].nonce,
                   sizeof(in_frame[0].nonce));
            out_frame[i].req_resp = swap16(RPMB_RESP_DATA_READ);
            out_frame[i].block_count = swap16(out_cnt);
            out_frame[i].address = in_frame[0].address;
            memcpy(out_frame[i].data, data+256*i, 256);
        }
        if (get_key(key))
            trusty_error("rpmb_read get_key failed.\n");

        out_frame[out_cnt - 1].result = swap16(err);
        rpmb_mac(key, out_frame, out_cnt, mac);
        memcpy(out_frame[out_cnt - 1].key_mac, mac, sizeof(mac));
    }

    return ret;
}

static int rpmb_get_counter(const struct rpmb_packet *in_frame, uint32_t in_cnt,
                            struct rpmb_packet *out_frame, uint32_t out_cnt)
{
    int ret = 0;
    int err = RPMB_RES_COUNTER_FAILURE;
    uint8_t key[32];
    uint32_t counter;

    if (in_cnt != 1 || in_frame == NULL)
        return -1;

    if (in_frame->req_resp != swap16(RPMB_REQ_GET_COUNTER))
        return -1;

    if (!is_key_programmed()) {
        err = RPMB_RES_NO_AUTH_KEY_PROGRAM;
        goto out;
    }

    if (get_key(key))
        goto out;

    if (get_counter(&counter))
        goto out;

    err = RPMB_RES_OK;

out:
    if (out_frame) {
        memset(out_frame, 0, sizeof(*out_frame)*out_cnt);
        out_frame->result = swap16(err);
        out_frame->req_resp = swap16(RPMB_RESP_GET_COUNTER);
        memcpy(out_frame->nonce, in_frame[0].nonce, sizeof(in_frame[0].nonce));

        if (err == RPMB_RES_OK) {
            out_frame->write_counter = swap32(counter);
            rpmb_mac(key, out_frame, out_cnt, out_frame->key_mac);
        }
    }

    return ret;
}

/*
 *                rel_write       write      read
 * RPMB_READ          0             1        1~N
 * RPMB_WRITE        1~N            1         1
 * GET_COUNTER        0             1         1
 * PROGRAM_KEY        1             1         1
 */
int rpmb_sim_operations(const void *rel_write_data, size_t rel_write_size,
                        const void *write_data, size_t write_size,
                        void *read_buf, size_t read_size)
{
    int ret = -1;

    if (rel_write_size) {
        int nframe = rel_write_size/RPMB_FRAME_SIZE;
        struct rpmb_packet rel_write_frame[nframe];
        memcpy(rel_write_frame, rel_write_data, sizeof(rel_write_frame));
        if (rel_write_frame[0].req_resp == swap16(RPMB_REQ_DATA_WRITE)) {
            if (write_size/RPMB_FRAME_SIZE &&
                   ((struct rpmb_packet *)write_data)->req_resp
                       == swap16(RPMB_REQ_RESULT_READ)) {
                ret = rpmb_write(rel_write_frame, nframe,
                                 read_buf, read_size/RPMB_FRAME_SIZE);
            } else {
                ret = rpmb_write(rel_write_frame, nframe, NULL, 0);
            }
        } else if (rel_write_frame[0].req_resp
                                    == swap16(RPMB_REQ_PROGRAM_KEY)) {
            if (write_size/RPMB_FRAME_SIZE &&
                   ((struct rpmb_packet *)write_data)->req_resp
                        == swap16(RPMB_REQ_RESULT_READ)) {
                ret = rpmb_program_key(rel_write_frame, 1,
                                       read_buf, read_size/RPMB_FRAME_SIZE);
            } else {
                ret = rpmb_program_key(rel_write_frame, 1, NULL, 0);
            }
        }
    } else if (write_size) {
        struct rpmb_packet write_frame[write_size/RPMB_FRAME_SIZE];
        memcpy(write_frame, write_data, sizeof(write_frame));
        if (write_frame[0].req_resp == swap16(RPMB_REQ_DATA_READ))
            ret = rpmb_read(write_frame, 1,
                            read_buf, read_size/RPMB_FRAME_SIZE);
        else if (write_frame[0].req_resp == swap16(RPMB_REQ_GET_COUNTER)) {
            ret = rpmb_get_counter(write_frame, 1, read_buf, 1);
        }
    }

    return ret;
}

