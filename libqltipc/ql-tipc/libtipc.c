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

#include <trusty/avb.h>
#include <trusty/rpmb.h>
#include <trusty/rpmb_sim.h>
#include <trusty/trusty_dev.h>
#include <trusty/trusty_ipc.h>
#include <trusty/util.h>
#include <trusty/keymaster.h>
#include "storage.h"
#include "rpmb_storage.h"

#define LOCAL_LOG 0
#define TRUSTY_QL_TIPC_MAX_BUFFER_LEN PAGE_SIZE

static struct trusty_ipc_dev *_ipc_dev;
static struct trusty_dev _tdev; /* There should only be one trusty device */
static void *rpmb_ctx;

void trusty_ipc_shutdown(void)
{
    (void)rpmb_storage_proxy_shutdown(_ipc_dev);
    (void)avb_tipc_shutdown(_ipc_dev);
    (void)km_tipc_shutdown(_ipc_dev);

    /* shutdown Trusty IPC device */
    (void)trusty_ipc_dev_shutdown(_ipc_dev);

    /* shutdown Trusty device */
    (void)trusty_dev_shutdown(&_tdev);
}

#define KEYBOX_PROVISION_MAGIC_DATA  (0xe62f30d4)
#define KEYBOX_PROVISION_ADDR  (is_boot_device_virtual()?129:1)

static int rpmb_read_keybox_magic_data(uint32_t *data)
{
#if defined(RPMB_STORAGE)
    EFI_STATUS rc = 0;

    rc = read_rpmb_keybox_magic(KEYBOX_PROVISION_ADDR,  data);
    if (EFI_ERROR(rc)) {
        trusty_error("[KeyBox] Failed to read keybox magic data from rpmb.\n");
        return -1;
    }

    return 0;
#else
    (void)data;
    trusty_error("RPMB storage unsupported.\n");
    return -1;
#endif
}

static int rpmb_write_keybox_magic_data(uint32_t data)
{
#if defined(RPMB_STORAGE)
    EFI_STATUS rc = 0;

    rc = write_rpmb_keybox_magic(KEYBOX_PROVISION_ADDR, &data);
    if (EFI_ERROR(rc)) {
        trusty_error("[KeyBox] Failed to write keybox magic data from rpmb.\n");
        return -1;
    }

    return 0;
#else
    (void)data;
    trusty_error("RPMB storage unsupported.\n");
    return -1;
#endif
}

int is_keybox_retrieved(void)
{
    uint32_t data = 0;
    int rc = 0;

    rc = rpmb_read_keybox_magic_data(&data);
    if (rc != 0) {
        trusty_error("Reading keybox provision magic data failed.\n");
    }

    return (data == KEYBOX_PROVISION_MAGIC_DATA);
}

int set_keybox_provision_magic_data(void)
{
    uint32_t data = KEYBOX_PROVISION_MAGIC_DATA;
    int rc = 0;

    rc = rpmb_write_keybox_magic_data(data);
    if (rc != 0) {
        trusty_error("Writing keybox provision magic data failed (%d)\n", rc);
        return rc;
    }

    return 0;
}

int trusty_ipc_init(void)
{
    int rc = 0;

    /* init Trusty device */
    trusty_info("Initializing Trusty device\n");
    rc = trusty_dev_init(&_tdev, NULL);
    if (rc != 0) {
        trusty_error("Initializing Trusty device failed (%d)\n", rc);
        return rc;
    }

    /* create Trusty IPC device */
    trusty_info("Initializing Trusty IPC device\n");
    rc = trusty_ipc_dev_create(&_ipc_dev, &_tdev,
                               TRUSTY_QL_TIPC_MAX_BUFFER_LEN);
    if (rc != 0) {
        trusty_error("Initializing Trusty IPC device failed (%d)\n", rc);
        return rc;
    }

#if defined(RPMB_STORAGE)
    /* get storage rpmb */
    if (is_use_sim_rpmb()) {
        trusty_info("Simulation RPMB is in use.\n");
    } else {
        trusty_info("Physical RPMB is in use.\n");
        rpmb_ctx = rpmb_storage_get_ctx();
    }

    /* start secure storage proxy service for initialization */
    rc = rpmb_storage_proxy_init(_ipc_dev, rpmb_ctx);
    trusty_info("1st Initlializing RPMB storage proxy service rc: (%d)\n", rc);


    if (!is_keybox_retrieved()) {
       /* start secure storage proxy service */
       trusty_info("Initializing RPMB storage proxy service\n");
       rc = rpmb_storage_proxy_init(_ipc_dev, rpmb_ctx);
       if (rc != 0) {
           trusty_error("Initlializing RPMB storage proxy service failed (%d)\n",
                     rc);
           return rc;
       }
    }
#else
    (void)rpmb_ctx;
#endif

    /*
    trusty_info("Initializing Trusty AVB client\n");
    rc = avb_tipc_init(_ipc_dev);
    if (rc != 0) {
        trusty_error("Initlializing Trusty AVB client failed (%d)\n", rc);
        return rc;
    }
    */

    trusty_info("Initializing Trusty Keymaster client\n");
    rc = km_tipc_init(_ipc_dev);
    if (rc != 0) {
#ifndef USER
        trusty_error("Initlializing Trusty Keymaster client failed (%d)\n", rc);
#endif
        return rc;
    }

    return TRUSTY_ERR_NONE;
}
