/*
 * Copyright (C) 2017 The Android Open Source Project
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

#include <trusty/keymaster.h>
#include <trusty/keymaster_serializable.h>
#include <trusty/trusty_ipc.h>
#include <trusty/util.h>
#include "security.h"
#include <life_cycle.h>
#include <libtipc.h>
#include "storage.h"

#define LOCAL_LOG 0
#define UNUSED(x) (void)(x)

static struct trusty_ipc_chan km_chan;
static bool initialized;
static int trusty_km_version = 2;
static const size_t max_send_size = 4000;

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

#ifndef NELEMS
#define NELEMS(x) (sizeof(x) / sizeof((x)[0]))
#endif
static int km_send_request(uint32_t cmd, const void *req, size_t req_len)
{
    struct keymaster_message header = { .cmd = cmd };
    int num_iovecs = req ? 2 : 1;

    struct trusty_ipc_iovec req_iovs[2] = {
        { .base = &header, .len = sizeof(header) },
        { .base = (void*)req, .len = req_len },
    };

    return trusty_ipc_send(&km_chan, req_iovs, num_iovecs, true);
}

/* Checks that the command opcode in |header| matches |ex-ected_cmd|. Checks
 * that |tipc_result| is a valid response size. Returns negative on error.
 */
static int check_response_error(uint32_t expected_cmd,
                                struct keymaster_message header,
                                int32_t tipc_result)
{
    if (tipc_result < 0) {
        trusty_error("failed (%d) to recv response\n", tipc_result);
        return tipc_result;
    }
    if ((size_t) tipc_result < sizeof(struct keymaster_message)) {
        trusty_error("invalid response size (%d)\n", tipc_result);
        return TRUSTY_ERR_GENERIC;
    }
    if ((header.cmd & ~(KEYMASTER_STOP_BIT)) !=
        (expected_cmd | KEYMASTER_RESP_BIT)) {
        trusty_error("malformed response\n");
        return TRUSTY_ERR_GENERIC;
    }
    return tipc_result;
}

/* Reads the raw response to |resp| up to a maximum size of |resp_len|. Format
 * of each message frame read from the secure side:
 *
 * command header : 4 bytes
 * opaque bytes   : MAX(KEYMASTER_MAX_BUFFER_LENGTH, x) bytes
 *
 * The individual message frames from the secure side are reassembled
 * into |resp|, stripping each frame's command header. Returns the number
 * of bytes written to |resp| on success, negative on error.
 */
static int km_read_raw_response(uint32_t cmd, void *resp, size_t resp_len)
{
    struct keymaster_message header = { .cmd = cmd };
    int rc = TRUSTY_ERR_GENERIC;
    size_t max_resp_len = resp_len;
    struct trusty_ipc_iovec resp_iovs[2] = {
        { .base = &header, .len = sizeof(header) },
        { .base = resp, .len = MIN(KEYMASTER_MAX_BUFFER_LENGTH, max_resp_len) }
    };

    if (!resp) {
        return TRUSTY_ERR_GENERIC;
    }
    resp_len = 0;
    while (true) {
        resp_iovs[1].base = (uint8_t*)resp + resp_len;
        resp_iovs[1].len = MIN(KEYMASTER_MAX_BUFFER_LENGTH,
                               (int)max_resp_len - (int)resp_len);

        rc = trusty_ipc_recv(&km_chan, resp_iovs, NELEMS(resp_iovs), true);
        rc = check_response_error(cmd, header, rc);
        if (rc < 0) {
            return rc;
        }
        resp_len += ((size_t)rc - sizeof(struct keymaster_message));
        if (header.cmd & KEYMASTER_STOP_BIT || resp_len >= max_resp_len) {
            break;
        }
    }

    return resp_len;
}

/* Reads a Keymaster Response message with a sized buffer. The format
 * of the response is as follows:
 *
 * command header : 4 bytes
 * error          : 4 bytes
 * data length    : 4 bytes
 * data           : |data length| bytes
 *
 * On success, |error|, |resp_data|, and |resp_data_len| are filled
 * successfully. Returns a trusty_err.
 */
static int km_read_data_response(uint32_t cmd, int32_t *error,
                                 uint8_t* resp_data, uint32_t* resp_data_len)
{
    struct keymaster_message header = { .cmd = cmd };
    int rc = TRUSTY_ERR_GENERIC;
    size_t max_resp_len = *resp_data_len;
    uint32_t resp_data_bytes = 0;
    /* On the first read, recv the keymaster_message header, error code,
     * response data length, and response data. On subsequent iterations,
     * only recv the keymaster_message header and response data.
     */
    struct trusty_ipc_iovec resp_iovs[4] = {
        { .base = &header, .len = sizeof(header) },
        { .base = error, .len = sizeof(int32_t) },
        { .base = resp_data_len, .len = sizeof(uint32_t) },
        { .base = resp_data, .len = MIN(KEYMASTER_MAX_BUFFER_LENGTH, max_resp_len) }
    };

    rc = trusty_ipc_recv(&km_chan, resp_iovs, NELEMS(resp_iovs), true);
    rc = check_response_error(cmd, header, rc);
    if (rc < 0) {
        return rc;
    }
    /* resp_data_bytes does not include the error or response data length */
    resp_data_bytes += ((size_t)rc - sizeof(struct keymaster_message) -
                        2 * sizeof(uint32_t));
    if (header.cmd & KEYMASTER_STOP_BIT) {
        return TRUSTY_ERR_NONE;
    }

    /* Read the remaining response data */
    uint8_t* resp_data_start = resp_data + resp_data_bytes;
    size_t resp_data_remaining = *resp_data_len - resp_data_bytes;
    rc = km_read_raw_response(cmd, resp_data_start, resp_data_remaining);
    if (rc < 0) {
        return rc;
    }
    resp_data_bytes += rc;
    if (*resp_data_len != resp_data_bytes) {
        return TRUSTY_ERR_GENERIC;
    }
    return TRUSTY_ERR_NONE;
}

/**
 * Convenience method to send a request to the secure side
 * and receive the response. If |resp_data| is not NULL, the
 * caller expects an additional data buffer to be returned from the secure
 * side.
 */
static int km_do_tipc(uint32_t cmd, void* req,
                      uint32_t req_len, void* resp_data,
                      uint32_t* resp_data_len)
{
    int rc = TRUSTY_ERR_GENERIC;
    struct km_no_response resp_header  = { .error = 0 };

    rc = km_send_request(cmd, req, req_len);
    if (rc < 0) {
        trusty_error("%s: failed (%d) to send km request\n", __func__, rc);
        return rc;
    }

    if (!resp_data) {
        rc = km_read_raw_response(cmd, &resp_header, sizeof(resp_header));
    } else {
        rc = km_read_data_response(cmd, &resp_header.error, resp_data,
                                   resp_data_len);
    }

    if (rc < 0) {
        trusty_error("%s: failed (%d) to read km response\n", __func__, rc);
        return rc;
    }
    if (resp_header.error != KM_ERROR_OK) {
        trusty_error("%s: keymaster returned error (%d)\n", __func__,
                     resp_header.error);
        return TRUSTY_ERR_GENERIC;
    }
    return TRUSTY_ERR_NONE;
}

static int32_t MessageVersion(uint8_t major_ver, uint8_t minor_ver,
                              uint8_t subminor_ver) {
    UNUSED(subminor_ver);
    int32_t message_version = -1;
    switch (major_ver) {
    case 0:
        message_version = 0;
        break;
    case 1:
        switch (minor_ver) {
        case 0:
            message_version = 1;
            break;
        case 1:
            message_version = 2;
            break;
        }
        break;
    case 2:
        message_version = 3;
        break;
    }
    return message_version;
}

static int km_get_version(int32_t *version)
{
    int rc = TRUSTY_ERR_GENERIC;
    struct km_get_version_resp resp = { .major_ver = 0, .minor_ver = 0, .subminor_ver = 0 };

    rc = km_send_request(KM_GET_VERSION, NULL, 0);
    if (rc < 0) {
        trusty_error("failed to send km version request", rc);
        return rc;
    }

    rc = km_read_raw_response(KM_GET_VERSION, &resp, sizeof(resp));
    if (rc < 0) {
        trusty_error("%s: failed (%d) to read km response\n", __func__, rc);
        return rc;
    }

    *version = MessageVersion(resp.major_ver, resp.minor_ver,
                              resp.subminor_ver);
    return TRUSTY_ERR_NONE;
}

int km_tipc_init(struct trusty_ipc_dev *dev)
{
    int rc = TRUSTY_ERR_GENERIC;
    struct rot_data_t* p_rot_data = NULL;
    struct attestation_ids_t* p_attestation_ids = NULL;

    trusty_assert(dev);

    trusty_ipc_chan_init(&km_chan, dev);
    trusty_debug("Connecting to Keymaster service\n");

    /* connect to km service and wait for connect to complete */
    rc = trusty_ipc_connect(&km_chan, KEYMASTER_PORT, true);
    if (rc < 0) {
        trusty_error("failed (%d) to connect to '%s'\n", rc, KEYMASTER_PORT);
        return rc;
    }

    int32_t version = -1;
    rc = km_get_version(&version);
    if (rc < 0) {
        trusty_error("failed (%d) to get keymaster version\n", rc);
        return rc;
    }
    if (version < trusty_km_version) {
        trusty_error("keymaster version mismatch. Expected %d, received %d\n",
                     trusty_km_version, version);
        return TRUSTY_ERR_GENERIC;
    }

    p_rot_data =  get_rot_data();

    /* sent the ROT information to trusty */
    rc = trusty_set_boot_params(p_rot_data->osVersion,
                p_rot_data->patchMonthYearDay,
                p_rot_data->verifiedBootState,
                p_rot_data->deviceLocked,
                p_rot_data->keyHash256,
                p_rot_data->keySize,
                p_rot_data->vbmetaDigest,
                p_rot_data->digestSize);

    if (rc != KM_ERROR_OK && rc != KM_ERROR_ROOT_OF_TRUST_ALREADY_SET) {
        trusty_error("set boot_params has failed( %d )\n", rc);
        return TRUSTY_ERR_GENERIC;
    }

    /* sent the boot_patchlevel information to trusty */
    rc = trusty_config_boot_patchlevel(p_rot_data->patchMonthYearDay);

    if (rc != KM_ERROR_OK) {
        trusty_error("config boot_patchlevel has failed( %d )\n", rc);
        return TRUSTY_ERR_GENERIC;
    }

    p_attestation_ids =  get_attestation_ids();

    /* sent the attestation_ids information to trusty */
    rc = trusty_set_attestation_ids(p_attestation_ids->brand, p_attestation_ids->brandSize,
                p_attestation_ids->device, p_attestation_ids->deviceSize,
                p_attestation_ids->name, p_attestation_ids->nameSize,
                p_attestation_ids->serial,p_attestation_ids->serialSize,
                0,0,
                0,0,
                p_attestation_ids->manufacturer, p_attestation_ids->manufacturerSize,
                p_attestation_ids->model, p_attestation_ids->modelSize);

    if (rc != KM_ERROR_OK) {
        trusty_error("set attestation_ids has failed( %d )\n", rc);
        return TRUSTY_ERR_GENERIC;
    }
    return TRUSTY_ERR_NONE;
}

void km_tipc_shutdown(struct trusty_ipc_dev *dev)
{
    UNUSED(dev);
    if (!initialized)
        return;
    /* close channel */
    trusty_ipc_close(&km_chan);

    initialized = false;
}

int trusty_set_boot_params(uint32_t os_version, uint32_t os_patchlevel,
                           keymaster_verified_boot_t verified_boot_state,
                           bool device_locked,
                           const uint8_t *verified_boot_key_hash,
                           uint32_t verified_boot_key_hash_size,
                           const uint8_t* verified_boot_hash,
                           uint32_t verified_boot_hash_size)
{
    struct km_boot_params params = {
        .os_version = os_version,
        .os_patchlevel = os_patchlevel,
        .device_locked = (uint32_t)device_locked,
        .verified_boot_state = (uint32_t)verified_boot_state,
        .verified_boot_key_hash_size = verified_boot_key_hash_size,
        .verified_boot_key_hash = (uint8_t *)verified_boot_key_hash,
        .verified_boot_hash_size = verified_boot_hash_size,
        .verified_boot_hash = verified_boot_hash
    };
    uint8_t *req = NULL;
    uint32_t req_size = 0;
    int rc = km_boot_params_serialize(&params, &req, &req_size);

    if (rc < 0) {
        trusty_error("failed (%d) to serialize request\n", rc);
        goto end;
    }
    rc = km_do_tipc(KM_SET_BOOT_PARAMS, req, req_size, NULL, NULL);

end:
    if (req) {
        trusty_free(req);
    }
    return rc;
}

int trusty_config_boot_patchlevel(uint32_t boot_patchlevel)
{
    struct km_boot_patchlevel params = {
        .boot_patchlevel = boot_patchlevel
    };
    uint8_t *req = NULL;
    uint32_t req_size = 0;
    int rc = km_boot_patchlevel_serialize(&params, &req, &req_size);

    if (rc < 0) {
        trusty_error("failed (%d) to serialize request\n", rc);
        goto end;
    }
    rc = km_do_tipc(KM_CONFIGURE_BOOT_PATCHLEVEL, req, req_size, NULL, NULL);

end:
    if (req) {
        trusty_free(req);
    }
    return rc;
}

int trusty_set_attestation_ids(const uint8_t *brand,
                               uint32_t brand_size,
                               const uint8_t *device,
                               uint32_t device_size,
                               const uint8_t *product,
                               uint32_t product_size,
                               const uint8_t *serial,
                               uint32_t serial_size,
                               const uint8_t *imei,
                               uint32_t imei_size,
                               const uint8_t *meid,
                               uint32_t meid_size,
                               const uint8_t *manufacturer,
                               uint32_t manufacturer_size,
                               const uint8_t *model,
                               uint32_t model_size)
{
    struct km_attestation_ids params = {
        .brand_size = brand_size,
        .brand = brand,
        .device_size = device_size,
        .device = device,
        .product_size = product_size,
        .product = product,
        .serial_size = serial_size,
        .serial = serial,
        .imei_size = imei_size,
        .imei = imei,
        .meid_size = meid_size,
        .meid = meid,
        .manufacturer_size = manufacturer_size,
        .manufacturer = manufacturer,
        .model_size = model_size,
        .model = model
    };
    uint8_t *req = NULL;
    uint32_t req_size = 0;
    int rc = km_attestation_ids_serialize(&params, &req, &req_size);
    if (rc < 0) {
        trusty_error("failed (%d) to serialize request\n", rc);
        goto end;
    }
    rc = km_do_tipc(KM_SET_ATTESTATION_IDS, req, req_size, NULL, NULL);

end:
    if (req) {
        trusty_free(req);
    }
    return rc;
}

static int trusty_send_attestation_data(uint32_t cmd, const uint8_t *data,
                                        uint32_t data_size,
                                        keymaster_algorithm_t algorithm)
{
    struct km_attestation_data attestation_data = {
        .algorithm = (uint32_t)algorithm,
        .data_size = data_size,
        .data = (uint8_t *)data,
    };
    uint8_t *req = NULL;
    uint32_t req_size = 0;
    int rc = km_attestation_data_serialize(&attestation_data, &req, &req_size);

    if (rc < 0) {
        trusty_error("failed (%d) to serialize request\n", rc);
        goto end;
    }
    rc = km_do_tipc(cmd, req, req_size, NULL, NULL);

end:
    if (req) {
        trusty_free(req);
    }
    return rc;
}

int trusty_set_attestation_key(const uint8_t *key, uint32_t key_size,
                               keymaster_algorithm_t algorithm)
{
    return trusty_send_attestation_data(KM_SET_ATTESTATION_KEY, key, key_size,
                                        algorithm);
}

int trusty_append_attestation_cert_chain(const uint8_t *cert,
                                         uint32_t cert_size,
                                         keymaster_algorithm_t algorithm)
{
    return trusty_send_attestation_data(KM_APPEND_ATTESTATION_CERT_CHAIN,
                                        cert, cert_size, algorithm);
}
