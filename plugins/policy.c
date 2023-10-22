// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2013  Intel Corporation.
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>

#include <glib.h>

#include "lib/bluetooth.h"
#include "lib/sdp.h"
#include "lib/uuid.h"
#include "lib/mgmt.h"

#include "src/log.h"
#include "src/plugin.h"
#include "src/adapter.h"
#include "src/device.h"
#include "src/service.h"
#include "src/profile.h"
#include "src/btd.h"
#include "src/shared/timeout.h"
#include "src/shared/util.h"

#define CONTROL_CONNECT_TIMEOUT 2
#define SOURCE_RETRY_TIMEOUT 2
#define SINK_RETRY_TIMEOUT SOURCE_RETRY_TIMEOUT
#define CT_RETRY_TIMEOUT 1
#define TG_RETRY_TIMEOUT CT_RETRY_TIMEOUT
#define SOURCE_RETRIES 1
#define SINK_RETRIES SOURCE_RETRIES
#define CT_RETRIES 1
#define TG_RETRIES CT_RETRIES

struct reconnect_device_entry {
	struct btd_device *dev;
	bool reconnect_enabled;
	GSList *services_to_reconnect;
	unsigned int timer;
	bool reconnecting;
	unsigned int attempt;
	bool on_resume;
};

static const char *default_reconnect[] = {
			HSP_AG_UUID, HFP_AG_UUID, A2DP_SOURCE_UUID,
			A2DP_SINK_UUID, NULL };
static char **reconnect_uuids = NULL;

static const size_t default_attempts = 7;
static size_t reconnect_attempts = 0;

static const int default_intervals[] = { 1, 2, 4, 8, 16, 32, 64 };
static int *reconnect_intervals = NULL;
static size_t reconnect_intervals_len = 0;

static const int default_resume_delay = 2;
static int resume_delay;

static GSList *reconnects = NULL;

static unsigned int service_id = 0;
static GSList *devices = NULL;

static bool auto_enable = false;

struct policy_data {
	struct btd_device *dev;

	unsigned int source_timer;
	uint8_t source_retries;
	unsigned int sink_timer;
	uint8_t sink_retries;
	unsigned int ct_timer;
	uint8_t ct_retries;
	unsigned int tg_timer;
	uint8_t tg_retries;
};

static struct reconnect_device_entry *reconnect_find(struct btd_device *dev)
{
	GSList *l;

	for (l = reconnects; l; l = g_slist_next(l)) {
		struct reconnect_device_entry *device_entry = l->data;

		if (device_entry->dev == dev)
			return device_entry;
	}

	return NULL;
}

static void policy_connect(struct policy_data *data,
						struct btd_service *service)
{
	struct btd_profile *profile = btd_service_get_profile(service);
	struct reconnect_device_entry *device_entry;

	device_entry = reconnect_find(btd_service_get_device(service));
	if (device_entry && device_entry->reconnecting)
		return;

	DBG("%s profile %s", device_get_path(data->dev), profile->name);

	btd_service_connect(service);
}

static void policy_disconnect(struct policy_data *data,
						struct btd_service *service)
{
	struct btd_profile *profile = btd_service_get_profile(service);

	DBG("%s profile %s", device_get_path(data->dev), profile->name);

	btd_service_disconnect(service);
}

static bool policy_connect_ct(gpointer user_data)
{
	struct policy_data *data = user_data;
	struct btd_service *service;

	data->ct_timer = 0;
	data->ct_retries++;

	service = btd_device_get_service(data->dev, AVRCP_REMOTE_UUID);
	if (service != NULL)
		policy_connect(data, service);

	return FALSE;
}

static void policy_set_ct_timer(struct policy_data *data, int timeout)
{
	if (data->ct_timer > 0)
		timeout_remove(data->ct_timer);

	data->ct_timer = timeout_add_seconds(timeout, policy_connect_ct,
						data, NULL);
}

static struct policy_data *find_data(struct btd_device *dev)
{
	GSList *l;

	for (l = devices; l; l = l->next) {
		struct policy_data *data = l->data;

		if (data->dev == dev)
			return data;
	}

	return NULL;
}

static void policy_remove(void *user_data)
{
	struct policy_data *data = user_data;

	if (data->source_timer > 0)
		timeout_remove(data->source_timer);

	if (data->sink_timer > 0)
		timeout_remove(data->sink_timer);

	if (data->ct_timer > 0)
		timeout_remove(data->ct_timer);

	if (data->tg_timer > 0)
		timeout_remove(data->tg_timer);

	g_free(data);
}

static struct policy_data *policy_get_data(struct btd_device *dev)
{
	struct policy_data *data;

	data = find_data(dev);
	if (data != NULL)
		return data;

	data = g_new0(struct policy_data, 1);
	data->dev = dev;

	devices = g_slist_prepend(devices, data);

	return data;
}

static bool policy_connect_sink(gpointer user_data)
{
	struct policy_data *data = user_data;
	struct btd_service *service;

	data->sink_timer = 0;
	data->sink_retries++;

	service = btd_device_get_service(data->dev, A2DP_SINK_UUID);
	if (service != NULL)
		policy_connect(data, service);

	return FALSE;
}

static void policy_set_sink_timer(struct policy_data *data)
{
	if (data->sink_timer > 0)
		timeout_remove(data->sink_timer);

	data->sink_timer = timeout_add_seconds(SINK_RETRY_TIMEOUT,
							policy_connect_sink,
							data, NULL);
}

static void sink_cb(struct btd_service *service, btd_service_state_t old_state,
						btd_service_state_t new_state)
{
	struct btd_device *dev = btd_service_get_device(service);
	struct policy_data *data;
	struct btd_service *controller;

	controller = btd_device_get_service(dev, AVRCP_REMOTE_UUID);
	if (controller == NULL)
		return;

	data = policy_get_data(dev);

	switch (new_state) {
	case BTD_SERVICE_STATE_UNAVAILABLE:
		if (data->sink_timer > 0) {
			timeout_remove(data->sink_timer);
			data->sink_timer = 0;
		}
		break;
	case BTD_SERVICE_STATE_DISCONNECTED:
               break; // let conn failed handler deal with it

		if (old_state == BTD_SERVICE_STATE_CONNECTING) {
			int err = btd_service_get_error(service);

			if (err == -EAGAIN) {
				if (data->sink_retries < SINK_RETRIES)
					policy_set_sink_timer(data);
				else
					data->sink_retries = 0;
				break;
			} else if (data->sink_timer > 0) {
				timeout_remove(data->sink_timer);
				data->sink_timer = 0;
			}
		}

		if (data->ct_timer > 0) {
			timeout_remove(data->ct_timer);
			data->ct_timer = 0;
		} else if (btd_service_get_state(controller) !=
						BTD_SERVICE_STATE_DISCONNECTED)
			policy_disconnect(data, controller);
		break;
	case BTD_SERVICE_STATE_CONNECTING:
		break;
	case BTD_SERVICE_STATE_CONNECTED:
		if (data->sink_timer > 0) {
			timeout_remove(data->sink_timer);
			data->sink_timer = 0;
		}

		/* Check if service initiate the connection then proceed
		 * immediatelly otherwise set timer
		 */
		if (btd_service_is_initiator(service))
			policy_connect(data, controller);
		else if (btd_service_get_state(controller) !=
						BTD_SERVICE_STATE_CONNECTED)
			policy_set_ct_timer(data, CONTROL_CONNECT_TIMEOUT);
		break;
	case BTD_SERVICE_STATE_DISCONNECTING:
		break;
	}
}

static void hs_cb(struct btd_service *service, btd_service_state_t old_state,
						btd_service_state_t new_state)
{
	struct btd_device *dev = btd_service_get_device(service);
	struct policy_data *data;
	struct btd_service *sink;

	/* If the device supports Sink set a timer to connect it as well */
	sink = btd_device_get_service(dev, A2DP_SINK_UUID);
	if (sink == NULL)
		return;

	data = policy_get_data(dev);

	switch (new_state) {
	case BTD_SERVICE_STATE_UNAVAILABLE:
		break;
	case BTD_SERVICE_STATE_DISCONNECTED:
		break;
	case BTD_SERVICE_STATE_CONNECTING:
		break;
	case BTD_SERVICE_STATE_CONNECTED:
		/* Check if service initiate the connection then proceed
		 * immediately otherwise set timer
		 */
		if (btd_service_is_initiator(service))
			policy_connect(data, sink);
		else if (btd_service_get_state(sink) !=
						BTD_SERVICE_STATE_CONNECTED)
			policy_set_sink_timer(data);
		break;
	case BTD_SERVICE_STATE_DISCONNECTING:
		break;
	}
}

static bool policy_connect_tg(gpointer user_data)
{
	struct policy_data *data = user_data;
	struct btd_service *service;

	data->tg_timer = 0;
	data->tg_retries++;

	service = btd_device_get_service(data->dev, AVRCP_TARGET_UUID);
	if (service != NULL)
		policy_connect(data, service);

	return FALSE;
}

static void policy_set_tg_timer(struct policy_data *data, int timeout)
{
	if (data->tg_timer > 0)
		timeout_remove(data->tg_timer);

	data->tg_timer = timeout_add_seconds(timeout, policy_connect_tg,
							data, NULL);
}

static bool policy_connect_source(gpointer user_data)
{
	struct policy_data *data = user_data;
	struct btd_service *service;

	data->source_timer = 0;
	data->source_retries++;

	service = btd_device_get_service(data->dev, A2DP_SOURCE_UUID);
	if (service != NULL)
		policy_connect(data, service);

	return FALSE;
}

static void policy_set_source_timer(struct policy_data *data)
{
	if (data->source_timer > 0)
		timeout_remove(data->source_timer);

	data->source_timer = timeout_add_seconds(SOURCE_RETRY_TIMEOUT,
							policy_connect_source,
							data, NULL);
}

static void source_cb(struct btd_service *service,
						btd_service_state_t old_state,
						btd_service_state_t new_state)
{
	struct btd_device *dev = btd_service_get_device(service);
	struct policy_data *data;
	struct btd_service *target;

	target = btd_device_get_service(dev, AVRCP_TARGET_UUID);
	if (target == NULL)
		return;

	data = policy_get_data(dev);

	switch (new_state) {
	case BTD_SERVICE_STATE_UNAVAILABLE:
		if (data->source_timer > 0) {
			timeout_remove(data->source_timer);
			data->source_timer = 0;
		}
		break;
	case BTD_SERVICE_STATE_DISCONNECTED:
               break; // let conn failed handler deal with it

		if (old_state == BTD_SERVICE_STATE_CONNECTING) {
			int err = btd_service_get_error(service);

			if (err == -EAGAIN) {
				if (data->source_retries < SOURCE_RETRIES)
					policy_set_source_timer(data);
				else
					data->source_retries = 0;
				break;
			} else if (data->source_timer > 0) {
				timeout_remove(data->source_timer);
				data->source_timer = 0;
			}
		}

		if (data->tg_timer > 0) {
			timeout_remove(data->tg_timer);
			data->tg_timer = 0;
		} else if (btd_service_get_state(target) !=
						BTD_SERVICE_STATE_DISCONNECTED)
			policy_disconnect(data, target);
		break;
	case BTD_SERVICE_STATE_CONNECTING:
		break;
	case BTD_SERVICE_STATE_CONNECTED:
		if (data->source_timer > 0) {
			timeout_remove(data->source_timer);
			data->source_timer = 0;
		}

		/* Check if service initiate the connection then proceed
		 * immediatelly otherwise set timer
		 */
		if (btd_service_is_initiator(service))
			policy_connect(data, target);
		else if (btd_service_get_state(target) !=
						BTD_SERVICE_STATE_CONNECTED)
			policy_set_tg_timer(data, CONTROL_CONNECT_TIMEOUT);
		break;
	case BTD_SERVICE_STATE_DISCONNECTING:
		break;
	}
}

static void controller_cb(struct btd_service *service,
						btd_service_state_t old_state,
						btd_service_state_t new_state)
{
	struct btd_device *dev = btd_service_get_device(service);
	struct policy_data *data;

	data = find_data(dev);
	if (data == NULL)
		return;

	switch (new_state) {
	case BTD_SERVICE_STATE_UNAVAILABLE:
		if (data->ct_timer > 0) {
			timeout_remove(data->ct_timer);
			data->ct_timer = 0;
		}
		break;
	case BTD_SERVICE_STATE_DISCONNECTED:
               break; // let conn failed handler deal with it

		if (old_state == BTD_SERVICE_STATE_CONNECTING) {
			int err = btd_service_get_error(service);

			if (err == -EAGAIN) {
				if (data->ct_retries < CT_RETRIES)
					policy_set_ct_timer(data,
							CT_RETRY_TIMEOUT);
				else
					data->ct_retries = 0;
				break;
			} else if (data->ct_timer > 0) {
				timeout_remove(data->ct_timer);
				data->ct_timer = 0;
			}
		} else if (old_state == BTD_SERVICE_STATE_CONNECTED) {
			data->ct_retries = 0;
		}
		break;
	case BTD_SERVICE_STATE_CONNECTING:
		break;
	case BTD_SERVICE_STATE_CONNECTED:
		if (data->ct_timer > 0) {
			timeout_remove(data->ct_timer);
			data->ct_timer = 0;
		}
		break;
	case BTD_SERVICE_STATE_DISCONNECTING:
		break;
	}
}

static void target_cb(struct btd_service *service,
						btd_service_state_t old_state,
						btd_service_state_t new_state)
{
	struct btd_device *dev = btd_service_get_device(service);
	struct policy_data *data;

	data = find_data(dev);
	if (data == NULL)
		return;

	switch (new_state) {
	case BTD_SERVICE_STATE_UNAVAILABLE:
		if (data->tg_timer > 0) {
			timeout_remove(data->tg_timer);
			data->tg_timer = 0;
		}
		break;
	case BTD_SERVICE_STATE_DISCONNECTED:
               break; // let conn failed handler deal with it

		if (old_state == BTD_SERVICE_STATE_CONNECTING) {
			int err = btd_service_get_error(service);

			if (err == -EAGAIN) {
				if (data->tg_retries < TG_RETRIES)
					policy_set_tg_timer(data,
							TG_RETRY_TIMEOUT);
				else
					data->tg_retries = 0;
				break;
			} else if (data->tg_timer > 0) {
				timeout_remove(data->tg_timer);
				data->tg_timer = 0;
			}
		} else if (old_state == BTD_SERVICE_STATE_CONNECTED) {
			data->tg_retries = 0;
		}
		break;
	case BTD_SERVICE_STATE_CONNECTING:
		break;
	case BTD_SERVICE_STATE_CONNECTED:
		if (data->tg_timer > 0) {
			timeout_remove(data->tg_timer);
			data->tg_timer = 0;
		}
		break;
	case BTD_SERVICE_STATE_DISCONNECTING:
		break;
	}
}

static void reconnect_reset(struct reconnect_device_entry *reconnect)
{
	reconnect->attempt = 0;
	reconnect->reconnecting = false;

	if (reconnect->timer > 0) {
		timeout_remove(reconnect->timer);
		reconnect->timer = 0;
	}
}

static bool reconnect_match(const char *uuid)
{
	char **str;

	if (!reconnect_uuids)
		return false;

	for (str = reconnect_uuids; *str; str++) {
		if (!bt_uuid_strcmp(uuid, *str))
			return true;
	}

	return false;
}

static struct reconnect_device_entry *reconnect_add(struct btd_device *dev)
{
	struct reconnect_device_entry *device_entry;

	device_entry = g_new0(struct reconnect_device_entry, 1);
	device_entry->dev = dev;
	reconnects = g_slist_append(reconnects, device_entry);

	return device_entry;
}

static void reconnect_destroy(gpointer data)
{
	struct reconnect_device_entry *device_entry = data;

	if (device_entry->timer > 0)
		timeout_remove(device_entry->timer);

	g_slist_free_full(device_entry->services_to_reconnect,
					(GDestroyNotify) btd_service_unref);
	g_free(device_entry);
}

static void reconnect_remove(struct reconnect_device_entry *device_entry)
{
	reconnects = g_slist_remove(reconnects, device_entry);

	if (device_entry->timer > 0)
		timeout_remove(device_entry->timer);

	g_free(device_entry);
}

static void update_reconnect_enabled(struct reconnect_device_entry *device_entry)
{
	GSList *l;

	for (l = device_entry->services_to_reconnect; l; l = l->next) {
		struct btd_service *service = l->data;
		struct btd_profile *profile = btd_service_get_profile(service);

		if (reconnect_match(profile->remote_uuid)) {
			device_entry->reconnect_enabled = TRUE;
			return;
		}
	}

	device_entry->reconnect_enabled = FALSE;
}

static void reconnect_set_timer(struct reconnect_device_entry *reconnect, int timeout);

static void service_cb(struct btd_service *service,
						btd_service_state_t old_state,
						btd_service_state_t new_state,
						void *user_data)
{
	struct btd_profile *profile = btd_service_get_profile(service);
  	struct btd_device *dev = btd_service_get_device(service);
	struct reconnect_device_entry *device_entry;

	if (g_str_equal(profile->remote_uuid, A2DP_SINK_UUID))
		sink_cb(service, old_state, new_state);
	else if (g_str_equal(profile->remote_uuid, A2DP_SOURCE_UUID))
		source_cb(service, old_state, new_state);
	else if (g_str_equal(profile->remote_uuid, AVRCP_REMOTE_UUID))
		controller_cb(service, old_state, new_state);
	else if (g_str_equal(profile->remote_uuid, AVRCP_TARGET_UUID))
		target_cb(service, old_state, new_state);
	else if (g_str_equal(profile->remote_uuid, HFP_HS_UUID) ||
			g_str_equal(profile->remote_uuid, HSP_HS_UUID))
		hs_cb(service, old_state, new_state);

	/*
	 * Return if the reconnection feature is not enabled (all
	 * subsequent code in this function is about that).
	 */
	if (!reconnect_uuids || !reconnect_uuids[0])
		return;

	/*
	 * We're only interested in reconnecting profiles which have set
	 * auto_connect to true.
	 */
	if (!profile->auto_connect)
		return;

  	device_entry = reconnect_find(dev);

	if (new_state == BTD_SERVICE_STATE_UNAVAILABLE) {
		if (!device_entry || !g_slist_find(device_entry->services_to_reconnect, service))
			return;

		device_entry->services_to_reconnect =
			g_slist_remove(device_entry->services_to_reconnect, service);
		btd_service_unref(service);

		update_reconnect_enabled(device_entry);

		if (!device_entry->services_to_reconnect)
			reconnect_remove(device_entry);
	} else if (new_state == BTD_SERVICE_STATE_CONNECTED) {
		if (device_entry) {
			device_entry->reconnecting = false;
			if (g_slist_find(device_entry->services_to_reconnect, service))
				return;
		} else {
			device_entry = reconnect_add(dev);
		}

		device_entry->services_to_reconnect = g_slist_append(device_entry->services_to_reconnect,
																service);
		btd_service_ref(service);

		update_reconnect_enabled(device_entry);

		DBG("Added %s reconnect %u", profile->name, device_entry->reconnect_enabled);
	} else if (old_state == BTD_SERVICE_STATE_CONNECTING && new_state == BTD_SERVICE_STATE_DISCONNECTED) {
		if (device_entry && device_entry->reconnecting) {
      	DBG("reconnecting manually for case where conn fail doesn't happend, %s reconnect %u", device_get_path(device_entry->dev), device_entry->reconnect_enabled);
                  // this is basically the case where btd_device_connect_services() in reconnect_timeout() fails
	if (device_entry->timer == 0) {
                device_entry->attempt--;
        	reconnect_set_timer(device_entry, -1);
        }
    }
    }
}

static bool reconnect_timeout(gpointer data)
{
	struct reconnect_device_entry *device_entry = data;
	int err;

	DBG("Reconnecting profiles for device %s", device_get_path(device_entry->dev));

	/* Mark the GSource as invalid */
	device_entry->timer = 0;

	/* Mark any reconnect on resume as handled */
	device_entry->on_resume = false;

	err = btd_device_connect_services(device_entry->dev, device_entry->services_to_reconnect);
	if (err < 0) {
		error("Reconnecting services failed: %s (%d)",
							strerror(-err), -err);
		reconnect_reset(device_entry);
		return FALSE;
	}

	device_entry->attempt++;

	return FALSE;
}

static void reconnect_set_timer(struct reconnect_device_entry *reconnect, int timeout)
{
	static int interval_timeout = 0;

	if (reconnect->timer > 0)
		return;

	reconnect->reconnecting = true;

	if (reconnect->attempt < reconnect_intervals_len)
		interval_timeout = reconnect_intervals[reconnect->attempt];

	if (timeout < 0)
		timeout = interval_timeout;

	DBG("attempt %u/%zu %d seconds", reconnect->attempt + 1,
						reconnect_attempts, timeout);

	reconnect->timer = timeout_add_seconds(timeout, reconnect_timeout,
						reconnect, NULL);
}

static void disconnect_cb(struct btd_device *dev, uint8_t reason)
{
	struct reconnect_device_entry *device_entry;

	DBG("reason %u: %s", reason, device_get_path(dev));

	/* Only attempt reconnect for the following reasons */
	if (reason != MGMT_DEV_DISCONN_TIMEOUT &&
	    reason != MGMT_DEV_DISCONN_LOCAL_HOST_SUSPEND)
		return;

	device_entry = reconnect_find(dev);
  	DBG("device entry %p en %d", device_entry, device_entry->reconnect_enabled);
	if (!device_entry || !device_entry->reconnect_enabled)
		return;

	reconnect_reset(device_entry);

	DBG("Device %s identified for auto-reconnection", device_get_path(dev));

	switch (reason) {
	case MGMT_DEV_DISCONN_LOCAL_HOST_SUSPEND:
		if (btd_device_get_service(dev, A2DP_SINK_UUID)) {
			DBG("%s configured to reconnect on resume",
				device_get_path(dev));

			device_entry->on_resume = true;

			/* If the kernel supports resume events, it is
			 * preferable to set the reconnect timer there as it is
			 * a more predictable delay.
			 */
			if (!btd_has_kernel_features(KERNEL_HAS_RESUME_EVT))
				reconnect_set_timer(device_entry, resume_delay);
		}
		break;
	case MGMT_DEV_DISCONN_TIMEOUT:
		reconnect_set_timer(device_entry, -1);
		break;
	default:
		DBG("Developer error. Reason = %d", reason);
		break;
	}
}

static void policy_adapter_resume(struct btd_adapter *adapter)
{
	GSList *l;

	/* Check if devices on this adapter need to be reconnected on resume */
	for (l = reconnects; l; l = g_slist_next(l)) {
		struct reconnect_device_entry *device_entry = l->data;

		if (device_entry->on_resume &&
		    device_get_adapter(device_entry->dev) == adapter) {
			reconnect_set_timer(device_entry, resume_delay);
		}
	}
}

static void conn_fail_cb(struct btd_device *dev, uint8_t status)
{
	struct reconnect_device_entry *device_entry;

	DBG("status %u for dev %s", status, device_get_path(dev));
if (status == MGMT_STATUS_DISCONNECTED)
	DBG("status disconnected");
if (status == MGMT_STATUS_NOT_CONNECTED)
	DBG("status not connected");

if (status == MGMT_STATUS_BUSY)
	DBG("status busy");
if (status == MGMT_STATUS_PERMISSION_DENIED)
	DBG("status permission denied");

	device_entry = reconnect_find(dev);
	if (!device_entry || !device_entry->reconnect_enabled)
		return;

	if (!device_entry->reconnecting)
		return;

	/* Give up if we were powered off */
	if (status == MGMT_STATUS_NOT_POWERED) {
		reconnect_reset(device_entry);
		return;
	}

	/* Reset if ReconnectAttempts was reached */
	if (device_entry->attempt == reconnect_attempts) {
		reconnect_reset(device_entry);
		return;
	}

if (status == MGMT_STATUS_NO_RESOURCES) {
	DBG("status no resources");
        // NO_RESOURCES simply means the card is busy doing other stuff, so that doesn't count
        if (device_entry->timer == 0) {
        	device_entry->attempt--;
        	reconnect_set_timer(device_entry, -1);
        }
  return;
}

	reconnect_set_timer(device_entry, -1);
}

static int policy_adapter_probe(struct btd_adapter *adapter)
{
	DBG("");

	if (auto_enable)
		btd_adapter_restore_powered(adapter);

	return 0;
}

static struct btd_adapter_driver policy_driver = {
	.name	= "policy",
	.probe	= policy_adapter_probe,
	.resume = policy_adapter_resume,
};

static int policy_init(void)
{
	GError *gerr = NULL;
	GKeyFile *conf;

	service_id = btd_service_add_state_cb(service_cb, NULL);

	conf = btd_get_main_conf();
	if (!conf) {
		reconnect_uuids = g_strdupv((char **) default_reconnect);
		reconnect_attempts = default_attempts;
		reconnect_intervals_len = sizeof(default_intervals) /
						sizeof(*reconnect_intervals);
		reconnect_intervals = util_memdup(default_intervals,
						sizeof(default_intervals));
		goto done;
	}

	g_key_file_set_list_separator(conf, ',');

	reconnect_uuids = g_key_file_get_string_list(conf, "Policy",
							"ReconnectUUIDs",
							NULL, &gerr);
	if (gerr) {
		g_clear_error(&gerr);
		reconnect_uuids = g_strdupv((char **) default_reconnect);
	}

	reconnect_attempts = g_key_file_get_integer(conf, "Policy",
							"ReconnectAttempts",
							&gerr);
	if (gerr) {
		g_clear_error(&gerr);
		reconnect_attempts = default_attempts;
	}

	reconnect_intervals = g_key_file_get_integer_list(conf, "Policy",
					"ReconnectIntervals",
					(size_t *) &reconnect_intervals_len,
					&gerr);
	if (gerr) {
		g_clear_error(&gerr);
		reconnect_intervals_len = sizeof(default_intervals) /
						sizeof(*reconnect_intervals);
		reconnect_intervals = util_memdup(default_intervals,
						sizeof(default_intervals));
	}

	auto_enable = g_key_file_get_boolean(conf, "Policy", "AutoEnable",
								&gerr);
	if (gerr) {
		g_clear_error(&gerr);
		auto_enable = true;
	}

	resume_delay = g_key_file_get_integer(
			conf, "Policy", "ResumeDelay", &gerr);

	if (gerr) {
		g_clear_error(&gerr);
		resume_delay = default_resume_delay;
	}
done:
	if (reconnect_uuids && reconnect_uuids[0] && reconnect_attempts) {
		btd_add_disconnect_cb(disconnect_cb);
		btd_add_conn_fail_cb(conn_fail_cb);
	}

	btd_register_adapter_driver(&policy_driver);

	return 0;
}

static void policy_exit(void)
{
	btd_remove_disconnect_cb(disconnect_cb);
	btd_remove_conn_fail_cb(conn_fail_cb);

	if (reconnect_uuids)
		g_strfreev(reconnect_uuids);

	free(reconnect_intervals);

	g_slist_free_full(reconnects, reconnect_destroy);

	g_slist_free_full(devices, policy_remove);

	btd_service_remove_state_cb(service_id);

	btd_unregister_adapter_driver(&policy_driver);
}

BLUETOOTH_PLUGIN_DEFINE(policy, VERSION, BLUETOOTH_PLUGIN_PRIORITY_DEFAULT,
						policy_init, policy_exit)
