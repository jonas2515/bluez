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

struct reconnect_data {
	struct btd_device *dev;
	bool reconnect;
	bool autoconnect;
	GSList *services;
	unsigned int timer;
	bool timer_active;
	unsigned int attempt;
	bool on_resume;
	bool is_prioritized;
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

static gboolean has_prioritized_reconnects = FALSE;
unsigned int queue_autoconnect_all_id = 0; 

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

static struct reconnect_data *reconnect_find(struct btd_device *dev)
{
	GSList *l;

	for (l = reconnects; l; l = g_slist_next(l)) {
		struct reconnect_data *reconnect = l->data;

		if (reconnect->dev == dev)
			return reconnect;
	}

	return NULL;
}

static void policy_connect(struct policy_data *data,
						struct btd_service *service)
{
	struct btd_profile *profile = btd_service_get_profile(service);
	struct reconnect_data *reconnect;

	reconnect = reconnect_find(btd_service_get_device(service));
	if (reconnect && reconnect->timer_active)
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
	if (service != NULL) {
DBG ("sink timer expired, trying to connect");
		policy_connect(data, service);
}

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
				if (data->sink_retries < SINK_RETRIES) {
DBG("we went from CONNECTING into DISCONNECTED, we'll try again after sink timer");
					policy_set_sink_timer(data);
				} else
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
		} /*else if (btd_service_get_state(controller) !=
						BTD_SERVICE_STATE_DISCONNECTED)
			policy_disconnect(data, controller);*/
		break;
	case BTD_SERVICE_STATE_CONNECTING:
		break;
	case BTD_SERVICE_STATE_CONNECTED:
		if (data->sink_timer > 0) {
			timeout_remove(data->sink_timer);
			data->sink_timer = 0;
		}

		if (btd_service_get_state(controller) == BTD_SERVICE_STATE_DISCONNECTED) {
			if (btd_service_is_initiator(service)) {
		DBG("a2dp connected, now connecting avrcp");
				policy_connect(data, controller);
			} else {
		DBG("a2dp connected, now connecting avrcp with timouet");
				policy_set_ct_timer(data, CONTROL_CONNECT_TIMEOUT);
	}
		}
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
		if (btd_service_get_state(sink) == BTD_SERVICE_STATE_DISCONNECTED) {
			if (btd_service_is_initiator(service)) {
		DBG("hs connected, now connecting sink");
				policy_connect(data, sink);
			} else {
	DBG("hs connected, now connecting sink with timeout");
				policy_set_sink_timer(data);
	}
		}



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
		}/* else if (btd_service_get_state(target) !=
						BTD_SERVICE_STATE_DISCONNECTED)
			policy_disconnect(data, target);*/
		break;
	case BTD_SERVICE_STATE_CONNECTING:
		break;
	case BTD_SERVICE_STATE_CONNECTED:
		if (data->source_timer > 0) {
			timeout_remove(data->source_timer);
			data->source_timer = 0;
		}

		if (btd_service_get_state(target) == BTD_SERVICE_STATE_DISCONNECTED) {
			if (btd_service_is_initiator(service))
				policy_connect(data, target);
			else
				policy_set_tg_timer(data, CONTROL_CONNECT_TIMEOUT);
		}
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

static void reconnect_reset(struct reconnect_data *reconnect)
{
	GSList *l;

	reconnect->attempt = 0;
	reconnect->timer_active = false;

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

static bool autoconnect_match(struct btd_service *service)
{
	struct btd_profile *profile = btd_service_get_profile(service);
	const char *uuid = profile->remote_uuid;
	char **str;

	if (!reconnect_uuids)
		return false;

	for (str = reconnect_uuids; *str; str++) {
		if (!bt_uuid_strcmp(uuid, *str))
			return true;
	}

	return false;

const bdaddr_t head;
str2ba ("94:DB:56:7F:51:19", &head);
//str2ba ("04:21:44:BD:46:73", &head);

//	DBG("matching %2.2X:%2.2X:%2.2X and %x", head);

 if (device_bdaddr_cmp (btd_service_get_device(service), &head) == 0)
   return true;

	return false;
}

static struct reconnect_data *reconnect_add(struct btd_device *dev)
{
	struct reconnect_data *reconnect;

	reconnect = reconnect_find(dev);
	if (!reconnect) {
		reconnect = g_new0(struct reconnect_data, 1);
		reconnect->dev = dev;
		reconnects = g_slist_append(reconnects, reconnect);
	}

	return reconnect;
}

static void reconnect_destroy(gpointer data)
{
	struct reconnect_data *reconnect = data;

	if (reconnect->timer > 0)
		timeout_remove(reconnect->timer);

	g_slist_free_full(reconnect->services,
					(GDestroyNotify) btd_service_unref);
	g_free(reconnect);
}

static void reconnect_remove(struct btd_service *service)
{
	struct btd_device *dev = btd_service_get_device(service);
	struct reconnect_data *reconnect;
	GSList *l;

	reconnect = reconnect_find(dev);
	if (!reconnect)
		return;

	reconnect_reset (reconnect);

	l = g_slist_find(reconnect->services, service);
	if (!l)
		return;

	reconnect->services = g_slist_delete_link(reconnect->services, l);
	btd_service_unref(service);

	if (reconnect->services)
		return;

	reconnects = g_slist_remove(reconnects, reconnect);



	g_free(reconnect);
}

static const char *state2str(btd_service_state_t state)
{
	switch (state) {
	case BTD_SERVICE_STATE_UNAVAILABLE:
		return "unavailable";
	case BTD_SERVICE_STATE_DISCONNECTED:
		return "disconnected";
	case BTD_SERVICE_STATE_CONNECTING:
		return "connecting";
	case BTD_SERVICE_STATE_CONNECTED:
		return "connected";
	case BTD_SERVICE_STATE_DISCONNECTING:
		return "disconnecting";
	}

	return NULL;
}

static int
compare_last_seen (gconstpointer a, gconstpointer b)
{
	struct btd_device *d_1 = ((struct reconnect_data *)a)->dev;
	struct btd_device *d_2 = ((struct reconnect_data *)b)->dev;

	return btd_device_get_last_seen_time (d_1, BDADDR_BREDR) < btd_device_get_last_seen_time (d_2, BDADDR_BREDR);
}

/* Autoconnect all services with autoconnect enabled in least-recently-used
 * order.
 */
static gboolean
autoconnect_all_lru (gpointer data)
{
	struct btd_adapter *adapter = data;

	DBG("Autoconnecting all services");

	time_t last_seen_time = 0;

	reconnects = g_slist_sort (reconnects, compare_last_seen);

	GSList *l;
	for (l = reconnects; l; l = l->next) {
		struct reconnect_data *reconnect = l->data;

		if (reconnect->autoconnect &&
			device_get_adapter(reconnect->dev) == adapter) {
			int err;

reconnect->attempt = 1;

				error("Autoconnecting services for device %s",
					device_get_path (reconnect->dev));

			err = btd_device_connect_services(reconnect->dev, reconnect->services);
			if (err < 0) {
				error("Autoconnecting services for device %s failed: %s (%d)",
					device_get_path (reconnect->dev), strerror(-err), -err);
			}
		}
	}

	DBG("");

	queue_autoconnect_all_id = 0;
	return G_SOURCE_REMOVE;
}

static void
queue_autoconnect_all_lru (struct btd_adapter *adapter)
{
	if (queue_autoconnect_all_id != 0)
		return;

//	queue_autoconnect_all_id = g_idle_add_full(G_PRIORITY_LOW, autoconnect_all_lru, adapter, NULL);

	queue_autoconnect_all_id = g_timeout_add(500, autoconnect_all_lru, adapter); 
}

static void service_cb(struct btd_service *service,
						btd_service_state_t old_state,
						btd_service_state_t new_state,
						void *user_data)
{
	struct btd_profile *profile = btd_service_get_profile(service);
	struct reconnect_data *reconnect;

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

	/*
	 * If the service went away remove it from the reconnection
	 * tracking. The function will remove the entire tracking data
	 * if this was the last service for the device.
	 */
	if (new_state == BTD_SERVICE_STATE_UNAVAILABLE) {
		reconnect_remove(service);
		return;
	}

	struct btd_device *dev = btd_service_get_device(service);

	reconnect = reconnect_find(dev);
	if (new_state == BTD_SERVICE_STATE_CONNECTED)
		reconnect->attempt = 0;


//	DBG("Service (%p) state change %s %s: %s -> %s", service, device_get_path(dev), profile->name, state2str(old_state), state2str(new_state));

	/*
	 * Add an entry to track reconnections. The function will return
	 * an existing entry if there is one.
	 */

	/* Service got added, check whether re- and autoconnecting are enabled */
	if (old_state == BTD_SERVICE_STATE_UNAVAILABLE &&
	    new_state == BTD_SERVICE_STATE_DISCONNECTED) {
		if (!reconnect)
			reconnect = reconnect_add(dev);

		reconnect->timer_active = false;

		reconnect->reconnect |= reconnect_match(profile->remote_uuid);
		reconnect->autoconnect |= autoconnect_match(service);

		if (reconnect->autoconnect) {
			if (!g_slist_find(reconnect->services, service))
			reconnect->services = g_slist_append(reconnect->services,
								btd_service_ref(service));
		}

		DBG("Service appeared, reconnect %d autoconnect %d", reconnect->reconnect, reconnect->autoconnect);

		if (reconnect->autoconnect &&
			btd_adapter_get_powered(device_get_adapter(dev))) {
			DBG("Adapter is powered, trying to autoconnect");
			queue_autoconnect_all_lru(device_get_adapter(dev));
		}
	}
/*
	if (reconnect->autoconnect &&
	    old_state == BTD_SERVICE_STATE_UNAVAILABLE &&
	    new_state == BTD_SERVICE_STATE_DISCONNECTED) {
//		struct btd_device *dev = btd_service_get_device(service);

		if (btd_adapter_get_powered(device_get_adapter(dev))) {
DBG("Adapter is powered, trying to connect");
			btd_service_connect(service);
}

	}
*/

}

static bool reconnect_timeout(gpointer data)
{
	struct reconnect_data *reconnect = data;
	int err;


	if (has_prioritized_reconnects) 
		return TRUE;

	DBG("Attempting reconnect %s",device_get_path(reconnect->dev));

#if 0
	if (has_prioritized_reconnects) {
		if (reconnect->is_prioritized) {
			GSList *l;

			reconnect->is_prioritized = FALSE;

			has_prioritized_reconnects = FALSE;
			for (l = reconnects; l; l = l->next) {
				struct reconnect_data *r = l->data;
				if (r->is_prioritized) {
					has_prioritized_reconnects = TRUE;
					break;
				}
			}
		} else {
			/* Prioritized reconnects should happen before non prioritized, so
			 * make the timeout continue until all priorized ones are done.
			 */
			DBG("Other reconnects are higher prio");
			return TRUE;
		}
	}
#endif

	/* Mark the GSource as invalid */
	reconnect->timer = 0;

	/* Mark any reconnect on resume as handled */
	reconnect->on_resume = false;

	err = btd_device_connect_services(reconnect->dev, reconnect->services);
	if (err < 0) {
		error("Reconnecting services failed: %s (%d)",
							strerror(-err), -err);

		/* Let the on_conn_failed() handler take care of trying again */
	}

	//reconnect->attempt++;

	return FALSE;
}

static void reconnect_set_timer(struct reconnect_data *reconnect, int timeout)
{
	static int interval_timeout = 0;

	reconnect->timer_active = true;

	if (reconnect->attempt <= reconnect_intervals_len)
		interval_timeout = reconnect_intervals[reconnect->attempt - 1];

	if (timeout < 0)
		timeout = interval_timeout;

	DBG("attempt %u/%zu %d seconds", reconnect->attempt,
						reconnect_attempts, timeout);

	reconnect->timer = timeout_add_seconds(timeout, reconnect_timeout,
						reconnect, NULL);
}

static void disconnect_cb(struct btd_device *dev, uint8_t reason)
{
	struct reconnect_data *reconnect;

	DBG("reason %u", reason);

	/* Only attempt reconnect for the following reasons */
	if (reason != MGMT_DEV_DISCONN_TIMEOUT &&
	    reason != MGMT_DEV_DISCONN_LOCAL_HOST_SUSPEND)
		return;

	reconnect = reconnect_find(dev);
	if (!reconnect || !reconnect->reconnect)
		return;

	reconnect_reset(reconnect);

	DBG("Device %s identified for auto-reconnection", device_get_path(dev));

	switch (reason) {
	case MGMT_DEV_DISCONN_LOCAL_HOST_SUSPEND:
		if (btd_device_get_service(dev, A2DP_SINK_UUID)) {
			DBG("%s configured to reconnect on resume",
				device_get_path(dev));

			reconnect->on_resume = true;

			/* If the kernel supports resume events, it is
			 * preferable to set the reconnect timer there as it is
			 * a more predictable delay.
			 */
			if (!btd_has_kernel_features(KERNEL_HAS_RESUME_EVT))
				reconnect_set_timer(reconnect, resume_delay);
		}
		break;
	case MGMT_DEV_DISCONN_TIMEOUT:
		reconnect_set_timer(reconnect, -1);
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
		struct reconnect_data *reconnect = l->data;

		if (reconnect->on_resume &&
		    device_get_adapter(reconnect->dev) == adapter) {
			reconnect_set_timer(reconnect, resume_delay);
		}
	}
}

static void policy_adapter_powered_changed(struct btd_adapter *adapter,
											gboolean powered)
{
	if (!powered)
		return;

	DBG("Device powered");

	autoconnect_all_lru(adapter);
}

static void conn_fail_cb(struct btd_device *dev, uint8_t status)
{
	struct reconnect_data *reconnect;



	reconnect = reconnect_find(dev);
	if (!reconnect || !reconnect->reconnect)
		return;

	/* We might get more than a single connection failure if we connect to
	 * more than a single service, so bail out if there's already a timer
	 * active.
	 */
	if (reconnect->timer > 0)
		return;



	/* NO_RESOURCES is a special one, it means that we're trying to connect
	 * too many devices at once. Say the card only supports 2 connection
	 * attempts at once but we want to connect to 3 devices. Instead of trying
	 * to connect to device number 1 again and again (and thus keeping the
	 * slot on the card blocked), we want to give device number 3 a chance too.
	 */
	if (status == MGMT_STATUS_NO_RESOURCES)
		return;

	DBG("Connection to %s failed, because %u", device_get_path(dev), status);

	reconnect->attempt++;


	GSList *l;

	has_prioritized_reconnects = FALSE;

	for (l = reconnects; l; l = l->next) {
		struct reconnect_data *r = l->data;

		/* Implementing the policy from the comment above, do reconnect attempts
		 * in lock-step.
		 */
		if (r->attempt == reconnect->attempt - 1) {
			has_prioritized_reconnects = TRUE;
			int err;

			error("Autoconnecting services for device %s",
				device_get_path (r->dev));

			err = btd_device_connect_services(r->dev, r->services);
			if (err == -EBUSY)
				continue; // fine

			if (err < 0) {
				error("failed: %s (%d)",
									strerror(-err), -err);
				/* Let the on_conn_failed() handler take care of trying again */
			}
		 }
	}


	/* Give up if we were powered off */
	if (status == MGMT_STATUS_NOT_POWERED) {
		reconnect_reset(reconnect);
		return;
	}



	/* Reset if ReconnectAttempts was reached */
	if (reconnect->attempt - 1 == reconnect_attempts) {
		reconnect_reset(reconnect);
		return;
	}



	reconnect_set_timer(reconnect, -1);
}

static int policy_adapter_probe(struct btd_adapter *adapter)
{
	DBG("auto %d", auto_enable);

	if (auto_enable) {
DBG("Restoring powered");
		btd_adapter_restore_powered(adapter);
}

	service_id = btd_service_add_state_cb(service_cb, NULL);

	return 0;
}

static struct btd_adapter_driver policy_driver = {
	.name	= "policy",
	.probe	= policy_adapter_probe,
	.resume = policy_adapter_resume,
	.powered_changed = policy_adapter_powered_changed,
};

static int policy_init(void)
{
	GError *gerr = NULL;
	GKeyFile *conf;

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
