/*
 * This file is part of the libsigrok project.
 *
 * Copyright (C) 2017 Peter Turczak <peter@turczak.de>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include "protocol.h"
/* Note: No spaces allowed because of sigrok-cli. */
static const char *logic_pattern_str[] = {
	"sigrok",
	"random",
	"incremental",
	"walking-one",
	"walking-zero",
	"all-low",
	"all-high",
	"squid",
};

static const uint32_t scanopts[] = {
	SR_CONF_NUM_LOGIC_CHANNELS,
//	SR_CONF_NUM_ANALOG_CHANNELS,
};

static const uint32_t drvopts[] = {
	SR_CONF_LOGIC_ANALYZER,
	SR_CONF_OSCILLOSCOPE,
};

static const uint32_t devopts[] = {
	SR_CONF_CONTINUOUS,
	SR_CONF_LIMIT_SAMPLES | SR_CONF_GET | SR_CONF_SET,
	SR_CONF_LIMIT_MSEC | SR_CONF_GET | SR_CONF_SET,
	SR_CONF_SAMPLERATE | SR_CONF_GET | SR_CONF_SET | SR_CONF_LIST,
};

static const uint32_t devopts_cg_logic[] = {
	SR_CONF_PATTERN_MODE | SR_CONF_GET | SR_CONF_SET | SR_CONF_LIST,
};

static const uint32_t devopts_cg_analog_group[] = {
	SR_CONF_AMPLITUDE | SR_CONF_GET | SR_CONF_SET,
};

static const uint32_t devopts_cg_analog_channel[] = {
	SR_CONF_PATTERN_MODE | SR_CONF_GET | SR_CONF_SET | SR_CONF_LIST,
	SR_CONF_AMPLITUDE | SR_CONF_GET | SR_CONF_SET,
};

#define DEFAULT_NUM_LOGIC_CHANNELS	8
#define DEFAULT_LOGIC_PATTERN		PATTERN_SIGROK

#define DEFAULT_NUM_ANALOG_CHANNELS	0
#define DEFAULT_ANALOG_AMPLITUDE	10

static const uint64_t samplerates[] = {
	SR_HZ(1),
	SR_GHZ(1),
	SR_HZ(1),
};

static GSList *scan(struct sr_dev_driver *di, GSList *options)
{
	struct dev_context *devc;
	struct sr_dev_inst *sdi;
	struct sr_channel *ch;
	struct sr_channel_group *cg;//, *acg;
	struct sr_config *src;
	//struct analog_gen *ag;
	GSList *l;
	int num_logic_channels, i;
	char channel_name[16];
	
	num_logic_channels = DEFAULT_NUM_LOGIC_CHANNELS;
	//num_analog_channels = DEFAULT_NUM_ANALOG_CHANNELS;
	for (l = options; l; l = l->next) {
		src = l->data;
		switch (src->key) {
		case SR_CONF_NUM_LOGIC_CHANNELS:
			num_logic_channels = g_variant_get_int32(src->data);
			break;
//		case SR_CONF_NUM_ANALOG_CHANNELS:
//			return SR_ERR_NA;
//			break;
		}
	}

	sdi = g_malloc0(sizeof(struct sr_dev_inst));
	sdi->status = SR_ST_INACTIVE;
	sdi->model = g_strdup("Demo device");

	devc = g_malloc0(sizeof(struct dev_context));
	devc->cur_samplerate = SR_KHZ(200);
	devc->num_logic_channels = num_logic_channels;
	devc->logic_unitsize = (devc->num_logic_channels + 7) / 8;
	//devc->num_analog_channels = num_analog_channels;
	hp16700_scan(devc);

	if (num_logic_channels > 0) {
		/* Logic channels, all in one channel group. */
		cg = g_malloc0(sizeof(struct sr_channel_group));
		cg->name = g_strdup("Logic");
		for (i = 0; i < num_logic_channels; i++) {
			sprintf(channel_name, "D%d", i);
			ch = sr_channel_new(sdi, i, SR_CHANNEL_LOGIC, TRUE, channel_name);
			cg->channels = g_slist_append(cg->channels, ch);
		}
		sdi->channel_groups = g_slist_append(NULL, cg);
	}

	devc->ch_ag = g_hash_table_new(g_direct_hash, g_direct_equal);

	sdi->priv = devc;

	return std_scan_complete(di, g_slist_append(NULL, sdi));
}

static int dev_open(struct sr_dev_inst *sdi)
{
	struct dev_context *devc = sdi->priv;
	struct addrinfo hints;
	struct addrinfo *results, *res;
	int err;

	/* TODO: get handle from sdi->conn and open it. */
	devc->address="192.168.0.47";
	devc->port="6500";

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	err = getaddrinfo(devc->address, devc->port, &hints, &results);

	if (err) {
		sr_err("Address lookup failed: %s:%s: %s", devc->address,
			devc->port, gai_strerror(err));
		return SR_ERR;
	}

	for (res = results; res; res = res->ai_next) {
		if ((devc->socket = socket(res->ai_family, res->ai_socktype,
						res->ai_protocol)) < 0)
			continue;
		if (connect(devc->socket, res->ai_addr, res->ai_addrlen) != 0) {
			close(devc->socket);
			devc->socket = -1;
			continue;
		}
		break;
	}

	freeaddrinfo(results);

	if (devc->socket < 0) {
		sr_err("Failed to connect to %s:%s: %s", devc->address,
			devc->port, g_strerror(errno));
		return SR_ERR;
	}

	return SR_OK;
}

static int dev_close(struct sr_dev_inst *sdi)
{
	(void)sdi;

	/* TODO: get handle from sdi->conn and close it. */

	return SR_OK;
}

static int config_get(uint32_t key, GVariant **data,
	const struct sr_dev_inst *sdi, const struct sr_channel_group *cg)
{
	int ret;

	(void)sdi;
	(void)data;
	(void)cg;

	ret = SR_OK;
	switch (key) {
	/* TODO */
	default:
		return SR_ERR_NA;
	}

	return ret;
}

//TODO: Warum **data (from demo/api.c)?!
static int config_set(uint32_t key, GVariant **data,
	const struct sr_dev_inst *sdi, const struct sr_channel_group *cg)
{
	int ret = SR_ERR_NA;
	struct sr_channel *ch;
	
	if (!cg) {
		switch (key) {
		case SR_CONF_SCAN_OPTIONS:
		case SR_CONF_DEVICE_OPTIONS:
			return STD_CONFIG_LIST(key, data, sdi, cg, scanopts, drvopts, devopts);
		case SR_CONF_SAMPLERATE:
			*data = std_gvar_samplerates_steps(ARRAY_AND_SIZE(samplerates));
			break;
		default:
			return SR_ERR_NA;
		}
	} else {
		ch = cg->channels->data;
		switch (key) {
		case SR_CONF_DEVICE_OPTIONS:
			if (ch->type == SR_CHANNEL_LOGIC)
				*data = std_gvar_array_u32(ARRAY_AND_SIZE(devopts_cg_logic));
			else if (ch->type == SR_CHANNEL_ANALOG) {
				if (strcmp(cg->name, "Analog") == 0)
					*data = std_gvar_array_u32(ARRAY_AND_SIZE(devopts_cg_analog_group));
				else
					*data = std_gvar_array_u32(ARRAY_AND_SIZE(devopts_cg_analog_channel));
			}
			else
				return SR_ERR_BUG;
			break;
		default:
			return SR_ERR_NA;
		}
	}

	return ret;
}

static int config_list(uint32_t key, GVariant **data,
	const struct sr_dev_inst *sdi, const struct sr_channel_group *cg)
{
	int ret;

	(void)sdi;
	(void)data;
	(void)cg;
	struct sr_channel *ch;

	ret = SR_OK;
	if (!cg) {
		switch (key) {
		case SR_CONF_SCAN_OPTIONS:
		case SR_CONF_DEVICE_OPTIONS:
			return STD_CONFIG_LIST(key, data, sdi, cg, scanopts, drvopts, devopts);
		case SR_CONF_SAMPLERATE:
			*data = std_gvar_samplerates_steps(ARRAY_AND_SIZE(samplerates));
			break;
		default:
			return SR_ERR_NA;
		}
	} else {
		ch = cg->channels->data;
		switch (key) {
		case SR_CONF_DEVICE_OPTIONS:
			if (ch->type == SR_CHANNEL_LOGIC)
				*data = std_gvar_array_u32(ARRAY_AND_SIZE(devopts_cg_logic));
			else if (ch->type == SR_CHANNEL_ANALOG) {
				if (strcmp(cg->name, "Analog") == 0)
					*data = std_gvar_array_u32(ARRAY_AND_SIZE(devopts_cg_analog_group));
				else
					*data = std_gvar_array_u32(ARRAY_AND_SIZE(devopts_cg_analog_channel));
			}
			else
				return SR_ERR_BUG;
			break;
		case SR_CONF_PATTERN_MODE:
			/* The analog group (with all 4 channels) shall not have a pattern property. */
			if (strcmp(cg->name, "Analog") == 0)
				return SR_ERR_NA;
			// TODO: Channel list from analyzer
			if (ch->type == SR_CHANNEL_LOGIC)
				*data = g_variant_new_strv(ARRAY_AND_SIZE(logic_pattern_str));
			else
				return SR_ERR_NA;
			break;
		default:
			return SR_ERR_NA;
		}
	}

	return ret;
}

static int dev_acquisition_start(const struct sr_dev_inst *sdi)
{
	/* TODO: configure hardware, reset acquisition state, set up
	 * callbacks and send header packet. */

	(void)sdi;

	return SR_OK;
}

static int dev_acquisition_stop(struct sr_dev_inst *sdi)
{
	/* TODO: stop acquisition. */

	(void)sdi;

	return SR_OK;
}

SR_PRIV struct sr_dev_driver hp16700_driver_info = {
	.name = "hp16700",
	.longname = "hp16700",
	.api_version = 1,
	.init = std_init,
	.cleanup = std_cleanup,
	.scan = scan,
	.dev_list = std_dev_list,
	.dev_clear = std_dev_clear,
	.config_get = config_get,
	.config_set = config_set,
	.config_list = config_list,
	.dev_open = dev_open,
	.dev_close = dev_close,
	.dev_acquisition_start = dev_acquisition_start,
	.dev_acquisition_stop = dev_acquisition_stop,
	.context = NULL,
};

SR_REGISTER_DEV_DRIVER(hp16700_driver_info);
