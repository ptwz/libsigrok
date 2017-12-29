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
	GSList *l;
	struct sr_config *src;
	struct sr_dev_inst *sdi;
	struct dev_context *devc;
	const char *conn = NULL;
	gchar **params;
	int i, maxch;

	maxch = NUM_CHANNELS;
	for (l = options; l; l = l->next) {
		src = l->data;
//		if (src->key == SR_CONF_NUM_LOGIC_CHANNELS)
//			maxch = g_variant_get_int32(src->data);
		if (src->key == SR_CONF_CONN)
			conn = g_variant_get_string(src->data, NULL);
	}

	params = g_strsplit(conn, "/", 0);
	if (!params || !params[1] || !params[2]) {
		sr_err("Invalid Parameters.");
		g_strfreev(params);
		return NULL;
	}
	if (g_ascii_strncasecmp(params[0], "tcp", 3)) {
		sr_err("Only TCP (tcp-raw) protocol is currently supported.");
		g_strfreev(params);
		return NULL;
	}

//	maxch = (maxch > 8) ? NUM_CHANNELS : 8;

	sdi = g_new0(struct sr_dev_inst, 1);
	sdi->status = SR_ST_INACTIVE;
	sdi->model = g_strdup("HP16700");
	sdi->version = g_strdup("1.0");

	devc = g_malloc0(sizeof(struct dev_context));

	/* Default non-zero values (if any) */
	devc->fd = -1;
	devc->tcp_buffer = 0;

	devc->read_timeout = 1000 * 1000;
	//devc->beaglelogic = &beaglelogic_tcp_ops;
	devc->address = g_strdup(params[1]);
	devc->port = g_strdup(params[2]);
	g_strfreev(params);

	if (hp16700_open(devc) != SR_OK)
		goto err_free;
	//if (beaglelogic_tcp_detect(devc) != SR_OK)
	if (hp16700_scan(devc) != SR_OK)
		goto err_free;
	if (hp16700_close(devc) != SR_OK)
		goto err_free;
	sr_info("BeagleLogic device found at %s : %s",
		devc->address, devc->port);

	/* Fill the channels */
	for (i = 0; i < maxch; i++)
		sr_channel_new(sdi, i, SR_CHANNEL_LOGIC, TRUE,
				channel_names[i]);

	sdi->priv = devc;

	return std_scan_complete(di, g_slist_append(NULL, sdi));

err_free:
	g_free(sdi->model);
	g_free(sdi->version);
	g_free(devc->address);
	g_free(devc->port);
	g_free(devc);
	g_free(sdi);

	return NULL;
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
