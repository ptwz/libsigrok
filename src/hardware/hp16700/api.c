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
	SR_CONF_CONN,
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
	struct sr_channel *ch;
	const char *conn = NULL;
	gchar **params;
	int channel_idx = 0;
	int i = 0;

	sr_info("scan");

	for (l = options; l; l = l->next) {
		src = l->data;
		if (src->key == SR_CONF_CONN)
			conn = g_variant_get_string(src->data, NULL);
	}

	if (conn)
		params = g_strsplit(conn, "/", 0);
	else
		return NULL;

	if (!params || !params[0] || !params[1] || !params[2] ) {
		sr_err("Invalid Parameters.");
		g_strfreev(params);
		return NULL;
	}
	for (int i=0; i<3; i++)
		sr_info("params[%d]=%s", i, params[i]);
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
	devc->tcp_buffer = 0;

	devc->read_timeout = 1000 * 1000;
	//devc->beaglelogic = &beaglelogic_tcp_ops;
	devc->address = g_strdup(params[1]);
	devc->port = g_strdup(params[2]);
	g_strfreev(params);

	sr_info("HIER");
	if (hp16700_open(devc) != SR_OK)
		goto err_free;
	//if (beaglelogic_tcp_detect(devc) != SR_OK)
	if (hp16700_scan(devc) != SR_OK)
		goto err_free;
	if (hp16700_close(devc) != SR_OK)
		goto err_free;
	sr_info("HP16700 device found at %s : %s",
		devc->address, devc->port);

	int module_base = 0;
	struct sr_channel *chan = NULL;

	for (l = devc->modules; l != NULL; l = l->next)
	{
		struct dev_module *module = l->data;
		struct sr_channel_group *cg = NULL;
		
		sr_info("HALLO");
		sr_info("module = %04x, devc->modules=%04x", module, devc->modules);
		if (module == NULL){
			continue;
		}
		module_base += 1024;

		char **changroup_names = NULL;
		char **chan_names = NULL;
		int chan_type;

		if (module->type == HP16700_SCOPE)
		{
			chan_type = SR_CHANNEL_ANALOG;
			const char *names[] = {"Analog", NULL};
			const char *channels[] = { "CH1", "CH2", NULL};
			changroup_names = (char **)names;
			chan_names = (char **)channels;
		}
		else if (strcmp(module->name, "16550A") == 0)
		{
			chan_type = SR_CHANNEL_LOGIC;
			const char *names[] = { "1", "2", "3", "4", "5", "6", NULL};
			const char *channels[] = { "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", NULL };
			changroup_names = (char **)names;
			chan_names = (char **)channels;
		}
		for ( ; *changroup_names != NULL ; changroup_names++ )
		{
			char group_name[1024];
			memset(group_name, 0, sizeof(group_name));
			snprintf(group_name, sizeof(group_name)-1, "%s-%s", module->name, *changroup_names);

			cg = g_malloc0(sizeof(struct sr_channel_group));
			cg->name = g_strdup(group_name);
			cg->priv = module; // TODO: any good?!

			channel_idx += 64;
			i = 0;
			for ( ; *chan_names != NULL ; chan_names++)
			{
				ch = sr_channel_new(sdi, channel_idx + i, SR_CHANNEL_ANALOG,  1, *chan_names);
				cg->channels = g_slist_append(cg->channels, ch);
				i++;

			}
			sdi->channel_groups = g_slist_append(sdi->channel_groups, cg);
		}
	}
	/* Fill the channels */
	//for (i = 0; i < maxch; i++)
	//	sr_channel_new(sdi, i, SR_CHANNEL_LOGIC, TRUE,
	//			channel_names[i]);

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

static int dev_open(struct sr_dev_inst *sdi)
{
	struct dev_context *devc = sdi->priv;

	sr_info("dev_open");
	/* Open BeagleLogic */
	if (hp16700_open(devc))
		return SR_ERR;

	/* Set fd and local attributes */
	/* devc->pollfd.fd = devc->socket;
	devc->pollfd.events = G_IO_IN;
	devc->pollfd.revents = 0;
	*/

	/* Get the default attributes */
	//devc->beaglelogic->get_samplerate(devc);
	//devc->beaglelogic->get_sampleunit(devc);
	//devc->beaglelogic->get_buffersize(devc);
	//devc->beaglelogic->get_bufunitsize(devc);

	/* Set the triggerflags to default for continuous capture unless we
	 * explicitly limit samples using SR_CONF_LIMIT_SAMPLES */
	//devc->triggerflags = BL_TRIGGERFLAGS_CONTINUOUS;
	//devc->beaglelogic->set_triggerflags(devc);

	/* Map the kernel capture FIFO for reads, saves 1 level of memcpy */
/*	if (devc->beaglelogic == &beaglelogic_native_ops) {
		if (devc->beaglelogic->mmap(devc) != SR_OK) {
			sr_err("Unable to map capture buffer");
			devc->beaglelogic->close(devc);
			return SR_ERR;
		}
	} else {
		devc->tcp_buffer = g_malloc(TCP_BUFFER_SIZE);
	}
*/
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
