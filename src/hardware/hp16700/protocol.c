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
#include <arpa/inet.h>
#include "protocol.h"

SR_PRIV int hp16700_open(struct dev_context *devc)
{
	struct addrinfo hints;
	struct addrinfo *results, *res;
	int err;

	sr_info("hp16700_open");

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

SR_PRIV int hp16700_close(struct dev_context *devc)
{
	g_assert(devc != NULL);
	if (devc->socket > 0) {
		close(devc->socket);
		devc->socket = 0;
	}

	return SR_OK;
}

SR_PRIV int hp16700_send_cmd(struct dev_context *devc,
				    const char *format, ...)
{
	int len, out;
	va_list args, args_copy;
	char *buf;

	va_start(args, format);
	va_copy(args_copy, args);
	len = vsnprintf(NULL, 0, format, args_copy);
	va_end(args_copy);

	buf = g_malloc0(len + 2);
	vsprintf(buf, format, args);
	va_end(args);

	if (buf[len - 1] != '\n')
		buf[len] = '\n';

	out = send(devc->socket, buf, strlen(buf), 0);

	if (out < 0) {
		sr_err("Send error: %s", g_strerror(errno));
		return SR_ERR;
	}

	if (out < (int)strlen(buf)) {
		sr_dbg("Only sent %d/%lu bytes of command: '%s'.", out,
		       strlen(buf), buf);
	}

	sr_spew("Sent command: '%s'.", buf);

	g_free(buf);

	return SR_OK;
}

SR_PRIV int hp16700_read_data(struct dev_context *devc, char *buf,
				     int maxlen)
{
	int len;

	len = recv(devc->socket, buf, maxlen, 0);

	if (len < 0) {
		sr_err("Receive error: %s", g_strerror(errno));
		return SR_ERR;
	}

	return len;
}

SR_PRIV int hp16700_drain(struct dev_context *devc)
{
	char *buf = g_malloc(1024);
	fd_set rset;
	int ret, len = 0;
	struct timeval tv;

	FD_ZERO(&rset);
	FD_SET(devc->socket, &rset);

	/* 25ms timeout */
	tv.tv_sec = 0;
	tv.tv_usec = 25 * 1000;

	do {
		ret = select(devc->socket + 1, &rset, NULL, NULL, &tv);
		if (ret > 0)
			len += hp16700_read_data(devc, buf, 1024);
	} while (ret > 0);

	sr_spew("Drained %d bytes of data.", len);

	g_free(buf);

	return SR_OK;
}

SR_PRIV int hp16700_receive_data(int fd, int revents, void *cb_data)
{
	const struct sr_dev_inst *sdi;
	struct dev_context *devc;

	(void)fd;

	if (!(sdi = cb_data))
		return TRUE;

	if (!(devc = sdi->priv))
		return TRUE;

	if (revents == G_IO_IN) {
		/* TODO */
	}

	return TRUE;
}

SR_PRIV int hp16700_get_strings(struct dev_context *devc, const char *cmd,
				      GSList **tcp_resp, int linecount)
{
	int len;
	gint64 timeout;

	if (cmd) {
		if (hp16700_send_cmd(devc, cmd) != SR_OK)
			return SR_ERR;
	}

	timeout = g_get_monotonic_time() + devc->read_timeout;

	*tcp_resp = g_slist_alloc();
	
	while (linecount-- > 0)
	{
		GString *cur_line = g_string_sized_new(1024);
		len = hp16700_read_data(devc, cur_line->str,
						cur_line->allocated_len);

		if (len < 0) {
			g_string_free(cur_line, TRUE);
			return SR_ERR;
		}

		if (len > 0)
			g_string_set_size(cur_line, len);

		if (g_get_monotonic_time() > timeout) {
			sr_err("Timed out waiting for response.");
			g_string_free(cur_line, TRUE);
			return SR_ERR_TIMEOUT;
		}

		/* Remove trailing newline if present */
		if (cur_line->len >= 1 && cur_line->str[cur_line->len - 1] == '\n')
			g_string_truncate(cur_line, cur_line->len - 1);

		/* Remove trailing carriage return if present */
		if (cur_line->len >= 1 && cur_line->str[cur_line->len - 1] == '\r')
			g_string_truncate(cur_line, cur_line->len - 1);

		sr_spew("Got cur_line: '%.70s', length %" G_GSIZE_FORMAT ".",
			cur_line->str, cur_line->len);

		if ( g_str_has_prefix(cur_line->str, "->") )
			return SR_OK;

		*tcp_resp = g_slist_append(*tcp_resp, g_string_free(cur_line, FALSE));
	}
	return SR_OK;
}

SR_PRIV int hp16700_get_int(struct dev_context *devc,
				   const char *cmd, int *response)
{
	int ret;
	GSList *resp = NULL;

	(void)response;

	ret = hp16700_get_strings(devc, cmd, &resp, 1);
	if (!resp && ret != SR_OK)
		return ret;
/* FIXME
	if (sr_atoi(resp[0], (char *)response->data) == SR_OK)
		ret = SR_OK;
	else
		ret = SR_ERR_DATA;

	g_free(resp);
*/
	return ret;
}

SR_PRIV int hp16700_get_scope_info(struct dev_context *devc, struct dev_module *module)
{
	char cmd[1024];
	gchar **label_set;
	GSList *resp = NULL;
	GSList *curline;
	int res;
	int i;
	gboolean in_fields = FALSE;

	if (module->type == HP16700_LOGIC)
		snprintf(cmd, sizeof(cmd)-1, "analyzer -n %s -i", module->name);
	else
		snprintf(cmd, sizeof(cmd)-1, "scope -n %s -i", module->name);

	res = hp16700_get_strings(devc, cmd, &resp, 7);
	if (res != SR_OK)
		return res;
	
	/** Sample:
	  * Run ID: 515220299
	  * States: -16383..16384
	  * Times:  -1.638375e-05..1.638425e-05
	  * 3 labels
	  * "State Number" 32 bits signed integer
	  * "Time" 64 bits signed integer timescale picoseconds
	  * "Channel E1" 15 bits yincrement 1.2747e-05 (volts/bit) yorigin -2.0803e-01
	  * ->
	  */
	for (curline = resp; curline != NULL; curline = curline->next){
		if ( curline->data == NULL )
			continue;
		if (g_regex_match_simple("^States", curline->data, 0, 0)){
		} 
		else if (g_regex_match_simple("^Times", curline->data, 0, 0)){
		} 
		else if (g_regex_match_simple(" labels$", curline->data, 0, 0)){
			in_fields = TRUE;
			if ( module->label_infos != NULL)
			{
				g_hash_table_destroy(module->label_infos);
			}
			module->label_infos = g_hash_table_new(g_str_hash, g_str_equal);
		}
		else if (in_fields){
			label_set = g_strsplit(curline->data, "\"", 0);
			
			sr_info("in labels:");
			for ( i=0 ; label_set[i] != NULL; i++)
				sr_info("%s", g_strstrip(label_set[i]));

			g_hash_table_insert(module->label_infos, label_set[0], label_set[1]);
			g_strfreev(label_set);
		}
	}
	g_slist_free_full(resp, g_free);
	return res;
}

SR_PRIV int hp16700_get_binary(struct dev_context *devc, const char *cmd,
				      uint8_t **data)
{
	int len, expected_len;
	gint64 timeout;
	struct hp16700_bin_hdr hdr;

	if (cmd) {
		if (hp16700_send_cmd(devc, cmd) != SR_OK)
			return SR_ERR;
	}

	timeout = g_get_monotonic_time() + devc->read_timeout;

	// TODO: Make sure the whole header is read
	len = hp16700_read_data(devc, (char *)&hdr, sizeof(hdr));
	
	if (len != sizeof(hdr)){
		sr_err("Error reading binary data.");
		return SR_ERR;
	}
	
	expected_len = htonl(hdr.bytes_per_record) * htonl( hdr.frame_count );
	*data = g_malloc(expected_len);

	len = hp16700_read_data(devc, (char *)*data, expected_len);

	if (len < expected_len) {
		g_free( *data );
		return SR_ERR;
	}

	if (g_get_monotonic_time() > timeout) {
		sr_err("Timed out waiting for response.");
		g_free(*data);
		*data = NULL;
		return SR_ERR_TIMEOUT;
	}

	return SR_OK;
}

SR_PRIV int hp16700_scan(struct dev_context *devc)
{
	int ret;
	GRegex *split_rgx;
	GSList *results = NULL;
	GSList *line = NULL;
	GError *err = NULL;
	
	sr_info("hp16700_scan");
	g_assert(devc->modules == NULL);
	devc->modules = g_slist_alloc();

	split_rgx = g_regex_new("[\" ]+", 0, 0, &err);
	if (err == NULL){
		ret = hp16700_get_strings(devc, "modules", &results, 10);
		for (line = results; line != NULL; line = line->next){
			struct dev_module *module = g_malloc0(sizeof(struct dev_module));
			if (line->data == NULL)
				continue;
			// TODO: Parse Logic/Analog lines
			gchar **columns;
			// Split to maximal six columns
			columns = g_regex_split_full(split_rgx, (char*)line->data, -1, 0, 0, 6, &err);
			g_assert(err==NULL);
			int col_num=0;
			for (gchar** x = columns; *x != NULL; x++)
			{
				switch (col_num++){
					case 0: // Type 
						if (g_strcmp0(*x, "LA")==0)
							module->type = HP16700_LOGIC;
						else if (g_strcmp0(*x, "SC")==0)
							module->type = HP16700_SCOPE;
						else if (g_strcmp0(*x, "PA")==0)
							module->type = HP16700_PATTERN_GEN;
						else if (g_strcmp0(*x, "EM")==0)
							module->type = HP16700_EMU;
						else module->type = HP16700_UNKNOWN;
						break;
					case 1: // Slot, may also be split into two
						module->slot = g_strdup(*x);
						break;
					case 2: // State
						module->enabled = (**x == '1') ? TRUE:FALSE;
						break;
					case 3: // Name
						module->name = g_strdup(*x);
						break;
					case 4: // Model
						module->model = g_strdup(*x);
						break;
					case 5: // description
						module->description = g_strdup(*x);
						break;
				}
			}
			sr_info("Found a %d in slot %s, type %s.", module->type, module->slot, module->model);
			devc->modules = g_slist_append(devc->modules, module);
			g_strfreev(columns);
		}
		//g_strfreev(results);
		g_regex_unref(split_rgx);
		ret = SR_OK;
		}
	else
		ret = SR_ERR;

	return ret;
}
