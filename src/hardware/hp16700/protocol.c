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

SR_PRIV int hp16700_open(struct dev_context *devc)
{
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

SR_PRIV hp16700_close(struct dev_context *devc)
{
	if (devc->socked > 0) {
		close(devc->socket);
		devc->socket = 0;
	}
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

SR_PRIV int hp16700_get_string(struct dev_context *devc, const char *cmd,
				      char **tcp_resp)
{
	GString *response = g_string_sized_new(1024);
	int len;
	gint64 timeout;

	if (cmd) {
		if (hp16700_send_cmd(devc, cmd) != SR_OK)
			return SR_ERR;
	}

	timeout = g_get_monotonic_time() + devc->read_timeout;
	len = hp16700_read_data(devc, response->str,
					response->allocated_len);

	if (len < 0) {
		g_string_free(response, TRUE);
		return SR_ERR;
	}

	if (len > 0)
		g_string_set_size(response, len);

	if (g_get_monotonic_time() > timeout) {
		sr_err("Timed out waiting for response.");
		g_string_free(response, TRUE);
		return SR_ERR_TIMEOUT;
	}

	/* Remove trailing newline if present */
	if (response->len >= 1 && response->str[response->len - 1] == '\n')
		g_string_truncate(response, response->len - 1);

	/* Remove trailing carriage return if present */
	if (response->len >= 1 && response->str[response->len - 1] == '\r')
		g_string_truncate(response, response->len - 1);

	sr_spew("Got response: '%.70s', length %" G_GSIZE_FORMAT ".",
		response->str, response->len);

	*tcp_resp = g_string_free(response, FALSE);

	return SR_OK;
}

SR_PRIV int hp16700_get_int(struct dev_context *devc,
				   const char *cmd, int *response)
{
	int ret;
	char *resp = NULL;

	ret = hp16700_get_string(devc, cmd, &resp);
	if (!resp && ret != SR_OK)
		return ret;

	if (sr_atoi(resp, response) == SR_OK)
		ret = SR_OK;
	else
		ret = SR_ERR_DATA;

	g_free(resp);

	return ret;
}

SR_PRIV int hp16700_scan(struct dev_context *devc)
{
	char *resp = NULL;
	int ret;
	gchar **results;
	gchar **line;
	GRegex *split_rgx;
	GError *err = NULL;
	
	split_rgx = g_regex_new(" +", 0, 0, &err);
	if (err == NULL){
		ret = hp16700_get_string(devc, "modules", &resp);

		results = g_strsplit(resp, "\n\r", 0);
		for (line = results; *line == NULL; line++){
			struct dev_module *module = g_malloc0(sizeof(struct dev_module));
			// TODO: Parse Logic/Analog lines
			gchar **columns;
			// Split to maximal six columns
			columns = g_regex_split_full(split_rgx, *line, -1, 0, 0, 6, &err);
			g_assert(err==NULL);
			int col_num=0;
			for (gchar** x=columns; *x != NULL; x++) 
				switch (col_num++){
					case 0: // Type 
						if (g_strcmp0(*x, "LA"))
							module->type = HP16700_LOGIC;
						else if (g_strcmp0(*x, "SC"))
							module->type = HP16700_SCOPE;
						else if (g_strcmp0(*x, "PA"))
							module->type = HP16700_PATTERN_GEN;
						else if (g_strcmp0(*x, "EM"))
							module->type = HP16700_EMU;
						else module->type = HP16700_UNKNOWN;
						break;
					case 1: // Slot, may also be split into two
						module->slot = g_strdup(*x);
						break;
					case 2: // State
						//TODO: Use or discard?!
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
			
			g_strfreev(columns);
		}
		g_strfreev(results);
		g_regex_unref(split_rgx);
		ret = SR_OK;
		}
	else
		ret = SR_ERR;

	g_free(resp);

	return ret;
}
