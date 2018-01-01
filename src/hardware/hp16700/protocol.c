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
#include <stdlib.h>
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

	hp16700_drain(devc);
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
				     int maxlen, gboolean text)
{
	int len, remain_len, recvd_len;
	char *recv_tmp = g_malloc0( maxlen + 1);
	char *inptr = recv_tmp;
	char *outptr;

	remain_len = maxlen;
	recvd_len = 0;
	if (text)
		sr_info("Looking for text");
	do
	{
		len = recv(devc->socket, inptr, remain_len, 0);
		sr_info("recv'd len=%d, value='%s'", len, recv_tmp);

		if (len < 0) {
			sr_err("Receive error: %s", g_strerror(errno));
			return SR_ERR;
		}

		remain_len -= len;
		recvd_len += len;
		inptr += len;
	}
	while ( text
		 && ( strchr(recv_tmp, 0x0a) == NULL )
//		 && ( strchr(recv_tmp, '\r') == NULL )
		 && (remain_len > 0) );

	if (devc->tcp_buffer != NULL) {
		sr_info("have some buffer len=%d", devc->buffer_len);
		g_assert( devc->buffer_len > 0 );
		inptr = g_malloc0( devc->buffer_len + recvd_len );

		memcpy( inptr,                    devc->tcp_buffer, devc->buffer_len );
		memcpy( &inptr[devc->buffer_len], recv_tmp,         recvd_len );

		recvd_len += devc->buffer_len;

		g_free( recv_tmp );
		recv_tmp = inptr;

		g_free(devc->tcp_buffer);
		devc->tcp_buffer = NULL;
	}

	if (text && (strchr(recv_tmp, '\n') != NULL) )
	{
		sr_info("Text with newline");
		len = 0;
		for ( inptr = recv_tmp, outptr = buf ;
			((len<1) || (inptr[-1]!='\n')) && (recvd_len>0);
			inptr++, outptr++, recvd_len--, len++ )
		{
			*outptr = *inptr;
		}
		devc->tcp_buffer = g_memdup(inptr, recvd_len);
		devc->buffer_len = recvd_len;
	} else
	{
		sr_info("Text without newline/too big");
		remain_len = maxlen - recvd_len;
		if (remain_len < 0)
		{
			memcpy( buf, recv_tmp, maxlen );
			len = maxlen;
			devc->tcp_buffer = g_memdup(&recv_tmp[maxlen], -remain_len);
			devc->buffer_len = recvd_len;
		} else
		{
			memcpy( buf, recv_tmp, recvd_len );
			len = recvd_len;
		}
	}
	g_free( recv_tmp );

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

	if (devc->tcp_buffer != NULL)
	{
		g_free(devc->tcp_buffer);
		devc->buffer_len = 0;
	}
	do {
		ret = select(devc->socket + 1, &rset, NULL, NULL, &tv);
		if (ret > 0)
			len += hp16700_read_data(devc, buf, 1024, FALSE);
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
						cur_line->allocated_len, TRUE);

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

SR_PRIV void hp16700_free_label_descriptor(void *field)
{
	struct hp_data_label *label = field;
	g_assert(label != NULL);
	g_assert(label->name != NULL);

	g_free(label->name);
	g_free(label);
}

SR_PRIV struct hp_data_label *hp16700_parse_label_descriptor(gchar *label_string)
{
	// Reads one label from the input and creates label descriptor
	/*
	 * 3 labels
	 * "State Number" 32 bits signed integer
	 * "Time" 64 bits signed integer timescale picoseconds
	 * "Channel E1" 15 bits yincrement 1.2747e-05 (volts/bit) yorigin -2.0803e-01
	 */
	gchar *name, *descriptor;
	gchar **label_set = g_strsplit(label_string, "\"", 0);
	gchar **descriptor_words;
	struct hp_data_label r;
	int i;

	memset(&r, 0, sizeof(r));
	r.factor = 1.0;
	r.offset = 0;

	g_assert( g_strv_length(label_set) == 3);
	name = g_strstrip( label_set[1] );
	descriptor = g_strstrip( label_set[2] );

	descriptor_words = g_strsplit(descriptor, " ", 0);
	g_assert( g_strv_length(descriptor_words) > 2);

	r.name = g_strdup(name);
	r.bits = atoi(descriptor_words[0]);
	g_assert( strcmp(descriptor_words[1], "bits") == 0 );

	for (i=0; descriptor_words[i]!=NULL; i++)
	{
		sr_info("word = '%s'", descriptor_words[i]);
		if (strcmp(descriptor_words[i], "integer") == 0)
		{
			//
		}
		else if (strcmp(descriptor_words[i], "unsigned") == 0)
		{
			r.is_signed = FALSE;
		}
		else if (strcmp(descriptor_words[i], "signed") == 0)
		{
			r.is_signed = TRUE;
		}
		else if (strcmp(descriptor_words[i], "picoseconds") == 0)
		{
			r.factor = 10.0e-12;
		}
		else if (strcmp(descriptor_words[i], "nanoseconds") == 0)
		{
			r.factor = 10.0e-9;
		}
		else if (strcmp(descriptor_words[i], "microseconds") == 0)
		{
			r.factor = 10.0e-6;
		}
		else if (strcmp(descriptor_words[i], "milliseconds") == 0)
		{
			r.factor = 10.0e-3;
		}
		else if (strcmp(descriptor_words[i], "yincrement") == 0)
		{ // TODO: Maybe add assertion to check if next field is there...
			r.factor = atof(descriptor_words[i+1]);
		}
		else if (strcmp(descriptor_words[i], "yorigin") == 0)
		{
			r.offset = atof(descriptor_words[i+1]);
		}
	}

	g_strfreev(label_set);
	return( g_memdup(&r, sizeof(r)) );
}

/*
SR_PRIV void hp16700_parse_sentence(GSList )
{
}
*/
SR_PRIV int hp16700_get_scope_info(struct dev_context *devc, struct dev_module *module)
{
	char cmd[1024];
	GSList *resp = NULL;
	GSList *curline;
	gchar **fields, **min_max;
	int res;
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
		fields = g_regex_split_simple(" +", curline->data, 0, 0);
		if (g_regex_match_simple("^States", curline->data, 0, 0)){
			g_assert( g_strv_length(fields) == 2 );

			min_max = g_strsplit( fields[1], "..", 0);
			g_assert (g_strv_length( min_max) );
			module->states_min = atoi(min_max[0]);
			module->states_max = atoi(min_max[1]);

			g_strfreev(min_max);
		}
		else if (g_regex_match_simple("^Times", curline->data, 0, 0)){
			g_assert( g_strv_length(fields) == 2 );

			min_max = g_strsplit( fields[1], "..", 0);
			g_assert (g_strv_length( min_max ) );
			module->time_min = atof(min_max[0]);
			module->time_max = atof(min_max[1]);

			g_strfreev(min_max);
		}
		else if (g_regex_match_simple(" labels$", curline->data, 0, 0)){
			in_fields = TRUE;
			if ( module->label_infos != NULL)
			{
				g_slist_free_full(module->label_infos, hp16700_free_label_descriptor);
			}
			module->label_infos = g_slist_alloc();
		}
		else if (in_fields){
			module->label_infos = g_slist_append(module->label_infos,
					hp16700_parse_label_descriptor(curline->data));

		}
		g_strfreev(fields);
	}
	g_slist_free_full(resp, g_free);
	return res;
}
/*
SR_PRIV void hp16700_parse_binary_stream(struct dev_module *module,
		int num_samples, int sample_size, void *buffer)
{
	int i;

}
*/
SR_PRIV int hp16700_get_binary(struct dev_context *devc, const char *cmd,
		uint8_t **data)
{
	int len, expected_len;
	gint64 timeout;
	struct hp16700_bin_hdr hdr;

	sr_info("get_binary");
	if (cmd) {
		if (hp16700_send_cmd(devc, cmd) != SR_OK)
			return SR_ERR;
	}

	timeout = g_get_monotonic_time() + devc->read_timeout;

	len = hp16700_read_data(devc, (char *)&hdr, sizeof(hdr), FALSE);

	if (len != sizeof(hdr)){
		sr_err("Error reading binary data. Got len=%d sizeof(hdr)=%ld", len, sizeof(hdr));
		return SR_ERR;
	}

	expected_len = htonl(hdr.bytes_per_record) * htonl( hdr.frame_count );
	*data = g_malloc(expected_len);

	sr_info("bytes_per_record=%d, frame_count=%d", htonl(hdr.bytes_per_record),
			htonl(hdr.frame_count), FALSE );
	len = hp16700_read_data(devc, (char *)*data, expected_len, FALSE);

	if (len < expected_len) {
		g_free(*data);
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
			gchar **columns;
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
