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
#include <math.h>
#include "protocol.h"

SR_PRIV int str2rational(char *str, struct sr_rational *rational)
{
	gchar **fields;
	int64_t p = 1e6;
	uint64_t q = 1e6;
	int r;

	fields = g_strsplit_set(str, "eE", 0);
	g_assert( g_strv_length(fields) < 3 );
	g_assert( g_strv_length(fields) >= 1 );

	sr_info("str2rational('%s') -> field[0]='%s' field[1]='%s'\n", str, fields[0], fields[1]);
	p = round( atof(fields[0]) * 1e6 );
	if ( g_strv_length(fields) == 2 )
		q = pow(10, -atoi(fields[1])) * 1e6;

	sr_rational_set(rational, p, q);

	r = g_strv_length(fields);
	g_strfreev(fields);

	sr_info("str2rational('%s') -> p=%ld q=%ld\n", str, p, q);
	return r;
}

SR_PRIV int bit_to_bytes(int bits)
{
	int r;

	sr_info("bit_to_bytes: bits=%d", bits);
	for (r=0; bits>0; r++)
	{
		bits -= 8;
	}
	sr_info("bit_to_bytes: r=%d", r);
	return r;
}

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

SR_PRIV int strncpy_and_clean(uint8_t *dest, uint8_t *src, int len)
{
	int effective_len = 0;
	// Copies strings and removes the low ascii characters except for \n
	for ( ; ( *src!=0 ) && ( len>0 ) ; len--)
	{
		if ( (*src < ' ') && (*src != '\n') )
		{
			len++;
		} else
		{
			*dest=*src;
			effective_len++;
		}
		dest++;
		src++;
	}
	return effective_len;
}

SR_PRIV int hp16700_read_answer(struct dev_context *devc, char *buf,
				     int maxlen)
{
	int len;
	unsigned int remain_len, recvd_len;
	char *recv_tmp = g_malloc0( maxlen + devc->buffer_len + 1);
	char *inptr = recv_tmp;

	remain_len = maxlen;
	recvd_len = 0;

	memset(buf, 0, maxlen);

	if (devc->tcp_buffer != NULL) {
		sr_info("have some buffer len=%d", devc->buffer_len);

		g_assert( devc->buffer_len > 0 );

		remain_len -= devc->buffer_len;

		recvd_len = strncpy_and_clean( (uint8_t *)inptr, devc->tcp_buffer, devc->buffer_len );
		sr_info("Copied buffer len = %d", recvd_len);
		inptr += recvd_len + 1;

		g_free(devc->tcp_buffer);
		devc->tcp_buffer = NULL;
		devc->buffer_len = 0;
	}

	while ( (strstr((char*)recv_tmp, "->") == NULL ) && (remain_len > 0) )
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

	len = strlen(recv_tmp);
	len = len > maxlen ? maxlen : len;
	strncpy(buf, recv_tmp, maxlen);
	g_free( recv_tmp );

	return len;
}

SR_PRIV int hp16700_read_binary(struct dev_context *devc, char *buf,
				     int expected_len)
{
	int len, remain_len, recvd_len;
	char *recv_tmp = g_malloc0( expected_len + devc->buffer_len + 1);
	char *inptr = recv_tmp;

	remain_len = expected_len;
	recvd_len = 0;

	if (devc->tcp_buffer != NULL) {
		sr_info("have some buffer len=%d", devc->buffer_len);

		g_assert( devc->buffer_len > 0 );

		remain_len -= devc->buffer_len;

		memcpy( inptr, devc->tcp_buffer, devc->buffer_len );
		inptr += devc->buffer_len;

		recvd_len = devc->buffer_len;

		g_free(devc->tcp_buffer);
		devc->tcp_buffer = NULL;
	}


	while (remain_len > 1)
	{
		len = recv(devc->socket, inptr, remain_len, 0);

		if (len < 0) {
			sr_err("Receive error: %s", g_strerror(errno));
			return SR_ERR;
		}

		remain_len -= len;
		recvd_len += len;
		inptr += len;
		sr_info("recv'd len=%d, remain_len=%d", len, remain_len);
	}

	remain_len = expected_len - recvd_len;
	if (remain_len < 0)
	{
		memcpy( buf, recv_tmp, expected_len );
		len = expected_len;
		devc->tcp_buffer = g_memdup(&recv_tmp[expected_len], -remain_len);
		devc->buffer_len = recvd_len;
	} else
	{
		memcpy( buf, recv_tmp, recvd_len );
		len = recvd_len;
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
		devc->tcp_buffer = NULL;
		devc->buffer_len = 0;
	}
	do {
		ret = select(devc->socket + 1, &rset, NULL, NULL, &tv);
		if (ret > 0)
			len += hp16700_read_binary(devc, buf, 1024);
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
	char **lines;
	char **line;
	GString *cur_line = g_string_sized_new(1024);
	int r = SR_OK;

	if (cmd) {
		if (hp16700_send_cmd(devc, cmd) != SR_OK)
		{
			r = SR_ERR_DATA;
			goto ret;
		}
	}

	timeout = g_get_monotonic_time() + devc->read_timeout;

	*tcp_resp = g_slist_alloc();

	len = hp16700_read_answer(devc, cur_line->str,
					cur_line->allocated_len);
	g_assert(len > 0);
	if (len > 0)
		g_string_set_size(cur_line, len);

/*	if (g_get_monotonic_time() > timeout) {
		sr_err("Timed out waiting for response.");
		g_string_free(cur_line, TRUE);
		r = SR_ERR_TIMEOUT;
		goto ret;
	}
*/
	lines = g_regex_split_simple("\\R+", cur_line->str, 0, 0);
	
	g_assert(g_strv_length(lines)>=1);

	for (line = lines; *line != NULL; line++)
	{
		sr_spew("Got cur_line: '%s'", *line);
		if ( strstr(*line, "->") != NULL)
		{
			sr_info("hp16700_get_strings: done");
			r = SR_OK;
			goto ret;
		}
		*tcp_resp = g_slist_append(*tcp_resp, g_strdup(*line));
	}

	ret:
	g_string_free(cur_line, TRUE);
	return r;
}


SR_PRIV void hp16700_free_label_descriptor(void *field)
{
	struct hp_data_label *label = field;
	g_assert(label != NULL);
	g_assert(label->name != NULL);

	g_free(label->name);
	g_free(label);
}

SR_PRIV struct hp_data_label *hp16700_parse_label_descriptor(gchar *label_string,
		struct dev_module *parent)
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
	r.parent = parent;

	sr_info("hp16700_parse_label_descriptor: len(label_set)=%d", g_strv_length(label_set));
	g_assert( g_strv_length(label_set) == 3);
	name = g_strstrip( label_set[1] );
	descriptor = g_strstrip( label_set[2] );

	descriptor_words = g_strsplit(descriptor, " ", 0);
	g_assert( g_strv_length(descriptor_words) > 2);

	r.name = g_strdup(name);
	r.bits = atoi(descriptor_words[0]);
	r.bytes = bit_to_bytes(r.bits);
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
			sr_rational_set(&r.scale, 1, 12);
		}
		else if (strcmp(descriptor_words[i], "nanoseconds") == 0)
		{
			sr_rational_set(&r.scale, 1, 9);
		}
		else if (strcmp(descriptor_words[i], "microseconds") == 0)
		{
			sr_rational_set(&r.scale, 1, 6);
		}
		else if (strcmp(descriptor_words[i], "milliseconds") == 0)
		{
			sr_rational_set(&r.scale, 1, 3);
		}
		else if (strcmp(descriptor_words[i], "yincrement") == 0)
		{ // TODO: Maybe add assertion to check if next field is there...
			str2rational(descriptor_words[i+1], &r.scale);
		}
		else if (strcmp(descriptor_words[i], "yorigin") == 0)
		{
			str2rational(descriptor_words[i+1], &r.offset);
		}
	}

	g_strfreev(label_set);
	return( g_memdup(&r, sizeof(r)) );
}

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
					hp16700_parse_label_descriptor(curline->data, module));

		}
		g_strfreev(fields);
	}
	g_slist_free_full(resp, g_free);
	return res;
}


SR_PRIV void hp16700_parse_binary_stream(struct dev_module *module,
		int num_samples, uint8_t *buffer)
{
	int i, j;
	GSList *field;
	struct hp_data_label *labelinfo;

	sr_info("hp16700_parse_binary_stream num_samples=%d", num_samples);
	for (field = module->label_infos; field != NULL ; field = field->next)
	{
		if (field->data == NULL)
			continue;
		labelinfo = field->data;
		if (labelinfo->raw_buffer != NULL)
			g_free(labelinfo->raw_buffer);

		labelinfo->raw_buffer = g_malloc0( labelinfo->bytes * num_samples );
		labelinfo->load_ptr = labelinfo->raw_buffer;
		labelinfo->num_samples = num_samples;
	}

	for (i=0; i<num_samples; i++)
	{
		g_assert(module->label_infos != NULL);
		for (field = module->label_infos; field != NULL ; 
				field = field->next)
		{
			if (field->data == NULL)
				continue;
			labelinfo = field->data;

			for (j=0; j<labelinfo->bytes; j++)
			{
				*((labelinfo->load_ptr)++) = *(buffer++);
			}
		}
	}
}

static struct sr_channel *find_channel(GSList *channellist, const char *channelname)
{
	struct sr_channel *ch;
	GSList *l;

	ch = NULL;
	for (l = channellist; l; l = l->next) {
		ch = l->data;
		if (!strcmp(ch->name, channelname))
			break;
	}
	ch = l ? l->data : NULL;

	return ch;
}

SR_PRIV int hp16700_fetch_all_channels(int fd, int revents, struct sr_dev_inst *sdi)
{
	// ToDo: Do a proper scan..
	struct dev_context *devc = sdi->priv;
	struct dev_module *module = devc->modules->next->data;
	(void)fd;
	(void)revents;

	hp16700_fetch_scope_data(devc, sdi, module);

	return SR_OK;
}


SR_PRIV int hp16700_fetch_scope_data(struct dev_context *devc, 
		struct sr_dev_inst *sdi,
		struct dev_module *module)
{
	char cmd[1025];
	uint8_t *data;
	uint32_t bytes_per_frame;
	uint32_t frame_count;
	struct sr_datafeed_analog analog;
	struct sr_analog_encoding encoding;
	struct sr_datafeed_packet packet;
	struct sr_analog_meaning meaning;
	struct sr_analog_spec spec;
	GSList *channel_list;
	GSList *l;
	struct hp_data_label *labelinfo;
	struct sr_channel *ch;

	//hp16700_fetch_scope_data(devc, module);

	memset(cmd, 0, sizeof(cmd));
	snprintf(cmd, sizeof(cmd)-1, "scope -n %s -d", module->name);

	if (hp16700_get_binary(devc, cmd, &frame_count, &bytes_per_frame, &data) 
			!= SR_OK)
		return SR_ERR;
	
	hp16700_parse_binary_stream(module, frame_count, data);

	sr_analog_init(&analog, &encoding, &meaning, &spec, 4);

	channel_list = sr_dev_inst_channels_get(sdi);

	for (l = module->label_infos ; l != NULL ; l = l->next )
	{
		if (l->data == NULL)
			continue;
		labelinfo = l->data;

		ch = find_channel(channel_list, labelinfo->name);
		if ( ch == NULL ) 
		{
			sr_info("Skipping label %s because it does not seem to be a channel", labelinfo->name);
			continue;
		}

		if ( labelinfo->num_samples == 0 )
		{
			sr_info("Skipping label: %s, no samples", labelinfo->name);
			continue;
		}
		encoding.unitsize = labelinfo->bytes;
		encoding.is_bigendian = TRUE;
		encoding.is_signed = labelinfo->is_signed;
		encoding.is_float = FALSE;
		encoding.digits = 2;
		memcpy(&encoding.offset, &labelinfo->offset, sizeof(struct sr_rational));
		memcpy(&encoding.scale, &labelinfo->scale, sizeof(struct sr_rational));

		analog.meaning->channels = g_slist_append(NULL, ch);
		sr_info("%s: num_samples = %d", labelinfo->name, labelinfo->num_samples);
		analog.num_samples = labelinfo->num_samples;

		analog.data = labelinfo->raw_buffer;
		analog.meaning->mq = SR_MQ_VOLTAGE;
		analog.meaning->unit = SR_UNIT_VOLT;
		analog.meaning->mqflags = 0;
		packet.type = SR_DF_ANALOG;
		packet.payload = &analog;
		sr_session_send(sdi, &packet);
		g_slist_free(analog.meaning->channels);
	}

	return SR_OK;
}

SR_PRIV int hp16700_get_binary(struct dev_context *devc, const char *cmd,
		uint32_t *frame_count, uint32_t *bytes_per_frame, uint8_t **data)
{
	int len, expected_len;
	gint64 timeout;
	struct hp16700_bin_hdr hdr;

	*frame_count = 0;
	*bytes_per_frame = 0;

	sr_info("get_binary");
	if (cmd) {
		if (hp16700_send_cmd(devc, cmd) != SR_OK)
			return SR_ERR;
	}

	timeout = g_get_monotonic_time() + devc->read_timeout;

	len = hp16700_read_binary(devc, (char *)&hdr, sizeof(hdr));

	if (len != sizeof(hdr)){
		sr_err("Error reading binary data. Got len=%d sizeof(hdr)=%ld", len, sizeof(hdr));
		return SR_ERR;
	}

	*frame_count = htonl(hdr.frame_count);
	*bytes_per_frame = htonl(hdr.bytes_per_record);

	expected_len = *frame_count * *bytes_per_frame;
	*data = g_malloc(expected_len);

	sr_info("bytes_per_record=%d, frame_count=%d", *bytes_per_frame,
			*frame_count );
	len = hp16700_read_binary(devc, (char *)*data, expected_len);

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
	gchar **columns;

	sr_info("hp16700_scan");
	g_assert(devc->modules == NULL);
	devc->modules = g_slist_alloc();

	split_rgx = g_regex_new("[\" ]+", 0, 0, &err);
	if (err == NULL){
		ret = hp16700_get_strings(devc, "modules", &results, 10);
		for (line = results; line != NULL; line = line->next){
			struct dev_module *module;
			if (line->data == NULL)
				continue;
			
		       	module = g_malloc0(sizeof(struct dev_module));
			module->parent = devc;
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
