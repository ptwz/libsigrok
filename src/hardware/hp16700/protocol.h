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

#ifndef LIBSIGROK_HARDWARE_HP16700_PROTOCOL_H
#define LIBSIGROK_HARDWARE_HP16700_PROTOCOL_H

#include <config.h>
#ifdef _WIN32
#define _WIN32_WINNT 0x0501
#include <winsock2.h>
#include <ws2tcpip.h>
#endif
#include <glib.h>
#include <string.h>
#include <unistd.h>
#ifndef _WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#endif
#include <errno.h>
#include <stdint.h>
#include <libsigrok/libsigrok.h>
#include "libsigrok-internal.h"

#define LOG_PREFIX "hp16700"

/* The size in bytes of chunks to send through the session bus. */
#define LOGIC_BUFSIZE			4096
/* Size of the analog pattern space per channel. */
#define ANALOG_BUFSIZE			4096
/* This is a development feature: it starts a new frame every n samples. */
#define SAMPLES_PER_FRAME		0

struct dev_context {
	char *address;
	char *port;
	int socket;
	unsigned int read_timeout;
	unsigned char *tcp_buffer;

	uint64_t cur_samplerate;
	uint64_t num_logic_channels;
	uint64_t num_analog_channels;

	uint64_t logic_unitsize;
	GHashTable *ch_ag;
};

enum hp16700_module_type{
	HP16700_UNKNOWN=0,
	HP16700_LOGIC,
	HP16700_SCOPE,
	HP16700_PATTERN_GEN,
	HP16700_EMU
	};

struct dev_module {
	// Describes a module: Either a whole card or a "machine" of a logic analyzer
	enum hp16700_module_type type;
	gchar *slot;
	gchar *name;
	gchar *model;
	gchar *description;
	uint64_t max_sample_rate;
	uint16_t num_channels;
	
};

SR_PRIV int hp16700_open(struct sr_dev_inst *sdi);
SR_PRIV int hp16700_close(struct sr_dev_inst *sdi);
SR_PRIV int hp16700_receive_data(int fd, int revents, void *cb_data);
SR_PRIV int hp16700_get_string(struct dev_context *devc, const char *cmd,
				      char **tcp_resp);
SR_PRIV int hp16700_read_data(struct dev_context *devc, char *buf,
				     int maxlen);
SR_PRIV int hp16700_drain(struct dev_context *devc);
SR_PRIV int hp16700_scan(struct dev_context *devc);

#endif
