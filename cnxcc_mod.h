/*
 * $Id$
 *
 * Copyright (C) 2012 Carlos Ruiz Díaz (caruizdiaz.com),
 *                    ConexionGroup (www.conexiongroup.com)
 *
 * This file is part of Kamailio, a free SIP server.
 *
 * Kamailio is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * Kamailio is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include <kamailio/locking.h>
#include <kamailio/str_hash.h>
#include <kamailio/parser/parse_rr.h>

#define str_shm_free_if_not_null(_var_) if (_var_.s != NULL)  { shm_free(_var_.s); _var_.s = NULL; _var_.len = 0; }

typedef struct stats
{
	unsigned int total;
	unsigned int active;
	unsigned int dropped;
} stats_t;

typedef enum cnxpvtypes
{
	CNX_PV_ACTIVE = 1,
	CNX_PV_TOTAL,
	CNX_PV_DROPPED
} cnxpvtypes_t;

typedef struct data
{
	gen_lock_t lock;

	struct str_hash_table *credit_data_by_client;
	struct str_hash_table *call_data_by_cid;
	stats_t *stats;

	/*
	 * Call Shutdown Route Number
	 */
	int cs_route_number;

	/*
	 * Dialog flag used to track the call
	 */
	flag_t ctrl_flag;

} data_t;

typedef struct sip_data
{
	str callid;
	str to_tag;
	str from_tag;
} sip_data_t;

struct call;
typedef struct call
{
	struct call *prev;
	struct call *next;

	gen_lock_t lock;

	char confirmed;
	int max_secs;
//	char call_ended;

	unsigned int start_timestamp;
	unsigned int consumed_secs;

	unsigned int dlg_h_entry;
	unsigned int dlg_h_id;

	str client_id;

	sip_data_t sip_data;
} call_t;

typedef struct call_array
{
	call_t *array;
	int length;

} call_array_t;

typedef struct credit_data
{
	gen_lock_t lock;

	int max_secs;
	int consumed_secs;
	int ended_calls_consumed_secs;
	int number_of_calls;
	int concurrent_calls;

	call_t *call_list;

} credit_data_t;
