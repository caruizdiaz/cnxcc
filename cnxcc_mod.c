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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <ctype.h>

#include <kamailio/sr_module.h>
#include <kamailio/dprint.h>
#include <kamailio/error.h>
#include <kamailio/mem/mem.h>
#include <kamailio/shm_init.h>
#include <kamailio/mem/shm_mem.h>
#include <kamailio/pvar.h>
#include <kamailio/locking.h>
#include <kamailio/lock_ops.h>
#include <kamailio/str_hash.h>
#include <kamailio/timer.h>
#include <kamailio/modules/tm/tm_load.h>
#include <kamailio/parser/parse_from.h>
#include <kamailio/parser/parse_to.h>
#include <kamailio/parser/parse_uri.h>
#include <kamailio/parser/parse_cseq.h>
#include <kamailio/parser/contact/parse_contact.h>
#include <kamailio/parser/contact/contact.h>
#include <kamailio/parser/parse_rr.h>
#include <kamailio/lib/kcore/parser_helpers.h>
#include <kamailio/mod_fix.h>
#include <kamailio/modules_k/dialog/dlg_load.h>
#include <kamailio/modules_k/dialog/dlg_hash.h>
#include <kamailio/mi/mi_types.h>
#include <kamailio/lib/kcore/faked_msg.h>
#include <kamailio/rpc.h>
#include <kamailio/rpc_lookup.h>

#include "cnxcc_mod.h"
#include "cnxcc.h"
#include "cnxcc_sip_msg_faker.h"

MODULE_VERSION

#define HT_SIZE						69
#define MODULE_NAME					"CNXCC"
#define CALLER_LEG 					0
#define CALLEE_LEG 					1
#define PCNXCC_HDR 					"P-cnxcc: "
#define PCNXCC_HDR_LEN 				sizeof(PCNXCC_HDR) - 1
#define PCNXCC_HDR_TXT				"call forced to end due to lack of credit"
#define PCNXCC_HDR_TXT_LEN			sizeof(PCNXCC_HDR_TXT) - 1
#define CREDIT_CHECK_TIME			1
#define FREE_CHECK_TIME				1

#define TRUE						1
#define FALSE						0

static data_t _data;
struct dlg_binds _dlgbinds;

/*
 *  module core functions
 */
static int mod_init(void);

/*
 * Memory management functions
 */
static int shm_str_hash_alloc(struct str_hash_table *ht, int size);
static void free_credit_data_hash_entry(struct str_hash_entry *e);

/*
 * PV management functions
 */
static int pv_parse_calls_param(pv_spec_p sp, str *in);
static int pv_get_calls(struct sip_msg *msg, pv_param_t *param, pv_value_t *res);
//static int get_str_pv(struct sip_msg* msg, str *pv_name, str *pvvalue);

/*
 * Billing management functions
 */
static int set_max_time(struct sip_msg* msg, char* number, char* str2);
static void start_billing(str *callid, str tags[2]);
static void setup_billing(str *callid, unsigned int h_entry, unsigned int h_id);
static void stop_billing(str *callid);
static int add_call_by_cid(str *cid, call_t *call);
static credit_data_t *get_or_create_credit_data_entry(str *client_id);
static call_t *alloc_new_call(credit_data_t *credit_data, struct sip_msg *msg, int max_secs);
static void check_calls(unsigned int ticks, void *param);
static int terminate_call(call_t *call);
static void notify_call_termination(str *callid, str *from_tag, str *to_tag);
static void terminate_all_calls(credit_data_t *credit_data);
static void free_call(call_t *call);
static int has_to_tag(struct sip_msg *msg);

/*
 * MI interface
 */
static struct mi_root *mi_credit_control_stats(struct mi_root *tree, void *param);

/*
 * RPC interface
 */
static void rpc_active_clients(rpc_t* rpc, void* ctx);
static void rpc_check_client_stats(rpc_t* rpc, void* ctx);
static void rpc_kill_call(rpc_t* rpc, void* ctx);

/*
 * Dialog management callback functions
 */
static void dialog_terminated_callback(struct dlg_cell *cell, int type, struct dlg_cb_params *params);
static void dialog_confirmed_callback(struct dlg_cell *cell, int type, struct dlg_cb_params *params);
static void dialog_created_callback(struct dlg_cell *cell, int type, struct dlg_cb_params *params);

static pv_export_t mod_pvs[] =
{
	{ {"cnxcc", sizeof("cnxcc")-1 }, PVT_OTHER, pv_get_calls, 0,
		                pv_parse_calls_param, 0, 0, 0 },
	{ {0, 0}, 0, 0, 0, 0, 0, 0, 0 }
};

static cmd_export_t cmds[] =
{
	{"cnxcc_set_max_time",   (cmd_function) set_max_time, 2, fixup_pvar_pvar, fixup_free_pvar_pvar, ANY_ROUTE},
	{0,0,0,0,0,0}
};

static param_export_t params[] =
{
	{"dlg_flag",  		INT_PARAM,			&_data.ctrl_flag	},
	{ 0, 0, 0 }
};

static const char* rpc_active_clients_doc[2] =
{
	"List of clients with active calls",
	0
};

static const char* rpc_check_client_stats_doc[2] =
{
	"Check specific client calls",
	0
};

static const char* rpc_kill_call_doc[2] =
{
	"Kill call using its call ID",
	0
};

rpc_export_t ul_rpc[] =
{
    {"cnxcc.active_clients",	rpc_active_clients,	rpc_active_clients_doc,	0},
    {"cnxcc.check_client",		rpc_check_client_stats,	rpc_check_client_stats_doc,	0},
    {"cnxcc.kill_call",			rpc_kill_call,	rpc_kill_call_doc,	0},

    {0, 0, 0, 0}
};

/** module exports */
struct module_exports exports =
{
	"cnxcc",
	DEFAULT_DLFLAGS, 	/* dlopen flags */
	cmds,
	params,
	0,          		/* exported statistics */
	0, 		    		/* exported MI functions */
	mod_pvs,  			/* exported pseudo-variables */
	0,          		/* extra processes */
	mod_init,   		/* module initialization function */
	0,
	0,
	0		            /* per-child init function */
};

static int mod_init(void)
{
	LM_ALERT("Loading " MODULE_NAME " module\n");

	_data.cs_route_number = route_get(&event_rt, "cnxcc:call-shutdown");

	if (_data.cs_route_number < 0)
		LM_INFO("No cnxcc:call-shutdown event route found");

	if (_data.cs_route_number > 0 && event_rt.rlist[_data.cs_route_number] == NULL)
	{
		LM_INFO("cnxcc:call-shutdown route is empty");
		_data.cs_route_number	= -1;
	}

	_data.credit_data_by_client = shm_malloc(sizeof(struct str_hash_table));
	_data.call_data_by_cid 		= shm_malloc(sizeof(struct str_hash_table));

	_data.stats					= (stats_t *) shm_malloc(sizeof(stats_t));

	if (!_data.stats)
	{
		LM_ERR("Error allocating shared memory stats\n");
		return -1;
	}

	_data.stats->active		= 0;
	_data.stats->dropped	= 0;
	_data.stats->total		= 0;

	if (shm_str_hash_alloc(_data.credit_data_by_client, HT_SIZE) != 0)
	{
		LM_ERR("Error allocating shared memory hash table\n");
		return -1;
	}

	str_hash_init(_data.credit_data_by_client);

	if (shm_str_hash_alloc(_data.call_data_by_cid, HT_SIZE) != 0)
	{
		LM_ERR("Error allocating shared memory hash table\n");
		return -1;
	}

	str_hash_init(_data.call_data_by_cid);

	lock_init(&_data.lock);

	register_mi_cmd(mi_credit_control_stats, "cnxcc_stats", NULL, NULL, 0);

	if (register_timer(check_calls, NULL, CREDIT_CHECK_TIME) < 0)
	{
		LM_ERR("Failed to register timer");
		return -1;
	}

	if (rpc_register_array(ul_rpc) != 0)
	{
		LM_ERR("Failed registering RPC commands\n");
		return -1;
	}

	if (load_dlg_api(&_dlgbinds) != 0)
	{
		LM_ERR("Error loading dialog API\n");
	    return -1;
	}

	_dlgbinds.register_dlgcb(NULL, DLGCB_CREATED, dialog_created_callback, NULL, NULL);

	return 0;
}

static void rpc_kill_call(rpc_t* rpc, void* ctx)
{
	struct str_hash_entry *e;
	call_t *call;
	str call_id;

	if (!rpc->scan(ctx, "S", &call_id))
	{
		LM_ERR("%s: error reading RPC param\n", __FUNCTION__);
		return;
	}

	lock_get(&_data.lock);

	e	= str_hash_get(_data.call_data_by_cid, call_id.s, call_id.len);

	if (e == NULL)
	{
		LM_ERR("%s: call [%.*s] not found\n", __FUNCTION__, call_id.len, call_id.s);
		rpc->fault(ctx, 404, "CallID Not Found");
		lock_release(&_data.lock);
		return;
	}

	call	= (call_t *) e->u.p;

	if (call == NULL)
	{
		LM_ERR("%s: call [%.*s] is in null state\n", __FUNCTION__, call_id.len, call_id.s);
		rpc->fault(ctx, 500, "Call is NULL");
		lock_release(&_data.lock);
		return;
	}

	LM_ALERT("Killing call [%.*s] via XMLRPC request\n", call_id.len, call_id.s);

	terminate_call(call);

	lock_release(&_data.lock);

}

static void rpc_check_client_stats(rpc_t* rpc, void* ctx)
{
	struct str_hash_entry *e;
	call_t *call, *tmp;
	int index	= 0;
	str client_id, rows;
	char row_buffer[512];
	credit_data_t *credit_data;

	if (!rpc->scan(ctx, "S", &client_id))
	{
		LM_ERR("%s: error reading RPC param\n", __FUNCTION__);
		return;
	}

	lock_get(&_data.lock);

	e	= str_hash_get(_data.credit_data_by_client, client_id.s, client_id.len);

	if (e == NULL)
	{
		LM_ERR("%s: client [%.*s] not found\n", __FUNCTION__, client_id.len, client_id.s);
		rpc->fault(ctx, 404, "Not Found");
		lock_release(&_data.lock);
		return;
	}

	credit_data	= (credit_data_t *) e->u.p;

	lock_release(&_data.lock);

	lock_get(&credit_data->lock);

	if (credit_data->number_of_calls <= 0)
	{
		lock_release(&credit_data->lock);
		LM_INFO("No calls for current client\n");
		return;
	}

	rows.len = 0;
	rows.s	 = pkg_malloc(10);

	if (rows.s == NULL)
		goto nomem;

	clist_foreach_safe(credit_data->call_list, call, tmp, next)
	{
		int row_len = 0;

		memset(row_buffer, 0, sizeof(row_buffer));
		snprintf(row_buffer, sizeof(row_buffer), "id:%d,confimed:%s,local_consumed_secs:%d,global_consumed_secs:%d,local_max_secs:%d,global_max_secs:%d,callid:%.*s,start_timestamp:%d;", index,
														     call->confirmed ? "yes" : "no",
															 call->consumed_secs,
															 credit_data->consumed_secs,
															 call->max_secs,
															 credit_data->max_secs,
															 call->sip_data.callid.len, call->sip_data.callid.s,
															 call->start_timestamp);

		row_len 	= strlen(row_buffer);
		rows.s		= pkg_realloc(rows.s, rows.len + row_len);

		if (rows.s == NULL)
		{
			lock_release(&credit_data->lock);
			goto nomem;
		}

		memcpy(rows.s + rows.len, row_buffer, row_len);
		rows.len += row_len;

		index++;
	}

	lock_release(&credit_data->lock);

	if (rpc->add(ctx, "S", &rows) < 0)
	{
		LM_ERR("%s: error creating RPC struct\n", __FUNCTION__);
	}

	if (rows.s != NULL)
		pkg_free(rows.s);

	return;

nomem:
	LM_ERR("No more pkg memory");
	rpc->fault(ctx, 500, "No more memory\n");
}

static void rpc_active_clients(rpc_t* rpc, void* ctx)
{
	struct str_hash_entry *h_entry, *tmp;
	char row_buffer[512];
	int index = 0;
	str rows;

	lock_get(&_data.lock);

	rows.len = 0;
	rows.s	 = pkg_malloc(10);

	if (_data.credit_data_by_client->table)
		for(index = 0; index < _data.credit_data_by_client->size; index++)
			clist_foreach_safe(&_data.credit_data_by_client->table[index], h_entry, tmp, next)
			{
				credit_data_t *credit_data	= (credit_data_t *) h_entry->u.p;
				int row_len = 0;

				lock_get(&credit_data->lock);

				memset(row_buffer, 0, sizeof(row_buffer));
				snprintf(row_buffer, sizeof(row_buffer), "client_id:%.*s,"
														 "number_of_calls:%d,"
														 "concurrent_calls:%d,"
														 "max_secs:%d,"
														 "consumed_seconds:%d;",
														 credit_data->call_list->client_id.len, credit_data->call_list->client_id.s,
														 credit_data->number_of_calls,
														 credit_data->concurrent_calls,
														 credit_data->max_secs,
														 credit_data->consumed_secs);

				row_len 	= strlen(row_buffer);
				rows.s		= pkg_realloc(rows.s, rows.len + row_len);

				if (rows.s == NULL)
				{
					lock_release(&credit_data->lock);
					lock_release(&_data.lock);
					goto nomem;
				}

				memcpy(rows.s + rows.len, row_buffer, row_len);
				rows.len += row_len;

				lock_release(&credit_data->lock);
			}

	lock_release(&_data.lock);

	if (!rpc->add(ctx, "S", &rows) < 0)
	{
		LM_ERR("%s: error creating RPC struct\n", __FUNCTION__);
	}

	if (rows.s != NULL)
		pkg_free(rows.s);

	return;

nomem:
	LM_ERR("No more pkg memory");
	rpc->fault(ctx, 500, "No more memory\n");
}

static void dialog_created_callback(struct dlg_cell *cell, int type, struct dlg_cb_params *params)
{
	struct sip_msg *msg	= NULL;

	msg	= params->direction == SIP_REPLY ? params->rpl : params->req;

	if (msg == NULL)
	{
		LM_ERR("Error getting direction of SIP msg\n");
		return;
	}

	if (isflagset(msg, _data.ctrl_flag) == -1)
	{
		LM_DBG("Flag is not set for this message. Ignoring\n");
		return;
	}

	LM_DBG("Dialog created for CID [%.*s]", cell->callid.len, cell->callid.s);

	_dlgbinds.register_dlgcb(cell, DLGCB_CONFIRMED, dialog_confirmed_callback, NULL, NULL);
	_dlgbinds.register_dlgcb(cell, DLGCB_TERMINATED|DLGCB_FAILED|DLGCB_EXPIRED, dialog_terminated_callback, NULL, NULL);

	setup_billing(&cell->callid, cell->h_entry, cell->h_id);
}

static void dialog_confirmed_callback(struct dlg_cell *cell, int type, struct dlg_cb_params *params)
{
	LM_DBG("Dialog confirmed for CID [%.*s]", cell->callid.len, cell->callid.s);

	start_billing(&cell->callid, cell->tag);
}

static void dialog_terminated_callback(struct dlg_cell *cell, int type, struct dlg_cb_params *params)
{
	LM_DBG("Dialog terminated for CID [%.*s]", cell->callid.len, cell->callid.s);

	stop_billing(&cell->callid);
}

static void notify_call_termination(str *callid, str *from_tag, str *to_tag)
{
	struct run_act_ctx ra_ctx;
	struct sip_msg *msg;

	if (_data.cs_route_number < 0)
		return;

	if (faked_msg_init_with_dlg_info(callid, from_tag, to_tag,  &msg) != 0)
	{
		LM_ERR("[%.*s]: error generating faked sip message\n", callid->len, callid->s);
		return;
	}

	init_run_actions_ctx(&ra_ctx);
	//run_top_route(event_rt.rlist[_data.cs_route_number], msg, &ra_ctx);

	if (run_actions(&ra_ctx, event_rt.rlist[_data.cs_route_number], msg) < 0)
		LM_ERR("Error executing cnxcc:call-shutdown route");

}

static void stop_billing(str *callid)
{
	struct str_hash_entry *cd_entry		= NULL,
						  *call_entry	= NULL;
	call_t *call						= NULL;
	credit_data_t *credit_data			= NULL;

	lock_get(&_data.lock);

	/*
	 * Search call data by call-id
	 */
	call_entry			= str_hash_get(_data.call_data_by_cid, callid->s, callid->len);

	if (call_entry == NULL)
	{
		LM_ERR("Call [%.*s] not found", callid->len, callid->s);
		lock_release(&_data.lock);
		return;
	}

	call		= (call_t *) call_entry->u.p;

	if (call == NULL)
	{
		LM_ERR("[%.*s] call pointer is null", callid->len, callid->s);
		return;
	}

	/*
	 * Search credit_data by client_id
	 */
	cd_entry			= str_hash_get(_data.credit_data_by_client, call->client_id.s, call->client_id.len);

	if (cd_entry == NULL)
	{
		LM_ERR("Credit data not found for CID [%.*s], client-ID [%.*s]\n", callid->len, callid->s, call->client_id.len, call->client_id.s);
		lock_release(&_data.lock);
		return;
	}

	credit_data	= (credit_data_t *) cd_entry->u.p;

	if (credit_data == NULL)
	{
		LM_ERR("[%.*s]: credit_data pointer is null", callid->len, callid->s);
		return;
	}

	/*
	 * Update calls statistics
	 */
	_data.stats->active--;
	_data.stats->total--;

	lock_release(&_data.lock);

	lock(&credit_data->lock);

	LM_DBG("Call [%.*s] of client-ID [%.*s], ended\n", callid->len, callid->s, call->client_id.len, call->client_id.s);
	/*
	 * This call just ended and we need to remove it from the summ.
	 */
	if (call->confirmed)
	{
		credit_data->concurrent_calls--;
		credit_data->ended_calls_consumed_secs += call->consumed_secs;
	}

	credit_data->number_of_calls--;

	if (credit_data->concurrent_calls < 0)
	{
		LM_ERR("[BUG]: number of concurrent calls dropped to negative value: %d", credit_data->concurrent_calls);
	}

	if (credit_data->number_of_calls < 0)
	{
		LM_ERR("[BUG]: number of calls dropped to negative value: %d", credit_data->number_of_calls);
	}

	/*
	 * Remove (and free) the call from the list of calls of the current credit_data
	 */
	clist_rm(call, next, prev);
	free_call(call);

	/*
	 * In case there are no active calls for a certain client, we remove the client-id from the hash table.
	 * This way, we can save memory for useful clients.
	 */
	if (credit_data->number_of_calls == 0)
	{
		LM_DBG("Removing client [%.*s] and its calls from the list\n", credit_data->call_list->client_id.len, credit_data->call_list->client_id.s);

		lock(&_data.lock);
		/*
		 * Remove the credit_data_t from the hash table
		 */
		str_hash_del(cd_entry);

		lock_release(&_data.lock);

		/*
		 * Free client_id in list's root
		 */
		shm_free(credit_data->call_list->client_id.s);
		shm_free(credit_data->call_list);

		/*
		 * Release the lock since we are going to free the entry down below
		 */
		lock_release(&credit_data->lock);

		/*
		 * Free the whole entry
		 */
		free_credit_data_hash_entry(cd_entry);

		/*
		 * return without releasing the acquired lock over credit_data. Why? Because we just freed it.
		 */
		return;
	}

	lock_release(&credit_data->lock);
}

static void setup_billing(str *callid, unsigned int h_entry, unsigned int h_id)
{
	struct str_hash_entry *e	= NULL;
	call_t *call				= NULL;

	LM_DBG("Creating dialog for [%.*s], h_id [%u], h_entry [%u]", callid->len, callid->s, h_id, h_entry);

	lock_get(&_data.lock);

	/*
	 * Search call data by call-id
	 */
	e			= str_hash_get(_data.call_data_by_cid, callid->s, callid->len);

	if (e == NULL)
	{
		LM_ERR("Call [%.*s] not found", callid->len, callid->s);
		lock_release(&_data.lock);
		return;
	}

	call		= (call_t *) e->u.p;

	/*
	 * Update calls statistics
	 */
	_data.stats->active++;
	_data.stats->total++;

	lock_release(&_data.lock);

	lock_get(&call->lock);

	call->dlg_h_entry		= h_entry;
	call->dlg_h_id			= h_id;

	LM_DBG("Call [%.*s] from client [%.*s], created\n", callid->len, callid->s, call->client_id.len, call->client_id.s);

	lock_release(&call->lock);
}

static void start_billing(str *callid, str tags[2])
{
	struct str_hash_entry *e	= NULL;
	call_t *call				= NULL;
	credit_data_t *credit_data	= NULL;

	LM_DBG("Billing started for call [%.*s]", callid->len, callid->s);

	lock_get(&_data.lock);

	/*
	 * Search call data by call-id
	 */
	e			= str_hash_get(_data.call_data_by_cid, callid->s, callid->len);

	if (e == NULL)
	{
		LM_ERR("Call [%.*s] not found", callid->len, callid->s);
		lock_release(&_data.lock);
		return;
	}

	call		= (call_t *) e->u.p;

	/*
	 * Search credit_data by client_id
	 */
	e			= str_hash_get(_data.credit_data_by_client, call->client_id.s, call->client_id.len);

	if (e == NULL)
	{
		LM_ERR("Credit data not found for CID [%.*s], client-ID [%.*s]\n", callid->len, callid->s, call->client_id.len, call->client_id.s);
		lock_release(&_data.lock);
		return;
	}

	credit_data	= (credit_data_t *) e->u.p;

	lock_release(&_data.lock);

	lock(&credit_data->lock);

	/*
	 * Now that the call is confirmed, we can increase the count of "concurrent_calls".
	 * This will impact in the discount rate performed by the check_calls() function.
	 *
	 */
	credit_data->concurrent_calls++;

	/*
	 * The maximum speak time is equal to the current "max_secs" minus
	 * "consumed_seconds".
	 * The value of "max_secs" is provided by the AAA subsystem which
	 * does not maintain an in-memory/real-time status of the consumed seconds
	 * of an authorized call. In case a new call is originated under the domain
	 * of the same client-id, this is, the same client making two (or more)
	 * simultaneous calls, we will receive an amount of "max_secs" that is not
	 * accurate or updated since the previous calls may have not finished yet.
	 *
	 * For example:
	 *
	 * 1. Call 1; client-id=111; max_secs=10; discount-rate=1/sec
	 *
	 * 2. We discount 1 sec. of talk time every 1 second on the check_calls() function.
	 *
	 * 3. After 5 seconds of talk time, we receive a new call under the same client ID.
	 *
	 * 4. Since the first call hasn't finished yet, the call setup will go as follows
	 *    Call 2; client-id=111; max_secs=10 (remember, 10 secs because the stop billing mark
	 *                                        of the first call was not received by the authorizer)
	 *    It should have been only 5 seconds in "max_secs", but 1st call is still on
	 *    the go and the AAA hasn't refreshed its credit yet.
	 *
	 * 5. After applying the algorithm we will get:
	 *    Calls: 1, 2; client-id=111; max_secs=5; discount-rate=2/sec.
	 *    Caller #1 will speak 7 secs. Caller #2 will speak 3 secs.
	 *
	 * 6. The value of "concurrent_calls" will be incremented once the
	 *    call is confirmed
	 */

	if (credit_data->max_secs == 0)
		credit_data->max_secs	= call->max_secs; // first time setup

	if (call->max_secs > credit_data->max_secs)
	{
		LM_ALERT("Maximum-speak-time changed, maybe credit reload? %d > %d. Client [%.*s]", call->max_secs, credit_data->max_secs,
																							call->client_id.len, call->client_id.s);

		credit_data->max_secs += call->max_secs - credit_data->max_secs;
	}

	/*
	 * Update max_secs, discounting what was already consumed by other calls of the same client
	 */

	call->max_secs = credit_data->max_secs - credit_data->consumed_secs;

	lock_release(&credit_data->lock);

	lock_get(&call->lock);

	/*
	 * Store from-tag value
	 */
	if (shm_str_dup(&call->sip_data.from_tag, &tags[0]) != 0)
	{
		LM_ERR("No more pkg memory\n");
		goto exit;
	}

	/*
	 * Store to-tag value
	 */
	if (shm_str_dup(&call->sip_data.to_tag, &tags[1]) != 0)
	{
		LM_ERR("No more pkg memory\n");
		goto exit;
	}

	call->start_timestamp	= get_current_timestamp();
	call->confirmed			= TRUE;

	LM_DBG("Call [%.*s] from client [%.*s], confirmed\n", callid->len, callid->s, call->client_id.len, call->client_id.s);

exit:
	lock_release(&call->lock);
}

static void check_calls(unsigned int ticks, void *param)
{
	struct str_hash_entry *h_entry 	= NULL,
						  *tmp		= NULL;
	call_t *tmp_call				= NULL;
	int i;

	lock_get(&_data.lock);

	if (_data.credit_data_by_client->table)
		for(i = 0; i < _data.credit_data_by_client->size; i++)
			clist_foreach_safe(&_data.credit_data_by_client->table[i], h_entry, tmp, next)
			{
				credit_data_t *credit_data	= (credit_data_t *) h_entry->u.p;
				call_t *call				= NULL;
				int total_consumed_secs		= 0;

				lock_get(&credit_data->lock);
//				LM_DBG("Iterating through calls of client [%.*s]\n", credit_data->call_list->client_id.len, credit_data->call_list->client_id.s);

				clist_foreach_safe(credit_data->call_list, call, tmp_call, next)
				{
					if (!call->confirmed)
						continue;

					call->consumed_secs			= get_current_timestamp() - call->start_timestamp;
					total_consumed_secs			+= call->consumed_secs;

					if (call->consumed_secs > call->max_secs)
					{
						LM_ALERT("[%.*s] call has exhausted its time. Breaking the loop\n", call->sip_data.callid.len, call->sip_data.callid.s);
						break;
					}

					LM_DBG("CID [%.*s], start_timestamp [%d], seconds alive [%d]\n",
																			call->sip_data.callid.len, call->sip_data.callid.s,
																			call->start_timestamp,
																			call->consumed_secs
																			);
				}

				if (credit_data->concurrent_calls == 0)
				{
					lock_release(&credit_data->lock);
					continue;
				}

				credit_data->consumed_secs	= credit_data->ended_calls_consumed_secs + total_consumed_secs;

				LM_DBG("Client [%.*s] | Ended-Calls-Time: %d  TotalTime/MaxTime: %d/%d\n", credit_data->call_list->client_id.len, credit_data->call_list->client_id.s,
																									credit_data->ended_calls_consumed_secs,
																									credit_data->consumed_secs,
																									credit_data->max_secs);

				if (credit_data->consumed_secs >= credit_data->max_secs)
				{
					terminate_all_calls(credit_data);
					lock_release(&credit_data->lock);
					break;
				}

				lock_release(&credit_data->lock);
			}

	lock_release(&_data.lock);
}

static void terminate_all_calls(credit_data_t *credit_data)
{
	call_t 	*call 	= NULL,
			*tmp 	= NULL;

	clist_foreach_safe(credit_data->call_list, call, tmp, next)
	{
		LM_DBG("Killing call with CID [%.*s]\n", call->sip_data.callid.len, call->sip_data.callid.s);

		/*
		 * Update number of calls forced to end
		 */
		_data.stats->dropped++;

		terminate_call(call);
	}
}

/*
 * WARNING: When calling this function, the proper lock should have been acquired
 */
static void free_call(call_t *call)
{
	struct str_hash_entry *e	= NULL;

	LM_DBG("Freeing call [%.*s]\n", call->sip_data.callid.len, call->sip_data.callid.s);

	e			= str_hash_get(_data.call_data_by_cid, call->sip_data.callid.s, call->sip_data.callid.len);

	str_shm_free_if_not_null(call->sip_data.callid);
	str_shm_free_if_not_null(call->sip_data.to_tag);
	str_shm_free_if_not_null(call->sip_data.from_tag);

	shm_free(call);

	if (e == NULL)
	{
		LM_ERR("Call [%.*s] not found. Couldn't be able to free it from hashtable", call->sip_data.callid.len, call->sip_data.callid.s);
		return;
	}

	str_hash_del(e);

	shm_free(e->key.s);
	shm_free(e);
}

/*
 * WARNING: When calling this function, the proper lock should have been acquired
 */
static void free_credit_data_hash_entry(struct str_hash_entry *e)
{
	shm_free(e->key.s);
//	shm_free(((credit_data_t *) e->u.p)->call);
	shm_free(e->u.p);
	shm_free(e);
}

static int shm_str_hash_alloc(struct str_hash_table *ht, int size)
{
	ht->table	= shm_malloc(sizeof(struct str_hash_head) * size);

	if (!ht->table)
		return -1;

	ht->size	= size;
	return 0;
}

static credit_data_t *get_or_create_credit_data_entry(str *client_id)
{
	struct str_hash_table *ht	= _data.credit_data_by_client;
	struct str_hash_entry *e	= NULL;

	lock_get(&_data.lock);
	e							= str_hash_get(ht, client_id->s, client_id->len);
	lock_release(&_data.lock);

	/*
	 * Alloc new call_array_t if it doesn't exist
	 */
	if (e != NULL)
	{
		LM_DBG("Found key %.*s in hash table\n", e->key.len, e->key.s);
	}
	else
	{
		credit_data_t *credit_data	= NULL;
		e							= shm_malloc(sizeof(struct str_hash_entry));

		if (e == NULL)
		{
			LM_ERR("No shared memory left\n");
			return NULL;
		}

		if (shm_str_dup(&e->key, client_id) != 0)
		{
			LM_ERR("No shared memory left\n");
			return NULL;
		}

		e->flags					= 0;
		e->u.p						= (void *) shm_malloc(sizeof(credit_data_t));
		credit_data					= (credit_data_t *) e->u.p;

		lock_init(&credit_data->lock);

		credit_data->call_list 		= shm_malloc(sizeof(call_t));

		if (credit_data->call_list == NULL)
		{
			LM_ERR("No shared memory left\n");
			return NULL;
		}

		credit_data->max_secs					= 0;
		credit_data->concurrent_calls			= 0;
		credit_data->consumed_secs				= 0;
		credit_data->ended_calls_consumed_secs 	= 0;
		credit_data->number_of_calls			= 0;

		/*
		 * Copy the client_id value to the root of the calls list.
		 * This will be used later to get the credit_data_t of the
		 * call when it is being searched by call ID.
		 */
		if (shm_str_dup(&credit_data->call_list->client_id, client_id) != 0)
		{
			LM_ERR("No shared memory left\n");
			return NULL;
		}

		clist_init(credit_data->call_list, next, prev);

		lock_get(&_data.lock);
		str_hash_add(ht, e);
		lock_release(&_data.lock);

		LM_DBG("Call didn't exist. Allocated new entry\n");
	}

	return (credit_data_t *) e->u.p;
}

static int terminate_call(call_t *call)
{
	LM_DBG("Got kill signal for call [%.*s] client [%.*s] h_id [%u] h_entry [%u]. Dropping it now\n",
						call->sip_data.callid.len,
						call->sip_data.callid.s,
						call->client_id.len,
						call->client_id.s,
						call->dlg_h_id,
						call->dlg_h_entry);

	struct mi_root *root, *result	= NULL;
	struct mi_node *node, *node1	= NULL;
	struct mi_cmd *end_dlg_cmd		= NULL;

	root	= init_mi_tree(0, 0, 0);
	if (root == NULL)
	{
		LM_ERR("Error initializing tree to terminate call\n");
		goto error;
	}

	node	= &root->node;

	node1	= addf_mi_node_child(node, MI_DUP_VALUE, MI_SSTR("h_entry"), "%u", call->dlg_h_entry);
	if (node1 == NULL)
	{
		LM_ERR("Error initializing h_entry node to terminate call\n");
		goto error;
	}

	node1	= addf_mi_node_child(node, MI_DUP_VALUE, MI_SSTR("h_id"), "%u", call->dlg_h_id);
	if (node1 == NULL)
	{
		LM_ERR("Error initializing dlg_h_id node to terminate call\n");
		goto error;
	}

	end_dlg_cmd = lookup_mi_cmd(MI_SSTR("dlg_end_dlg"));
	if (node == NULL)
	{
		LM_ERR("Error initializing dlg_end_dlg command\n");
		goto error;
	}

	result		= run_mi_cmd(end_dlg_cmd, root);
	if (result == NULL)
	{
		LM_ERR("Error executing dlg_end_dlg command\n");
		goto error;
	}

	if (result->code == 200)
	{
		LM_DBG("dlg_end_dlg sent to call [%.*s]\n", call->sip_data.callid.len, call->sip_data.callid.s);
		free_mi_tree(root);
		free_mi_tree(result);

		notify_call_termination(&call->sip_data.callid, &call->sip_data.from_tag, &call->sip_data.to_tag);

		return 0;
	}

	LM_ERR("Error executing dlg_end_dlg command. Return code was [%d]\n", result->code);
error:
	if (root)
		free_mi_tree(root);

	return -1;
}

static call_t *alloc_new_call(credit_data_t *credit_data, struct sip_msg *msg, int max_secs)
{
	call_t *call		= NULL;

	lock_get(&credit_data->lock);

	if (credit_data->call_list == NULL)
	{
		LM_ERR("Credit data call list is NULL\n");
		goto error;
	}

	call 				= shm_malloc(sizeof(call_t));
	if (call == NULL)
	{
		LM_ERR("No shared memory left\n");
		goto error;
	}

	if ( (!msg->callid && parse_headers(msg, HDR_CALLID_F, 0) != 0) ||
		   shm_str_dup(&call->sip_data.callid, &msg->callid->body) != 0 )
	{
		LM_ERR("Error processing CALLID hdr\n");
		goto error;
	}

	call->sip_data.to_tag.s		= NULL;
	call->sip_data.to_tag.len 	= 0;
	call->sip_data.from_tag.s	= NULL;
	call->sip_data.from_tag.len = 0;

	call->consumed_secs			= 0;
	call->confirmed				= FALSE;
	call->max_secs				= max_secs;

	/*
	 * Reference the client_id from the root of the list
	 */
	call->client_id.s			= credit_data->call_list->client_id.s;
	call->client_id.len			= credit_data->call_list->client_id.len;

	/*
	 * Insert the newly created call to the list of calls
	 */
	clist_insert(credit_data->call_list, call, next, prev);

	lock_init(&call->lock);

	/*
	 * Increase the number of calls for this client. This call is not yet confirmed.
	 */
	credit_data->number_of_calls++;

	lock_release(&credit_data->lock);

	LM_DBG("New call allocated for client [%.*s]\n", call->client_id.len, call->client_id.s);

	return call;

error:
	lock_release(&credit_data->lock);
	return NULL;
}

static int add_call_by_cid(str *cid, call_t *call)
{
	struct str_hash_entry *e;
	e	= str_hash_get(_data.call_data_by_cid, cid->s, cid->len);

	if (e != NULL)
	{
		LM_DBG("e != NULL\n");

		call_t *value	= (call_t *) e->u.p;

		if (value == NULL)
		{
			LM_ERR("Value of CID [%.*s] is NULL\n", cid->len, cid->s);
			return -1;
		}

		LM_WARN("value cid: len=%d | value [%.*s]", value->sip_data.callid.len, value->sip_data.callid.len, value->sip_data.callid.s);
		LM_WARN("added cid: len=%d | value [%.*s]", cid->len, cid->len, cid->s);

		if (value->sip_data.callid.len != cid->len ||
			strncasecmp(value->sip_data.callid.s, cid->s, cid->len) != 0)
		{
			LM_ERR("Value of CID is [%.*s] and differs from value being added [%.*s]\n", cid->len, cid->s,
																			value->sip_data.callid.len, value->sip_data.callid.s);
			return -1;
		}

		LM_DBG("CID already present\n");

		return 0;
	}

	e	= shm_malloc(sizeof(struct str_hash_entry));

	if (e == NULL)
	{
		LM_ERR("No shared memory left\n");
		return -1;
	}

	if (shm_str_dup(&e->key, cid) != 0)
	{
		LM_ERR("No shared memory left\n");
		return -1;
	}

	e->u.p		= call;

	lock_get(&_data.lock);
	str_hash_add(_data.call_data_by_cid, e);
	lock_release(&_data.lock);

	return 0;
}

static int set_max_time(struct sip_msg* msg, char* str_pv_client, char* str_pv_maxsecs)
{
	credit_data_t *credit_data 	= NULL;
	call_t *call				= NULL;
	str client_id;
	pv_spec_t *max_secs_spec	= (pv_spec_t *) str_pv_maxsecs,
			  *client_id_spec	= (pv_spec_t *) str_pv_client;
	pv_value_t max_secs_val, client_id_val;
	int max_secs					= 0;

	if (_data.ctrl_flag != -1)
	{
		LM_DBG("Flag set!\n");
		setflag(msg, _data.ctrl_flag);
	}

	if (parse_headers(msg, HDR_CALLID_F, 0) != 0)
	{
		LM_ERR("Error parsing Call-ID");
		return -1;
	}

	if (msg->first_line.type == SIP_REQUEST && msg->first_line.u.request.method_value == METHOD_INVITE)
	{
		if (has_to_tag(msg))
		{
			LM_ERR("INVITE is a reINVITE\n");
			return -1;
		}

		if (pv_get_spec_value(msg, max_secs_spec, &max_secs_val) != 0)
		{
			LM_ERR("Can't get max_secs PV value\n");
			return -1;
		}
		max_secs	= max_secs_val.ri;

		if (max_secs <= 0)
		{
			LM_ERR("[%.*s] MAXSECS cannot be less than or equal to zero: %d\n", msg->callid->body.len, msg->callid->body.s, max_secs);
			return -1;
		}

		if (pv_get_spec_value(msg, client_id_spec, &client_id_val) != 0)
		{
			LM_ERR("[%.*s]: can't get client_id PV value\n", msg->callid->body.len, msg->callid->body.s);
			return -1;
		}
		client_id	= client_id_val.rs;

		if (client_id.len == 0 || client_id.s == NULL)
		{
			LM_ERR("[%.*s]: client ID cannot be null\n", msg->callid->body.len, msg->callid->body.s);
			return -1;
		}

		LM_DBG("Setting up new call for client [%.*s], max-secs[%d], call-id[%.*s]\n", client_id.len, client_id.s,
																		max_secs,
																		msg->callid->body.len, msg->callid->body.s);

		if ((credit_data = get_or_create_credit_data_entry(&client_id)) == NULL)
		{
			LM_ERR("Error retrieving credit data from shared memory for client [%.*s]\n", client_id.len, client_id.s);
			return -1;
		}

		if ((call = alloc_new_call(credit_data, msg, max_secs)) == NULL)
		{
			LM_ERR("Unable to allocate new call for client [%.*s]\n", client_id.len, client_id.s);
			return -1;
		}

		if (add_call_by_cid(&call->sip_data.callid, call) != 0)
		{
			LM_ERR("Unable to allocate new cid_by_client for client [%.*s]\n", client_id.len, client_id.s);
			return -1;
		}

		//LM_ALERT("ready!");
	}
	else
	{
		LM_ALERT("MSG was not a request\n");
		return -1;
	}

	return 1;
}

static int has_to_tag(struct sip_msg *msg)
{
	if (msg->to == NULL && parse_headers(msg, HDR_TO_F, 0) != 0)
	{
		LM_ERR("Cannot parse to-tag\n");
		return 0;
	}

	return !(get_to(msg)->tag_value.s == NULL || get_to(msg)->tag_value.len == 0);
}

static int pv_parse_calls_param(pv_spec_p sp, str *in)
{
	if (sp == NULL || in == NULL || in->len == 0)
		return -1;

	switch(in->len)
	{
	case 5:
		if (strncmp("total", in->s, in->len) == 0)
			sp->pvp.pvn.u.isname.name.n	= CNX_PV_TOTAL;
		else
			return -1;
		break;
	case 6:
		if (strncmp("active", in->s, in->len) == 0)
			sp->pvp.pvn.u.isname.name.n	= CNX_PV_ACTIVE;
		else
			return -1;
		break;
	case 7:
		if (strncmp("dropped", in->s, in->len) == 0)
			sp->pvp.pvn.u.isname.name.n	= CNX_PV_DROPPED;
		else
			return -1;
		break;

	}

	sp->pvp.pvn.type = PV_NAME_INTSTR;
	sp->pvp.pvn.u.isname.type = 0;

	return 0;
}

static int pv_get_calls(struct sip_msg *msg, pv_param_t *param, pv_value_t *res)
{
	switch(param->pvn.u.isname.name.n)
	{
	case CNX_PV_ACTIVE:
		return pv_get_uintval(msg, param, res, _data.stats->active);
	case CNX_PV_TOTAL:
		return pv_get_uintval(msg, param, res, _data.stats->total);
	case CNX_PV_DROPPED:
		return pv_get_uintval(msg, param, res, _data.stats->dropped);
	default:
		LM_ERR("Unknown PV type %d\n", param->pvn.u.isname.name.n);
		break;
	}

	return -1;
}

static struct mi_root *mi_credit_control_stats(struct mi_root *tree, void *param)
{
	char *p;
	int len;
	struct mi_root *rpl_tree;
	struct mi_node *node, *node1;

	/*node	= tree->node.kids;
	if (node == NULL)
		return init_mi_tree(500, MI_MISSING_PARM_S, MI_MISSING_PARM_LEN);

	sp	= node->value;
	if (sp.len <= 0 || sp.s == NULL)
	{
		LM_ERR("Invalid param\n");
		return init_mi_tree(500, "Invalid param", sizeof("Invalid param") - 1);
	}*/

	rpl_tree	= init_mi_tree(200, "OK", 2);
	node		= &rpl_tree->node;

	node1 = add_mi_node_child(node, 0, MI_SSTR("CNX Credit Control"), 0, 0);
	if (node1 == NULL)
	{
		LM_ERR("Error creating child node\n");
		goto error;
	}

/*	if (addf_mi_attr(node1, 0, MI_SSTR("hola"), "-> %s", "que tal") == 0)
		goto error;*/

	p	= int2str((unsigned long) _data.stats->active, &len);
	if (p == NULL)
	{
		LM_ERR("Error converting INT to STR\n");
		goto error;
	}
	add_mi_node_child(node1, MI_DUP_VALUE, MI_SSTR("active"), p, len);

	p	= int2str((unsigned long) _data.stats->dropped, &len);
	if (p == NULL)
	{
		LM_ERR("Error converting INT to STR\n");
		goto error;
	}
	add_mi_node_child(node1, MI_DUP_VALUE, MI_SSTR("dropped"), p, len);

	p	= int2str((unsigned long) _data.stats->total, &len);
	if (p == NULL)
	{
		LM_ERR("Error converting INT to STR\n");
		goto error;
	}

	add_mi_node_child(node1, MI_DUP_VALUE, MI_SSTR("total"), p, len);

	return rpl_tree;

error:
	return init_mi_tree(500, MI_INTERNAL_ERR, MI_INTERNAL_ERR_LEN);
}
