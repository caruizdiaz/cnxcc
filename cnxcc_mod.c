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

#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../error.h"
#include "../../mem/mem.h"
#include "../../shm_init.h"
#include "../../mem/shm_mem.h"
#include "../../pvar.h"
#include "../../locking.h"
#include "../../lock_ops.h"
#include "../../str_hash.h"
//#include "../../timer.h"
#include "../../timer_proc.h"
#include "../../modules/tm/tm_load.h"
#include "../../parser/parse_from.h"
#include "../../parser/parse_to.h"
#include "../../parser/parse_uri.h"
#include "../../parser/parse_cseq.h"
#include "../../parser/contact/parse_contact.h"
#include "../../parser/contact/contact.h"
#include "../../parser/parse_rr.h"
//#include "../../lib/kcore/parser_helpers.h"
#include "../../mod_fix.h"
#include "../dialog/dlg_load.h"
#include "../dialog/dlg_hash.h"
#include "../../mi/mi_types.h"
#include "../../lib/kcore/faked_msg.h"
#include "../../rpc.h"
#include "../../rpc_lookup.h"

#include "cnxcc_mod.h"
#include "cnxcc.h"
#include "cnxcc_sip_msg_faker.h"
#include "cnxcc_check.h"
#include "cnxcc_rpc.h"

MODULE_VERSION

#define HT_SIZE						229
#define MODULE_NAME					"CNXCC"
#define NUMBER_OF_TIMERS			2

#define TRUE						1
#define FALSE						0

data_t _data;
struct dlg_binds _dlgbinds;

static int fixup_par(void** param, int param_no);

/*
 *  module core functions
 */
static int mod_init(void);
static int child_init(int);
static int init_hashtable(struct str_hash_table *ht);

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
static int set_max_credit(struct sip_msg* msg, char *str_pv_client, char *str_pv_credit, char *str_pv_cps, char *str_pv_inip, char *str_pv_finp);
static void start_billing(str *callid, str tags[2]);
static void setup_billing(str *callid, unsigned int h_entry, unsigned int h_id);
static void stop_billing(str *callid);
static int add_call_by_cid(str *cid, call_t *call, credit_type_t type);
static credit_data_t *get_or_create_credit_data_entry(str *client_id, credit_type_t type);
static call_t *alloc_new_call_by_time(credit_data_t *credit_data, struct sip_msg *msg, int max_secs);
static call_t *alloc_new_call_by_money(credit_data_t *credit_data, struct sip_msg *msg, double credit, double cost_per_second, int initial_pulse, int final_pulse);
static void notify_call_termination(str *callid, str *from_tag, str *to_tag);
static void free_call(call_t *call);
static int has_to_tag(struct sip_msg *msg);

/*
 * MI interface
 */
static struct mi_root *mi_credit_control_stats(struct mi_root *tree, void *param);

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
	{"cnxcc_set_max_credit",   (cmd_function) set_max_credit, 5, fixup_par, NULL, ANY_ROUTE},
	{0,0,0,0,0,0}
};

static param_export_t params[] =
{
	{"dlg_flag",  				INT_PARAM,			&_data.ctrl_flag	},
	{"credit_check_period",  	INT_PARAM,			&_data.check_period	},
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
	child_init          /* per-child init function */
};

static int fixup_par(void** param, int param_no)
{
	str var;

	var.s	= (char *) *param;
	var.len = strlen(var.s);

	if (fixup_pvar_null(param, 1))
	{
		LM_ERR("Invalid PV [%.*s] as parameter\n", var.len, var.s);
		return E_CFG;
	}
/*
	if (((pv_spec_t*)(*param))->setf == NULL)
	{
		LM_ERR("[%.*s] has to be writable\n", var.len, var.s);
		return E_CFG;
	} */

	return 0;
}

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

	if (_data.check_period <= 0)
	{
		LM_INFO("credit_check_period cannot be less than 1 second");
		return -1;
	}

	_data.time.credit_data_by_client	= shm_malloc(sizeof(struct str_hash_table));
	_data.time.call_data_by_cid 		= shm_malloc(sizeof(struct str_hash_table));
	_data.money.credit_data_by_client	= shm_malloc(sizeof(struct str_hash_table));
	_data.money.call_data_by_cid 		= shm_malloc(sizeof(struct str_hash_table));

	_data.stats							= (stats_t *) shm_malloc(sizeof(stats_t));

	if (!_data.stats)
	{
		LM_ERR("Error allocating shared memory stats\n");
		return -1;
	}

	_data.stats->active		= 0;
	_data.stats->dropped	= 0;
	_data.stats->total		= 0;

	if (init_hashtable(_data.time.credit_data_by_client) != 0)
		return -1;

	if (init_hashtable(_data.time.call_data_by_cid) != 0)
		return -1;

	if (init_hashtable(_data.money.credit_data_by_client) != 0)
		return -1;

	if (init_hashtable(_data.money.call_data_by_cid) != 0)
		return -1;

	lock_init(&_data.lock);
	lock_init(&_data.time.lock);
	lock_init(&_data.money.lock);

	register_mi_cmd(mi_credit_control_stats, "cnxcc_stats", NULL, NULL, 0);

	/*
	 * One for time based monitoring
	 * One for money based monitoring
	 */
	register_dummy_timers(NUMBER_OF_TIMERS);

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

static int child_init(int rank)
{
	if (rank != PROC_MAIN)
		return 0;


	if(fork_dummy_timer(PROC_TIMER, "CNXCC TB TIMER", 1,
			check_calls_by_money, NULL, _data.check_period) < 0)
	{
		LM_ERR("failed to register TB TIMER routine as process\n");
		return -1;
	}

	if(fork_dummy_timer(PROC_TIMER, "CNXCC MB TIMER", 1,
								check_calls_by_time, NULL, _data.check_period) < 0)
	{
		LM_ERR("failed to register MB TIMER routine as process\n");
		return -1;
	}

	return 0;
}

static int init_hashtable(struct str_hash_table *ht)
{
	if (shm_str_hash_alloc(ht, HT_SIZE) != 0)
	{
		LM_ERR("Error allocating shared memory hashtable\n");
		return -1;
	}

	str_hash_init(ht);

	return 0;
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

int try_get_credit_data_entry(str *client_id, credit_data_t **credit_data)
{
	struct str_hash_entry *cd_entry	= NULL;
	hash_tables_t *hts				= NULL;
	*credit_data					= NULL;

	hts					= &_data.money;
	lock_get(&hts->lock);

	cd_entry			= str_hash_get(hts->credit_data_by_client, client_id->s, client_id->len);

	if (cd_entry != NULL)
	{
		*credit_data	= cd_entry->u.p;
		lock_release(&hts->lock);
		return 0;
	}

	lock_release(&hts->lock);

	hts					= &_data.time;
	lock_get(&hts->lock);

	cd_entry			= str_hash_get(hts->call_data_by_cid, client_id->s, client_id->len);

	if (cd_entry != NULL)
	{
		*credit_data	= cd_entry->u.p;
		lock_release(&hts->lock);
		return 0;
	}

	lock_release(&hts->lock);

	return -1;
}

int try_get_call_entry(str *callid, call_t **call, hash_tables_t **hts)
{
	struct str_hash_entry *call_entry	= NULL;

	*call					= NULL;

	*hts					= &_data.money;
	lock_get(&(*hts)->lock);

	call_entry			= str_hash_get((*hts)->call_data_by_cid, callid->s, callid->len);

	if (call_entry != NULL)
	{
		*call	= call_entry->u.p;
		lock_release(&(*hts)->lock);
		return 0;
	}

	lock_release(&(*hts)->lock);

	*hts				= &_data.time;
	lock_get(&(*hts)->lock);

	call_entry			= str_hash_get((*hts)->call_data_by_cid, callid->s, callid->len);

	if (call_entry != NULL)
	{
		*call	= call_entry->u.p;
		lock_release(&(*hts)->lock);
		return 0;
	}

	lock_release(&(*hts)->lock);

	return -1;
}

static void stop_billing(str *callid)
{
	struct str_hash_entry *cd_entry		= NULL;
	call_t *call						= NULL;
	hash_tables_t *hts					= NULL;
	credit_data_t *credit_data			= NULL;

	/*
	 * Search call data by call-id
	 */
	if (try_get_call_entry(callid, &call, &hts) != 0)
	{
		LM_ERR("Call [%.*s] not found", callid->len, callid->s);
		return;
	}

	if (call == NULL)
	{
		LM_ERR("[%.*s] call pointer is null", callid->len, callid->s);
		return;
	}

	if (hts == NULL)
	{
		LM_ERR("[%.*s] result hashtable pointer is null", callid->len, callid->s);
		return;
	}

	lock_get(&hts->lock);

	/*
	 * Search credit_data by client_id
	 */
	cd_entry			= str_hash_get(hts->credit_data_by_client, call->client_id.s, call->client_id.len);

	if (cd_entry == NULL)
	{
		LM_ERR("Credit data not found for CID [%.*s], client-ID [%.*s]\n", callid->len, callid->s, call->client_id.len, call->client_id.s);
		lock_release(&hts->lock);
		return;
	}

	credit_data	= (credit_data_t *) cd_entry->u.p;

	if (credit_data == NULL)
	{
		LM_ERR("[%.*s]: credit_data pointer is null", callid->len, callid->s);
		lock_release(&hts->lock);
		return;
	}

	lock_release(&hts->lock);

	/*
	 * Update calls statistics
	 */
	lock_get(&_data.lock);

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
		credit_data->ended_calls_consumed_amount += call->consumed_amount;
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

		lock(&hts->lock);
		/*
		 * Remove the credit_data_t from the hash table
		 */
		str_hash_del(cd_entry);

		lock_release(&hts->lock);

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
	call_t *call						= NULL;
	hash_tables_t *hts					= NULL;

	LM_DBG("Creating dialog for [%.*s], h_id [%u], h_entry [%u]", callid->len, callid->s, h_id, h_entry);

//	lock_get(&_data.lock);

	/*
	 * Search call data by call-id
	 */
	if (try_get_call_entry(callid, &call, &hts) != 0)
	{
		LM_ERR("Call [%.*s] not found", callid->len, callid->s);
		return;
	}

	if (call == NULL)
	{
		LM_ERR("[%.*s] call pointer is null", callid->len, callid->s);
		return;
	}

	if (hts == NULL)
	{
		LM_ERR("[%.*s] result hashtable pointer is null", callid->len, callid->s);
		return;
	}

	/*
	 * Update calls statistics
	 */
	lock_get(&_data.lock);

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
	struct str_hash_entry *cd_entry		= NULL;
	call_t *call						= NULL;
	hash_tables_t *hts					= NULL;
	credit_data_t *credit_data			= NULL;

	LM_DBG("Billing started for call [%.*s]", callid->len, callid->s);

//	lock_get(&_data.lock);

	/*
	 * Search call data by call-id
	 */
	if (try_get_call_entry(callid, &call, &hts) != 0)
	{
		LM_ERR("Call [%.*s] not found", callid->len, callid->s);
		return;
	}

	if (call == NULL)
	{
		LM_ERR("[%.*s] call pointer is null", callid->len, callid->s);
		return;
	}

	if (hts == NULL)
	{
		LM_ERR("[%.*s] result hashtable pointer is null", callid->len, callid->s);
		return;
	}

	lock_get(&hts->lock);

	/*
	 * Search credit_data by client_id
	 */
	cd_entry			= str_hash_get(hts->credit_data_by_client, call->client_id.s, call->client_id.len);

	if (cd_entry == NULL)
	{
		LM_ERR("Credit data not found for CID [%.*s], client-ID [%.*s]\n", callid->len, callid->s, call->client_id.len, call->client_id.s);
		lock_release(&hts->lock);
		return;
	}

	credit_data	= (credit_data_t *) cd_entry->u.p;

	if (credit_data == NULL)
	{
		LM_ERR("[%.*s]: credit_data pointer is null", callid->len, callid->s);
		lock_release(&hts->lock);
		return;
	}

	lock_release(&hts->lock);

	lock(&credit_data->lock);

	/*
	 * Now that the call is confirmed, we can increase the count of "concurrent_calls".
	 * This will impact in the discount rate performed by the check_calls() function.
	 *
	 */
	credit_data->concurrent_calls++;

	if (credit_data->max_amount == 0)
		credit_data->max_amount	= call->max_amount; // first time setup

	if (call->max_amount > credit_data->max_amount)
	{
		LM_ALERT("Maximum-speak-time/credit changed, maybe a credit reload? %f > %f. Client [%.*s]", call->max_amount, credit_data->max_amount,
																							call->client_id.len, call->client_id.s);

		credit_data->max_amount += call->max_amount - credit_data->max_amount;
	}

	/*
	 * Update max_amount, discounting what was already consumed by other calls of the same client
	 */

	call->max_amount = credit_data->max_amount - credit_data->consumed_amount;

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


void terminate_all_calls(credit_data_t *credit_data)
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

	e			= str_hash_get(_data.money.call_data_by_cid, call->sip_data.callid.s, call->sip_data.callid.len);

	if (e == NULL)
	{
		e			= str_hash_get(_data.time.call_data_by_cid, call->sip_data.callid.s, call->sip_data.callid.len);

		if (e == NULL)
		{
			LM_ERR("Call [%.*s] not found. Couldn't be able to free it from hashtable", call->sip_data.callid.len, call->sip_data.callid.s);
			return;
		}
	}

	str_hash_del(e);

	shm_free(e->key.s);
	shm_free(e);

	str_shm_free_if_not_null(call->sip_data.callid);
	str_shm_free_if_not_null(call->sip_data.to_tag);
	str_shm_free_if_not_null(call->sip_data.from_tag);

	shm_free(call);
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

static credit_data_t *get_or_create_credit_data_entry(str *client_id, credit_type_t type)
{
	struct str_hash_table *ht	= type == CREDIT_MONEY ? _data.money.credit_data_by_client : _data.time.credit_data_by_client;
	gen_lock_t *lock			= type == CREDIT_MONEY ? &_data.money.lock : &_data.time.lock;
	struct str_hash_entry *e	= NULL;

	lock_get(lock);
	e							= str_hash_get(ht, client_id->s, client_id->len);
	lock_release(lock);

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

		credit_data->max_amount					= 0;
		credit_data->concurrent_calls			= 0;
		credit_data->consumed_amount			= 0;
		credit_data->ended_calls_consumed_amount= 0;
		credit_data->number_of_calls			= 0;

		credit_data->type						= type;

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

		lock_get(lock);
		str_hash_add(ht, e);
		lock_release(lock);

		LM_DBG("Call didn't exist. Allocated new entry\n");
	}

	return (credit_data_t *) e->u.p;
}

int terminate_call(call_t *call)
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

static call_t *alloc_new_call_by_money(credit_data_t *credit_data,
										struct sip_msg *msg, double credit, double cost_per_second, int initial_pulse, int final_pulse)
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

	call->consumed_amount		= initial_pulse * cost_per_second;
	call->confirmed				= FALSE;
	call->max_amount			= credit;

	call->money_based.cost_per_second	= cost_per_second;
	call->money_based.initial_pulse		= initial_pulse;
	call->money_based.final_pulse		= final_pulse;

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

static call_t *alloc_new_call_by_time(credit_data_t *credit_data, struct sip_msg *msg, int max_secs)
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

	call->consumed_amount		= 0;
	call->confirmed				= FALSE;
	call->max_amount			= max_secs;

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

static int add_call_by_cid(str *cid, call_t *call, credit_type_t type)
{
	struct str_hash_entry *e	= NULL;
	struct str_hash_table *ht	= type == CREDIT_MONEY ? _data.money.call_data_by_cid : _data.time.call_data_by_cid;
	gen_lock_t *lock			= type == CREDIT_MONEY ? &_data.money.lock : &_data.time.lock;

	e	= str_hash_get(ht, cid->s, cid->len);

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

	lock_get(lock);
	str_hash_add(ht, e);
	lock_release(lock);

	return 0;
}

static inline void set_ctrl_flag(struct sip_msg* msg)
{
	if (_data.ctrl_flag != -1)
	{
		LM_DBG("Flag set!\n");
		setflag(msg, _data.ctrl_flag);
	}
}

static inline int get_pv_value(struct sip_msg* msg, pv_spec_t* spec, pv_value_t* value)
{
	if (pv_get_spec_value(msg, spec, value) != 0)
	{
		LM_ERR("Can't get PV's value\n");
		return -1;
	}

	return 0;
}

static int set_max_credit(struct sip_msg* msg,
							char *str_pv_client,
							char *str_pv_credit, char *str_pv_cps,
							char *str_pv_inip, char *str_pv_finp)
{
	credit_data_t *credit_data 	= NULL;
	call_t *call				= NULL;

	pv_spec_t *client_id_spec		= (pv_spec_t *) str_pv_client,
			  *credit_spec			= (pv_spec_t *) str_pv_credit,
			  *cps_spec				= (pv_spec_t *) str_pv_cps,
			  *initial_pulse_spec	= (pv_spec_t *) str_pv_inip,
			  *final_pulse_spec		= (pv_spec_t *) str_pv_finp;

	pv_value_t client_id_val,
				credit_val,
				cps_val,
				initial_pulse_val,
				final_pulse_val;

	double credit					= 0,
		   cost_per_second			= 0;

	unsigned int initial_pulse		= 0,
			final_pulse				= 0;

	if (msg->first_line.type == SIP_REQUEST && msg->first_line.u.request.method_value == METHOD_INVITE)
	{
		if (has_to_tag(msg))
		{
			LM_ERR("INVITE is a reINVITE\n");
			return -1;
		}

		if (pv_get_spec_value(msg, client_id_spec, &client_id_val) != 0)
		{
			LM_ERR("Can't get client_id's value\n");
			return -1;
		}

		if (pv_get_spec_value(msg, credit_spec, &credit_val) != 0)
		{
			LM_ERR("Can't get credit's value\n");
			return -1;
		}

		credit	= str2double(&credit_val.rs);

		if (credit <= 0)
		{
			LM_ERR("credit value must be > 0: %f", credit);
			return -1;
		}

		if (pv_get_spec_value(msg, cps_spec, &cps_val) != 0)
		{
			LM_ERR("Can't get cost_per_sec's value\n");
			return -1;
		}

		cost_per_second	= str2double(&cps_val.rs);

		if (cost_per_second <= 0)
		{
			LM_ERR("cost_per_second value must be > 0: %f", cost_per_second);
			return -1;
		}

		if (pv_get_spec_value(msg, initial_pulse_spec, &initial_pulse_val) != 0)
		{
			LM_ERR("Can't get initial_pulse's value\n");
			return -1;
		}

		if (str2int(&initial_pulse_val.rs, &initial_pulse) != 0)
		{
			LM_ERR("initial_pulse value is invalid: %.*s", initial_pulse_val.rs.len, initial_pulse_val.rs.s);
			return -1;
		}

		if (pv_get_spec_value(msg, final_pulse_spec, &final_pulse_val) != 0)
		{
			LM_ERR("Can't get final_pulse's value\n");
			return -1;
		}

		if (str2int(&final_pulse_val.rs, &final_pulse) != 0)
		{
			LM_ERR("final_pulse value is invalid: %.*s", final_pulse_val.rs.len, final_pulse_val.rs.s);
			return -1;
		}

		if (client_id_val.rs.len == 0 || client_id_val.rs.s == NULL)
		{
			LM_ERR("[%.*s]: client ID cannot be null\n", msg->callid->body.len, msg->callid->body.s);
			return -1;
		}

		LM_DBG("Setting up new call for client [%.*s], max-credit[%f], "
				"cost-per-sec[%f], initial-pulse [%d], "
				"final-pulse [%d], call-id[%.*s]\n", client_id_val.rs.len, client_id_val.rs.s,
													 credit,
													 cost_per_second, initial_pulse,
													 final_pulse, msg->callid->body.len, msg->callid->body.s);
		set_ctrl_flag(msg);

		if ((credit_data = get_or_create_credit_data_entry(&client_id_val.rs, CREDIT_MONEY)) == NULL)
		{
			LM_ERR("Error retrieving credit data from shared memory for client [%.*s]\n", client_id_val.rs.len, client_id_val.rs.s);
			return -1;
		}

		if ((call = alloc_new_call_by_money(credit_data, msg, credit, cost_per_second, initial_pulse, final_pulse)) == NULL)
		{
			LM_ERR("Unable to allocate new call for client [%.*s]\n", client_id_val.rs.len, client_id_val.rs.s);
			return -1;
		}

		if (add_call_by_cid(&call->sip_data.callid, call, CREDIT_MONEY) != 0)
		{
			LM_ERR("Unable to allocate new cid_by_client for client [%.*s]\n", client_id_val.rs.len, client_id_val.rs.s);
			return -1;
		}
	}
	else
	{
		LM_ALERT("MSG was not a request\n");
		return -1;
	}

	return 1;
}

static int set_max_time(struct sip_msg* msg, char* str_pv_client, char* str_pv_maxsecs)
{
	credit_data_t *credit_data 	= NULL;
	call_t *call				= NULL;
	pv_spec_t *max_secs_spec	= (pv_spec_t *) str_pv_maxsecs,
			  *client_id_spec	= (pv_spec_t *) str_pv_client;
	pv_value_t max_secs_val, client_id_val;
	int max_secs				= 0;

	set_ctrl_flag(msg);

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

		if (client_id_val.rs.len == 0 || client_id_val.rs.s == NULL)
		{
			LM_ERR("[%.*s]: client ID cannot be null\n", msg->callid->body.len, msg->callid->body.s);
			return -1;
		}

		LM_DBG("Setting up new call for client [%.*s], max-secs[%d], call-id[%.*s]\n", client_id_val.rs.len, client_id_val.rs.s,
																		max_secs,
																		msg->callid->body.len, msg->callid->body.s);

		if ((credit_data = get_or_create_credit_data_entry(&client_id_val.rs, CREDIT_TIME)) == NULL)
		{
			LM_ERR("Error retrieving credit data from shared memory for client [%.*s]\n", client_id_val.rs.len, client_id_val.rs.s);
			return -1;
		}

		if ((call = alloc_new_call_by_time(credit_data, msg, max_secs)) == NULL)
		{
			LM_ERR("Unable to allocate new call for client [%.*s]\n", client_id_val.rs.len, client_id_val.rs.s);
			return -1;
		}

		if (add_call_by_cid(&call->sip_data.callid, call, CREDIT_TIME) != 0)
		{
			LM_ERR("Unable to allocate new cid_by_client for client [%.*s]\n", client_id_val.rs.len, client_id_val.rs.s);
			return -1;
		}
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

	rpl_tree	= init_mi_tree(200, "OK", 2);
	node		= &rpl_tree->node;

	node1 = add_mi_node_child(node, 0, MI_SSTR("CNX Credit Control"), 0, 0);
	if (node1 == NULL)
	{
		LM_ERR("Error creating child node\n");
		goto error;
	}

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
