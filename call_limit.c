/* $Id$
 *
 * Copyright (c) 2010 Thiago Rondon
 *
 * This file is part of OpenSIPS, a free SIP server.
 *
 * OpenSIPS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * For a license to use the OpenSIPS software under conditions
 * other than those described here, or to purchase support for this
 * software, please contact iptel.org by e-mail at the following addresses:
 *    info@iptel.org
 *
 * OpenSIPS is distributed in the hope that it will be useful,
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
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>
#include <assert.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/un.h>

#include "../../sr_module.h"
#include "../../mem/mem.h"
#include "../../dprint.h"
#include "../../str.h"
#include "../../pvar.h"
#include "../../ut.h"
#include "../../script_cb.h"
#include "../../parser/digest/digest.h"
#include "../../parser/parse_from.h"
#include "../dialog/dlg_load.h"
#include "../dialog/dlg_hash.h"

#include "../xlog/xl_lib.h"


#define FL_USE_CALL_LIMIT       (1<<30) // use call limit for a dialog

#if defined(__GNUC__) && !defined(__STRICT_ANSI__)
# define INLINE inline
#else
# define INLINE
#endif

// Although `AF_LOCAL' is mandated by POSIX.1g, `AF_UNIX' is portable to
// more systems.  `AF_UNIX' was the traditional name stemming from BSD, so
// even most POSIX systems support it.  It is also the name of choice in
// the Unix98 specification. So if there's no AF_LOCAL fallback to AF_UNIX
#ifndef AF_LOCAL
# define AF_LOCAL AF_UNIX
#endif

// Solaris does not have the MSG_NOSIGNAL flag for the send(2) syscall
#ifndef MSG_NOSIGNAL
# define MSG_NOSIGNAL 0
#endif

typedef int Bool;
#define True  1
#define False 0


typedef struct AVP_Param {
    str spec;
    int_str name;
    unsigned short type;
} AVP_Param;

typedef struct AVP_List {
    pv_spec_p pv;
    str name;
    struct AVP_List *next;
} AVP_List;

#define RETRY_INTERVAL 10
#define BUFFER_SIZE    8192

static int mod_init(void);
static int child_init(int rank);
static void destroy(void);

int parse_param_init(unsigned int type, void *val);
int parse_param_start(unsigned int type, void *val);
int parse_param_stop(unsigned int type, void *val);

static int call_limit(struct sip_msg *msg, char *str1, char *str2);
static int postprocess_request(struct sip_msg *msg, void *_param);


int limit_by_seconds = 0;
static int dialog_flag = -1;
struct dlg_binds dlg_api;

static param_export_t params[] = {
        {"seconds", INT_PARAM, &limit_by_seconds},
	{ 0, 0, 0 }
};

static cmd_export_t commands[] = {
    {"call_limit",  (cmd_function)call_limit, 0, 0, 0, REQUEST_ROUTE },
    {0, 0, 0, 0, 0, 0}
};

struct module_exports exports = {
    "call_limit",  // module name
    MODULE_VERSION,  // module version
    DEFAULT_DLFLAGS, // dlopen flags
    commands,        // exported functions
    params,      // exported parameters
    NULL,            // exported statistics
    NULL,            // exported MI functions
    NULL,            // exported pseudo-variables
    NULL,            // extra processes
    mod_init,        // module init function (before fork. kids will inherit)
    NULL,            // reply processing function
    destroy,         // destroy function
    child_init       // child init function
};

static Bool
has_to_tag(struct sip_msg *msg)
{
    str tag;

    if (!msg->to) {
        if (parse_headers(msg, HDR_TO_F, 0)==-1) {
            LM_ERR("cannot parse 'To' header\n");
            return False;
        }
        if (!msg->to) {
            LM_ERR("missing 'To' header\n");
            return False;
        }
    }

    tag = get_to(msg)->tag_value;

    if (tag.s==NULL || tag.len==0) {
        return False;
    }

    return True;
}

static int
postprocess_request(struct sip_msg *msg, void *_param)
{
	if ((msg->msg_flags & FL_USE_CALL_LIMIT) == 0)
		return 1;

    // the FL_USE_CALL_CONTROL flag is still set => the dialog was not created

	LM_WARN("dialog to trace controlled call was not created. discarding callcontrol.");
	return 1;
}


int
parse_param_init(unsigned int type, void *val) {
    return 0;
}

int
parse_param_start(unsigned int type, void *val) {
    return 0;
}

int
parse_param_stop(unsigned int type, void *val) {
    return 0;
}

static void
__dialog_replies(struct dlg_cell *dlg, int type, struct dlg_cb_params *_params)
{
    struct sip_msg *reply = _params->msg;

	LM_WARN("__dialog_replies.");

    if (reply!=FAKED_REPLY && reply->REPLY_STATUS==200) {
        //call_control_start(reply, dlg);
    }
}

static void
__dialog_ended(struct dlg_cell *dlg, int type, struct dlg_cb_params *_params)
{
	return;
}


static void
__dialog_created(struct dlg_cell *dlg, int type, struct dlg_cb_params *_params)
{
 	struct sip_msg *request = _params->msg;

	LM_WARN("__dialog_created.");


    	if (request->REQ_METHOD != METHOD_INVITE)
        	return;

	if ((request->msg_flags & FL_USE_CALL_LIMIT) == 0)
		return;

    	if (dlg_api.register_dlgcb(dlg, DLGCB_RESPONSE_FWDED, __dialog_replies, NULL, NULL) != 0)
        	LM_ERR("cannot register callback for dialog confirmation\n");
    	
	if (dlg_api.register_dlgcb(dlg, DLGCB_TERMINATED | DLGCB_FAILED | DLGCB_EXPIRED | DLGCB_DESTROY, __dialog_ended, NULL, NULL) != 0)
        	LM_ERR("cannot register callback for dialog termination\n");

    	// reset the flag to indicate that the dialog for callcontrol was created
    	request->msg_flags &= ~FL_USE_CALL_LIMIT;
}

static void
__dialog_loaded(struct dlg_cell *dlg, int type, struct dlg_cb_params *_params)
{
	
	LM_WARN("dialog_loaded");

	if (dlg_api.register_dlgcb(dlg, DLGCB_RESPONSE_FWDED, __dialog_replies, NULL, NULL) != 0)
		LM_ERR("cannot register callback for dialog confirmation\n");
   
	if (dlg_api.register_dlgcb(dlg, DLGCB_RESPONSE_WITHIN, __dialog_replies, NULL, NULL) != 0)
		LM_ERR("cannot register callback for dialog confirmation\n");
  
	if (dlg_api.register_dlgcb(dlg, DLGCB_TERMINATED | DLGCB_FAILED | DLGCB_EXPIRED | DLGCB_DESTROY, __dialog_ended, NULL, NULL) != 0)
        	LM_ERR("cannot register callback for dialog termination\n");
}

// Module management: initialization/destroy/function-parameter-fixing/...
//

static int
mod_init(void)
{
	int *param;

	LM_INFO("initializing...\n");

	LM_INFO("limit_by_seconds: %d\n", limit_by_seconds);

	// bind to the dialog API
	if (load_dlg_api(&dlg_api)!=0) {
		LM_CRIT("cannot load the dialog module API\n");
		return -1;    
	}
	
	// load dlg_flag and default_timeout parameters from the dialog module
	param = find_param_export("dialog", "dlg_flag", INT_PARAM);
	if (!param) {
		LM_CRIT("cannot find dlg_flag parameter in the dialog module\n");
		return -1;
	}
	dialog_flag = *param;
	
	// register dialog creation callback
	if (dlg_api.register_dlgcb(NULL, DLGCB_CREATED, __dialog_created, NULL, NULL) != 0) {
		LM_CRIT("cannot register callback for dialog creation\n");
        	return -1;
	}

	// register dialog loading callback
	if (dlg_api.register_dlgcb(NULL, DLGCB_LOADED, __dialog_loaded, NULL, NULL) != 0) { 
		LM_ERR("cannot register callback for dialogs loaded from the database\n");
	}

	// register a pre-script callback to automatically enable dialog tracing
	if (register_script_cb(postprocess_request, POST_SCRIPT_CB|REQ_TYPE_CB, 0) != 0) {
		LM_CRIT("could not register request postprocessing callback\n");
		return -1;
	}

	return 0;
}


static int
child_init(int rank)
{
    return 0;
}


static void
destroy(void) {
	return;
}

// Return codes:
//   2 - No limit
//   1 - Limited
//  -1 - Error with INVITE (has_tag) message.
static int
call_limit(struct sip_msg *msg, char *str1, char *str2)
{
	if (msg->first_line.type!=SIP_REQUEST || msg->REQ_METHOD!=METHOD_INVITE || has_to_tag(msg)) {
		LM_WARN("should only be called for the first INVITE\n");
		return -1;
    	}

	if (limit_by_seconds) {
		msg->msg_flags |= FL_USE_CALL_LIMIT;
        	setflag(msg, dialog_flag); // have the dialog module trace this dialog
		return 1;
	}

	return 2;
}

