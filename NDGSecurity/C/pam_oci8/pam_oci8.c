/***************************************************************************

			 * PAM module for Oracle, OCi8, ported from pam_mysql *
			 * written by: Andreas Kofler <andreas.kofler@gmx.net> *


                             -------------------
    copyright            : (C) 2002 by Siag, Andreas Kofler
    email                : Andreas Kofler <andreas.kofler@gmx.net>
 ***************************************************************************/
/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/


#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <stdarg.h>
#include <alloca.h>
#include <string.h>
#include "sqlora.h"

/*
 * here, we make definitions for the externally accessible functions
 * in this file (these definitions are required for static modules
 * but strongly encouraged generally) they are used to instruct the
 * modules include file to define their prototypes.
 */

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#define PAM_MODULE_NAME  "pam_oci8"
#define PLEASE_ENTER_PASSWORD "Password:"
/* #define DEBUG */

#include <security/pam_modules.h>
#include <security/pam_misc.h>

struct optionstruct {
	char where[257];
	char connectString[65];
	char table[17];
	char usercolumn[17];
	char passwdcolumn[17];
};


/* Global Variables */

sqlo_db_handle_t dbh;
int connected=0;

struct optionstruct options =
{
	"",
	"user/password@host",
	"TABLE",
	"USERCOLUMN",
	"PASSWDCOLUMN",
};

/* Prototypes */
int converse (pam_handle_t * pamh, int nargs, struct pam_message **message, struct pam_response **response);
int _set_auth_tok (pam_handle_t * pamh, int flags, int argc, const char **argv);

/*int db_connect (sqlo_db_handle_t dbh);*/
int db_connect ();
void db_close( void );
int askForPassword(pam_handle_t *pamh);

void db_close ( void ){
	if (connected) {
		connected=0;
		sqlo_finish(dbh);
	}
}

/* sqlora access functions */
int db_connect (){
	connected=0;
  if (SQLO_SUCCESS != sqlo_init(SQLO_OFF, 1, 100)) {
    syslog(LOG_ERR, "pam_oci8: Failed to init libsqlora8\n");
    return PAM_AUTH_ERR;
  }

	/* login */
  if (SQLO_SUCCESS != sqlo_connect(&dbh, options.connectString)) {
  	syslog(LOG_ERR, "pam_oci8: Cannot login with %s\n", options.connectString);
    return PAM_AUTH_ERR;
  }
	connected=1;
  return PAM_SUCCESS;
}

static int db_checkpasswd (const char *user, const char *passwd){
	sqlo_stmt_handle_t sth;
	int retval;
	char *sql = (char * )malloc (100 + strlen (user) + strlen (passwd) +
	 						strlen (options.table) + 2*strlen (options.usercolumn) +
							strlen (options.passwdcolumn) + strlen (options.where));

	sprintf(sql, "SELECT %s FROM %s WHERE %s='%s' and %s='%s' %s",
				options.usercolumn, options.table, options.usercolumn,
				user, options.passwdcolumn, passwd, options.where);

  if ( 0 > (sth = (sqlo_open(dbh, sql, 0, 0))) ) {
		syslog(LOG_ERR, "pam_oci8: Sql-error: %s", sql);
		free(sql);
		return PAM_AUTH_ERR;
	}

	if ( SQLO_SUCCESS == (sqlo_fetch(sth, 1))) {
		/*if the sql-query returns a ruslt --> authentication was successfully*/
		retval=PAM_SUCCESS;
	}
	else {
		syslog(LOG_ERR, "pam_oci8: Authentication failure, user %s", user);
		retval=PAM_AUTH_ERR;
	}
	free(sql);
	sqlo_close(sth);
	return retval;
}


/* Global PAM functions stolen from other modules */

int converse(pam_handle_t *pamh, int nargs
		    , struct pam_message **message
		    , struct pam_response **response)
{
    int retval;
    struct pam_conv *conv;

    retval = pam_get_item( pamh, PAM_CONV, (const void **) &conv ) ;
    if ( retval == PAM_SUCCESS )
    {
	retval = conv->conv(nargs, ( const struct pam_message ** ) message
			    , response, conv->appdata_ptr);
	if ((retval != PAM_SUCCESS) && (retval != PAM_CONV_AGAIN))
	{
	    syslog(LOG_DEBUG, "pam_oci8: conversation failure [%s]"
		     , pam_strerror(pamh, retval));
	}
    }
    else
    {
	syslog(LOG_ERR, "pam_oci8: couldn't obtain coversation function [%s]"
		 , pam_strerror(pamh, retval));
    }
    return retval;                  /* propagate error status */
}

int askForPassword(pam_handle_t *pamh)
{
	struct pam_message msg[1], *mesg[1];
	struct pam_response *resp=NULL;
	char *prompt=NULL;
	int i=0;
	int retval;

	prompt = malloc(strlen(PLEASE_ENTER_PASSWORD));
	if (prompt == NULL)
	{
		syslog(LOG_ERR,"pam_oci8: askForPassword(), out of memory!?");
		return PAM_BUF_ERR;
	}
	else
	{
		sprintf(prompt, PLEASE_ENTER_PASSWORD);
		msg[i].msg = prompt;
	}
	msg[i].msg_style = PAM_PROMPT_ECHO_OFF;
	mesg[i] = &msg[i];

	retval = converse(pamh, ++i, mesg, &resp);
	if (prompt)
	{
	    _pam_overwrite(prompt);
	    _pam_drop(prompt);
	}
	if (retval != PAM_SUCCESS)
	{
	    if (resp != NULL)
		_pam_drop_reply(resp,i);
	    return ((retval == PAM_CONV_AGAIN)
		    ? PAM_INCOMPLETE:PAM_AUTHINFO_UNAVAIL);
	}

	/* we have a password so set AUTHTOK
	 */
	return pam_set_item(pamh, PAM_AUTHTOK, resp->resp);
}


/* PAM Authentication functions */

PAM_EXTERN int pam_sm_authenticate (pam_handle_t * pamh,
				    int flags,
				    int argc,
				    const char **argv)
{
	int retval, i;
	const char *user;
	char *passwd = NULL;
/*	MYSQL auth_sql_server;*/

#ifdef DEBUG
	D (("called."));
#endif

/* Parse arguments taken from pam_listfile.c */
	for (i = 0; i < argc; i++) {
		char *junk;
		char mybuf[256], myval[256];

		junk = (char *) malloc (strlen (argv[i]) + 1);
		if (junk == NULL) {
#ifdef DEBUG
			D (("returning PAM_BUF_ERR."));
			return PAM_BUF_ERR;
#endif
		}
		strcpy (junk, argv[i]);
		if ((strchr (junk, (int) '=') != NULL)) {
			strncpy (mybuf, strtok (junk, "="), 255);
			strncpy (myval, strtok (NULL, "="), 255);
			free (junk);
			if (!strcasecmp ("where", mybuf)) {
				strncpy (options.where, myval, 256);
				D (("where changed."));
#ifdef DEBUG
				syslog(LOG_ERR, "pam_oci8: where now is %s", options.where);
#endif
			} else if (!strcasecmp ("connectString", mybuf)) {
				strncpy (options.connectString, myval, 64);
				D (("connectString changed."));
			} else if (!strcasecmp ("table", mybuf)) {
				strncpy (options.table, myval, 16);
				D (("table changed."));
			} else if (!strcasecmp ("usercolumn", mybuf)) {
				strncpy (options.usercolumn, myval, 16);
				D (("usercolumn changed."));
			} else if (!strcasecmp ("passwdcolumn", mybuf)) {
				strncpy (options.passwdcolumn, myval, 16);
				D (("passwdcolumn changed."));
			}
		}
	}/* for loop */

	/* Get User */

	retval = pam_get_user (pamh, &user, NULL);
	if (retval != PAM_SUCCESS || user == NULL) {
		syslog (LOG_ERR, "pam_oci8: no user specified");
		return PAM_USER_UNKNOWN;
	}

	retval = pam_get_item(pamh, PAM_AUTHTOK, (const void **) &passwd);
	if ( passwd == NULL )
	{
		askForPassword(pamh);
	}
	retval = pam_get_item(pamh, PAM_AUTHTOK, (const void **)&passwd);

	if ( passwd == NULL )
		return PAM_AUTHINFO_UNAVAIL;

	if ((retval = db_connect ()) != PAM_SUCCESS) {
		db_close();
		D (("returning %i after db_connect.",retval));
		return retval;
	}
	if ((retval = db_checkpasswd (user, passwd)) != PAM_SUCCESS) {
		D (("returning %i after db_checkpasswd.",retval));
		db_close();
		return retval;
	}
#ifdef DEBUG
	D (("returning %i.",retval));
#endif
	db_close();
	return retval;

}/* pam_sm_authenticate */


/* --- account management functions --- */
PAM_EXTERN int pam_sm_acct_mgmt (pam_handle_t * pamh, int flags, int argc
				 ,const char **argv)
{
#ifdef DEBUG
	syslog (LOG_INFO, "pam_oci8: acct_mgmt called but not implemented. Dont panic though :)");
#endif
	return PAM_SUCCESS;
}

PAM_EXTERN
int pam_sm_setcred(pam_handle_t *pamh,int flags,int argc
		   ,const char **argv)
{
#ifdef DEBUG
     syslog(LOG_INFO, "pam_oci8: setcred called but not implemented.");
#endif
     return PAM_SUCCESS;
}

/* --- password management --- */

PAM_EXTERN
int pam_sm_chauthtok(pam_handle_t *pamh,int flags,int argc
		     ,const char **argv)
{
     syslog(LOG_INFO, "pam_oci8: chauthtok called but not implemented. Password NOT CHANGED!");
     return PAM_SUCCESS;
}

/* --- session management --- */

PAM_EXTERN
int pam_sm_open_session(pam_handle_t *pamh,int flags,int argc
			,const char **argv)
{
#ifdef DEBUG
     syslog(LOG_INFO, "pam_oci8: open_session called but not implemented.");
#endif
    return PAM_SUCCESS;
}

PAM_EXTERN
int pam_sm_close_session(pam_handle_t *pamh,int flags,int argc
			 ,const char **argv)
{
     syslog(LOG_INFO, "pam_oci8: close_session called but not implemented.");
     return PAM_SUCCESS;
}

/* end of module definition */

#ifdef PAM_STATIC

/* static module data */

struct pam_module _pam_permit_modstruct = {
    "pam_permit",
    pam_sm_authenticate,
    pam_sm_setcred,
    pam_sm_acct_mgmt,
    pam_sm_open_session,
    pam_sm_close_session,
    pam_sm_chauthtok
};

#endif
