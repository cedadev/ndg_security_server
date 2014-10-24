/*
* MashMyData Project
*
* Description: test harness for PAM service module for use with MyProxyCA 
* 	       Credential Translation Service
*
* Author: P J Kershaw
*
* Date: 24/11/10
*
* Copyright: STFC 2010
*
* License: BSD
*
* Version: $Id$
*/

/*
* _conv function is adapted from MyProxy auth_pam.c, itself adapted from...
*/
/* COPYRIGHT
 * Copyright (c) 2000 Fabian Knittel.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain any existing copyright
 *    notice, and this entire permission notice in its entirety,
 *    including the disclaimer of warranties.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 2. Redistributions in binary form must reproduce all prior and current
 *    copyright notices, this list of conditions, and the following
 *    disclaimer in the documentation and/or other materials provided
 *    with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR(S) BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 * TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 * END COPYRIGHT */

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#include <security/pam_appl.h>

#include "pam_credential_translation.h"

typedef struct {
    const char *login;                  /* plaintext authenticator */
    const char *password;               /* plaintext password */
    pam_handle_t *pamh;                 /* pointer to PAM handle */
} pam_appdata;

/*
* Freely adapted from MyProxy PAM module to ensure compatibility
* See Copyright notice above
*/
static int _conv(int num_msg,
                 const struct pam_message **msg,
		 struct pam_response **resp,
                 void *appdata_ptr)
{
    int i=0;
    int rc;
    const char *login_prompt;
    pam_appdata *_appdata = (pam_appdata *)appdata_ptr;
    struct pam_response *_resp = calloc(sizeof(struct pam_response), num_msg);
    if (! _resp)
	return PAM_BUF_ERR;
    
    for (i = 0; i < num_msg; i++)
	switch (msg[i]->msg_style) 
	{
	    case PAM_PROMPT_ECHO_OFF:       /* password */
		_resp[i].resp = strdup(_appdata->password);
		if (_resp[i].resp == NULL) {
		    syslog(LOG_AUTH|LOG_DEBUG, "_conv: strdup failed");
		    goto ret_error;
		}
		_resp[i].resp_retcode = PAM_SUCCESS;
		break;
		
	    case PAM_PROMPT_ECHO_ON:        /* username? */
		/* Recheck setting each time, as it might have been changed
		in the mean-while. */
		rc = pam_get_item(_appdata->pamh, PAM_USER_PROMPT,
				  (void *) &login_prompt);
		if (rc != PAM_SUCCESS) 
		{
		    syslog(LOG_AUTH|LOG_DEBUG, 
			   "_pam_conv: unable to read login prompt string: %s",
			pam_strerror(_appdata->pamh, rc));
			goto ret_error;
		}
		    
		if (strcmp(msg[i]->msg, login_prompt) == 0) 
		{
		    _resp[i].resp = strdup(_appdata->login);
		    _resp[i].resp_retcode = PAM_SUCCESS;
		} 
		else 
		{                    /* ignore */
		    syslog(LOG_AUTH|LOG_DEBUG, "_conv: unknown prompt string: %s", 
			   msg[i]->msg);
		    _resp[i].resp = NULL;
		    _resp[i].resp_retcode = PAM_SUCCESS;
		}
		break;
		
	    case PAM_ERROR_MSG:             /* ignore */
	    case PAM_TEXT_INFO:             /* ignore */
		syslog(LOG_AUTH|LOG_DEBUG, "PAM: %s", msg[i]->msg);
		_resp[i].resp = NULL;
		_resp[i].resp_retcode = PAM_SUCCESS;
		break;
		
	    default:                        /* error */
		goto ret_error;
	}
    *resp = _resp;
    return PAM_SUCCESS;
	
ret_error:
    /*
    * Free response structure. Don't free _resp[i], as that
    * isn't initialised yet.
    */
    {
	int y;
	
	for (y = 0; y < i; y++)
	    if (_resp[y].resp != NULL)
		free(_resp[y].resp);
	    free(_resp);
    }
    return PAM_CONV_ERR;
}

/*
* Set to PAM_SILENT to stop log messages
*/
/*#define _PAM_SM_AUTHENTICATE_FLAGS PAM_SILENT*/
#define _PAM_SM_AUTHENTICATE_FLAGS 0x0


int main(int argc, char *argv[]) 
{
    pam_handle_t	*pam_h = (pam_handle_t *)NULL;
    int			flags = _PAM_SM_AUTHENTICATE_FLAGS;
    int			status = PAM_AUTH_ERR;
    const char *service_name = CREDENTIAL_TRANSLATION_PAM_ID;
    const char *user = (char *)NULL;
    char *passwd = (char *)NULL;
    pam_appdata _appdata;
    struct pam_conv pam_conversation;
    
    if (argc < 2)
    {
	fprintf(stderr, "Usage %s <username> <password>\n", argv[0]);
	exit(0);
    }
    user = argv[1];
    passwd = argv[2];
	
    _appdata.login = user;
    _appdata.password = passwd;
    _appdata.pamh = NULL;
    pam_conversation.conv = _conv;
    pam_conversation.appdata_ptr = &_appdata;
    
    status = pam_start(service_name, user, &pam_conversation, &pam_h);
    if (status != PAM_SUCCESS)
    {
	fprintf(stderr, "pam_start returned an error: %s\n", 
		pam_strerror(pam_h, status));
	exit(1);
    }
    
    status = pam_authenticate(pam_h, flags);
    if (status != PAM_SUCCESS)
    {
	fprintf(stderr, "pam_authenticate returned an error: %s\n", 
		pam_strerror(pam_h, status));
	exit(EXIT_FAILURE);
    }
    
    status = pam_end(pam_h, status);
    if (status != PAM_SUCCESS)
    {
	fprintf(stderr, "pam_end returned an error: %s\n", 
		pam_strerror(pam_h, status));
		exit(1);
    }
    
    fprintf(stderr, "Authentication succeeded.\n");
    exit(EXIT_SUCCESS);
}
