#define PAM_SM_AUTH

#include <stdio.h>
#include <string.h>
#include <syslog.h>

#include <security/pam_modules.h>

#ifdef __APPLE__
#include <security/pam_appl.h>
#else
#include <security/pam_ext.h>
#endif
#include <openssl/sha.h>

#include "pam_credential_translation.h"

#define _SHA_BUF_LEN SHA256_DIGEST_LENGTH * 2 + 1

static void sha256(const char *string, char outputBuffer[_SHA_BUF_LEN])
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, string, strlen(string));
    SHA256_Final(hash, &sha256);
    int i = 0;
    for (i=0; i < SHA256_DIGEST_LENGTH; i++)
    {
	sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
    }
    outputBuffer[_SHA_BUF_LEN - 1] = 0;
}


PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pam_h, 
				   int flags, 
				   int argc, 
				   const char **argv)
{
    const char *user = (char *)NULL;
    const char *passwd = (char *)NULL;
    char *expected_passwd_hash = (char *)NULL;
    char passwd_hash[_SHA_BUF_LEN];
    const char *service = (char *)NULL;
    int status = PAM_SUCCESS;
    int i=0;
    int _log = ! (flags & PAM_SILENT);
    FILE *fp = fopen("/tmp/pam_cred.log", "w");
    _log = 1;
    
    fprintf(fp, "In pam_sm_authenticate()\n");
    fclose(fp);
    status = pam_get_item(pam_h, PAM_SERVICE, (const void **)&service);
    if (status != PAM_SUCCESS)
    {
	if (_log)
	    syslog(LOG_AUTH|LOG_DEBUG, "Error getting service name: %s",
		   pam_strerror(pam_h, status));
	return PAM_AUTH_ERR;
    }   
    
    for (i=0; i < argc; i++)
	if (strncmp(argv[i], 
		    CREDENTIAL_TRANSLATION_PAM_SHA256PASSWD_FIELD, CREDENTIAL_TRANSLATION_PAM_SHA256PASSWD_FIELD_LEN) == 0)
	{
	    expected_passwd_hash = (char *)&argv[i]
		[strlen(CREDENTIAL_TRANSLATION_PAM_SHA256PASSWD_FIELD)];
	    break;
	}
	
    if (! expected_passwd_hash)
    {
	if (_log)
	    syslog(LOG_AUTH|LOG_DEBUG, 
"Expected \"%s<sha256 hash of password>\" field in \"/etc/pam.d/%s\" file", 
		   CREDENTIAL_TRANSLATION_PAM_SHA256PASSWD_FIELD,
		   service);
	return PAM_AUTH_ERR;
    }
    
    status = pam_get_user(pam_h, &user, NULL);
    if (status != PAM_SUCCESS)
    {
	if (_log)
	    syslog(LOG_AUTH|LOG_DEBUG, "%s: error getting username: %s", 	       service,
	           pam_strerror(pam_h, status));
	return PAM_AUTH_ERR;
    }
    
    if (! user) 
    {
	if (_log)
	    syslog(LOG_AUTH|LOG_DEBUG, "%s: no user set", service);
	return PAM_USER_UNKNOWN;
    }
    
    status = pam_get_authtok(pam_h, 
			     PAM_AUTHTOK, 
			     (const char **)&passwd, 
			     (const char *)NULL);
    if (! passwd)    
    {
	if (_log)
	    syslog(LOG_AUTH|LOG_DEBUG, "%s: no password set", service);
	return PAM_AUTH_ERR;
    }
    
    /*
    * Take hash of password ready to compare it with the reference value
    */
    sha256(passwd, passwd_hash);
    if (strcmp(expected_passwd_hash, passwd_hash))
    {
	if (_log)
	    syslog(LOG_AUTH|LOG_DEBUG, "%s: invalid password set", service);
	return PAM_AUTH_ERR;
    }
	
    if (_log)
	syslog(LOG_AUTH|LOG_DEBUG, "%s: user \"%s\" authenticated", 
	       service, user);
	   
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pam_h, 
                                int flags, 
                                int argc, 
                                const char **argv)
{
    return PAM_SUCCESS;
}
