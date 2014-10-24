#ifndef _PAM_CREDENTIAL_TRANSLATION_H
#define _PAM_CREDENTIAL_TRANSLATION_H
/*
* MashMyData Project
*
* Description: Header file for PAM service module for use with MyProxyCA 
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
* PAM Identifier for this Service
*/
#define CREDENTIAL_TRANSLATION_PAM_ID "myproxy-credential-translation"

/*
* Field scanned from PAM config file.  The content to the right of the 
* of this entry up to the next whitespace is read as the SHA256 Hash of the 
* password for authentication:
*
* pam_credential_translation.so sha256passwd=<SHA256 hash of password>
*/
#define CREDENTIAL_TRANSLATION_PAM_SHA256PASSWD_FIELD "sha256passwd="
#define CREDENTIAL_TRANSLATION_PAM_SHA256PASSWD_FIELD_LEN 13
#endif
