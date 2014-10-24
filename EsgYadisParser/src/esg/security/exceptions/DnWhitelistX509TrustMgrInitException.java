/**
 * Initialisation exception for Certificate DN Whitelist based X.509 Trust 
 * Manager
 * 
 * Earth System Grid/CMIP5
 *
 * Date: 09/08/10
 * 
 * Copyright: (C) 2010 Science and Technology Facilities Council
 * 
 * Licence: BSD
 * 
 * $Id$
 * 
 * @author pjkersha
 * @version $Revision$
 */
package esg.security.exceptions;


public class DnWhitelistX509TrustMgrInitException extends Exception {
	public DnWhitelistX509TrustMgrInitException(String message) {
		super(message);
	}
	
	public DnWhitelistX509TrustMgrInitException(String message, Exception e) {
		super(message, e);
	}
}
