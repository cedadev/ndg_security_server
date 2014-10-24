/**
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
package esg.security.openid2emailresolution.exceptions;

public class OpenId2EmailAddrResolutionException extends Exception {

	public OpenId2EmailAddrResolutionException(String message, Exception e) {
		super(message, e);
	}

	public OpenId2EmailAddrResolutionException(String message) {
		super(message);
	}
}
