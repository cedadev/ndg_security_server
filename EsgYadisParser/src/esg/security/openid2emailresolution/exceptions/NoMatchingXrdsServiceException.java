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

public class NoMatchingXrdsServiceException extends OpenId2EmailAddrResolutionException {

	public NoMatchingXrdsServiceException(String message, Exception e) {
		super(message, e);
	}

	public NoMatchingXrdsServiceException(String message) {
		super(message);
	}

}
