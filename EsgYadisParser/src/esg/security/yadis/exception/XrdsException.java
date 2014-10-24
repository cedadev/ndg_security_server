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
package esg.security.yadis.exception;

public class XrdsException extends Exception {

	public XrdsException(String message, Exception e) {
		super(message, e);
	}

	public XrdsException(String message) {
		super(message);
	}

}
