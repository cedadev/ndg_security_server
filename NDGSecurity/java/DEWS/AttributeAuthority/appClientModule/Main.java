import java.net.URL;

import javax.naming.InitialContext;
import java.net.URL;
import java.util.Arrays;

import javax.naming.InitialContext;
import javax.xml.rpc.holders.StringHolder;

import ndg.security.attAuthority.AttAuthority;
import ndg.security.attAuthority.AttAuthorityService;


public class Main {
	public static void main(String[] args) {
		try {
			//////////////////////////////////////////////////////////////////////////////////			
			// Setup Web service call basics
			//////////////////////////////////////////////////////////////////////////////////			
			System.out.println("Starting");
			AttAuthority port = null;
			InitialContext ctx = new InitialContext();
			String targetEndpoint = args[0];
			Object serviceLookup = ctx.lookup("java:comp/env/service/AttAuthorityService");
			port = ((AttAuthorityService) serviceLookup).getAttAuthority(new URL(targetEndpoint));
			
			//////////////////////////////////////////////////////////////////////////////////
			// Call getX509Cert operation
			//////////////////////////////////////////////////////////////////////////////////
			System.out.println("Calling getX509Cert ...");
			String X509CertResult = port.getX509Cert();
			System.out.println("... done");			
			System.out.println("Service getX509Cert returned: " + X509CertResult);

			
			//////////////////////////////////////////////////////////////////////////////////
			// Call getAttCert operation
			//////////////////////////////////////////////////////////////////////////////////
			System.out.println("Calling getAttCert ...");
			
			// Custom for DEWS: include user identifier
			String userId =  "dewsPortalUser";
			
			// Ignore this arg
			String userCert = "";
			
			// Input Attribute Certificate to be used to get a mapped Attribute Certificate.
			// Leave blank if making a request to an Attribute Authority where the user is 
			// registered
			String userAttCert = "";
			
			// Attribute Certificate to be returned
			StringHolder attCertHolder = new StringHolder();
			
			// Contains info if access is denied
			StringHolder msgHolder = new StringHolder();
			
			port.getAttCert(userId, userCert, userAttCert, attCertHolder, msgHolder);
			System.out.println("... done");			
			System.out.println("Service getAttCert returned: ");
			if (attCertHolder.value != null) 
				System.out.println("  Attribute Certificate = " + attCertHolder.value);
			
			if (msgHolder.value != null) 
				System.out.println("  Access Error Message = " + msgHolder.value);
			
			//////////////////////////////////////////////////////////////////////////////////			
			// End Web service call
			//////////////////////////////////////////////////////////////////////////////////			
			System.out.println("Ending");
			
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/* (non-Java-doc)
	 * @see java.lang.Object#Object()
	 */
	public Main() {
		super();
	}

}