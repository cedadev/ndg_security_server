import java.net.URL;
import java.util.Arrays;

import javax.naming.InitialContext;
import javax.xml.rpc.holders.StringHolder;

import ndg.security.SessionMgr;
import ndg.security.SessionMgrService;
import ndg.security.holders.StringArrayHolder;

public class Main {
	public static void main(String[] args) {
		try {
			//////////////////////////////////////////////////////////////////////////////////			
			// Setup Web service call basics
			//////////////////////////////////////////////////////////////////////////////////			
			System.out.println("Starting");
			SessionMgr port = null;
			InitialContext ctx = new InitialContext();
			String targetEndpoint = args[0];
			Object serviceLookup = ctx.lookup("java:comp/env/service/SessionMgrService");
			port = ((SessionMgrService) serviceLookup).getSessionMgr(new URL(targetEndpoint));
			
			//////////////////////////////////////////////////////////////////////////////////
			// Call getX509Cert operation
			//////////////////////////////////////////////////////////////////////////////////
			System.out.println("Calling getX509Cert ...");
			String X509CertResult = port.getX509Cert();
			System.out.println("... done");			
			System.out.println("Service getX509Cert returned: " + X509CertResult);

			//////////////////////////////////////////////////////////////////////////////////			
			// Call addUser operation
			//////////////////////////////////////////////////////////////////////////////////	
			
			// Setup input args			
			String addUserUsername = "testUserName";
			String addUserPassword = "testPassword";
			
			// Call the operation			
			System.out.println("Calling addUser ...");
			port.addUser(addUserUsername,addUserPassword);
			System.out.println("... done");			
			
			//////////////////////////////////////////////////////////////////////////////////			
			// Call connect operation
			//////////////////////////////////////////////////////////////////////////////////	
			
			// Setup input args			
			String connectUsername = "testUserName";
			String connectPassword = "testPassword";
			boolean createServerSess = true;
			boolean getCookie = false;
			
			// Setup output args			
			StringHolder connectCookieHolder = new StringHolder();
			StringHolder connectProxyCertHolder = new StringHolder();
			
			// Call the operation			
			System.out.println("Calling connect ...");
			port.connect(connectUsername,connectPassword,createServerSess,getCookie,connectCookieHolder,connectProxyCertHolder);
			System.out.println("... done");			
			
			// Print the output values			
			System.out.println("Service connect returned:");
			if (connectCookieHolder.value != null) System.out.println("  connectCookie = " + connectCookieHolder.value);			
			if (connectProxyCertHolder.value != null) System.out.println("  connectProxyCert = " + connectProxyCertHolder.value);
			
			//////////////////////////////////////////////////////////////////////////////////			
			// Call reqAuthorisation operation
			//////////////////////////////////////////////////////////////////////////////////			
			
			// Setup input args
			String sessID = "";
			String encrySessionMgrURI = "";
			String attAuthroityURI = "";
			String attAuthroityCert = "";
			String reqRole = "";
			boolean mapFromTrustedHosts = true;
			boolean rtExtAttCertList = false;
			String[] extTrustedHostList = {"trustedHost1"};  
			String[] extAttCertList = {"abc"};
			
			// Setup output args
			StringHolder attCertHolder = new StringHolder();
			StringHolder statusCodeHolder = new StringHolder();		
			StringArrayHolder extAttCertArrayHolder = new StringArrayHolder();
			
			// Call the operation
			System.out.println("Calling reqAuthorisation ...");
			port.reqAuthorisation(connectProxyCertHolder.value,sessID,encrySessionMgrURI,attAuthroityURI,attAuthroityCert,reqRole,mapFromTrustedHosts,rtExtAttCertList,extAttCertList,extTrustedHostList,attCertHolder,statusCodeHolder,extAttCertArrayHolder);
			System.out.println("... done");			
			
			// Print the output values
			System.out.println("Service reqAuthorisation returned:");
			if (attCertHolder.value != null) System.out.println("  attCert = " + attCertHolder.value);
			if (statusCodeHolder.value != null) System.out.println("  statusCode = " + statusCodeHolder.value);
			if (extAttCertArrayHolder.value != null) {
				String[] returnedextAttCertArrayHolder = extAttCertArrayHolder.value;
				for(int i = 0 ; i < returnedextAttCertArrayHolder.length ; i++) {
					System.out.println("  extAttCertArray[" + i + "] = " + returnedextAttCertArrayHolder[i]);
				}
			}
			
			//////////////////////////////////////////////////////////////////////////////////			
			// Call disconnect operation
			//////////////////////////////////////////////////////////////////////////////////	
			
			// Setup input args			
			String disconnectProxyCert = "";			
			String disconnectSessID = "";
			String disconnectEncrySessionMgrURI = "";;
			
			// Call the operation			
			System.out.println("Calling disconnect ...");
			port.disconnect(disconnectProxyCert,disconnectSessID,disconnectEncrySessionMgrURI);	
			System.out.println("... done");
			
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