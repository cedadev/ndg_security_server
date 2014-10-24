import java.net.URL;
import java.util.Arrays;

import javax.naming.InitialContext;
import javax.xml.rpc.holders.StringHolder;

import ndg.security.sessionMgr.SessionMgr;
import ndg.security.sessionMgr.SessionMgrService;
import ndg.security.sessionMgr.holders.StringArrayHolder;

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
/*
			//////////////////////////////////////////////////////////////////////////////////			
			// Call addUser operation
			//////////////////////////////////////////////////////////////////////////////////	
			
			// Setup input args			
			String addUserUsername = "testUserName";
			String addUserPassword = "";
			
			// Call the operation			
			System.out.println("Calling addUser ...");
			port.addUser(addUserUsername,addUserPassword);
			System.out.println("... done");			
*/			
			//////////////////////////////////////////////////////////////////////////////////			
			// Call connect operation
			//////////////////////////////////////////////////////////////////////////////////	
			
			// Setup input args			
			String connectUsername = "sstljakTestUser";
			String connectPassword = args[1];
			boolean createServerSess = true;
			boolean getCookie = false;
			
			// Setup output args			
			StringHolder cookieHolder = new StringHolder();
			StringHolder proxyCertHolder = new StringHolder();
			StringHolder proxyPriKeyHolder = new StringHolder();
			StringHolder userCertHolder = new StringHolder();
			
			// Call the operation			
			System.out.println("Calling connect ...");
			port.connect(connectUsername,
						connectPassword,
						createServerSess,
						getCookie,
						cookieHolder,
						proxyCertHolder,
						proxyPriKeyHolder,
						userCertHolder);
			System.out.println("... done");			
			
			// Print the output values			
			System.out.println("Service connect returned:");
			if (cookieHolder.value != null) 
				System.out.println("  Cookie = " + cookieHolder.value);
			
			if (proxyCertHolder.value != null) 
				System.out.println("  Proxy Cert = " + proxyCertHolder.value);
			
			if (proxyPriKeyHolder.value != null) 
				System.out.println("  Proxy Private key = " + proxyPriKeyHolder.value);
			
			if (userCertHolder.value != null) 
				System.out.println("  User Cert = " + userCertHolder.value);
			
			//////////////////////////////////////////////////////////////////////////////////			
			// Call getAttCert operation
			//////////////////////////////////////////////////////////////////////////////////			
			
			// Setup input args
			String sessID = "";
			String encrySessionMgrURI = "";
			String attAuthorityURI = "http://localhost:5000/AttributeAuthority";
			String attAuthorityCert = "";
			String reqRole = "";
			boolean mapFromTrustedHosts = true;
			boolean rtExtAttCertList = false;
			String[] extTrustedHostList = {};// = {"trustedHost1"};  
			String[] extAttCertList = {};// = {"abc"};
			
			// Setup output args
			StringHolder attCertHolder = new StringHolder();
			StringHolder msgHolder = new StringHolder();		
			StringArrayHolder extAttCertListOut = new StringArrayHolder();
			
			
			// Call the operation
			System.out.println("Calling getAttCert ...");
			port.getAttCert(userCertHolder.value,
							sessID,
							encrySessionMgrURI,
							attAuthorityURI,
							attAuthorityCert,
							reqRole,
							mapFromTrustedHosts,
							rtExtAttCertList,
							extAttCertList,
							extTrustedHostList,
							attCertHolder,
							msgHolder,
							extAttCertListOut);
			System.out.println("... done");			
			
			// Print the output values
			System.out.println("Service getAttCert returned:");
			if (attCertHolder.value != null) 
				System.out.println("  attCert = " + attCertHolder.value);
			
			if (msgHolder.value != null) 
				System.out.println("  Message = " + msgHolder.value);
			
			if (extAttCertListOut.value != null) {
				String[] returnedExtAttCertListOut = extAttCertListOut.value;
				for(int i = 0 ; i < returnedExtAttCertListOut.length ; i++) {
					System.out.println("  extAttCertArray[" + i + "] = " + returnedExtAttCertListOut[i]);
				}
			}
/*			
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
			
*/			//////////////////////////////////////////////////////////////////////////////////			
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