package ndg.security.attAuthority;

import java.rmi.RemoteException;

import ndg.security.attAuthority.AttAuthorityServiceStub.GetAllHostsInfo;
import ndg.security.attAuthority.AttAuthorityServiceStub.GetAllHostsInfoResponse;
import ndg.security.attAuthority.AttAuthorityServiceStub.GetAttCert;
import ndg.security.attAuthority.AttAuthorityServiceStub.GetAttCertResponse;
import ndg.security.attAuthority.AttAuthorityServiceStub.GetHostInfo;
import ndg.security.attAuthority.AttAuthorityServiceStub.GetHostInfoResponse;
import ndg.security.attAuthority.AttAuthorityServiceStub.GetTrustedHostInfo;
import ndg.security.attAuthority.AttAuthorityServiceStub.GetTrustedHostInfoResponse;
import ndg.security.attAuthority.AttAuthorityServiceStub.GetX509Cert;
import ndg.security.attAuthority.AttAuthorityServiceStub.GetX509CertResponse;

import org.apache.axis2.AxisFault;
import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.context.ConfigurationContextFactory;


/**
 * A java client using Axis Data Bindings to access the AttAuthority service
 * 
 * @author Calum Byrom, Tessella
 * @date 05/08/08
 */
public class AttAuthorityClientADB 
{
	private static final String LINE_BREAK = "-------------------------------";
	private AttAuthorityServiceStub service = null;
	
    public static void main(java.lang.String args[])
    {
        try
        {
        	AttAuthorityClientADB client = new AttAuthorityClientADB();

        	client.configureServiceConnection("/home/users/cbyrom/eclipseWorkspace/TI12-security-java/axis2",
        			"http://localhost:4900/AttributeAuthority");
        	
        	client.runServices();
        }
       	catch(Exception e)
        {
       		System.out.println("Back to the drawing board...:");
            e.printStackTrace();
        }
    }

    /**
     * Set up the connection from the client to the service - via the generated stub class
     * @param configDir - axis2 conf directory, with axis2.xml file to set up the connection
     * @param endpointURI - endpoint of service
     * @throws AxisFault 
     */
	public void configureServiceConnection(String configDir, String endpointURI) throws AxisFault 
	{
    	// set up the connection to the client
    	ConfigurationContext ctx = 
    		ConfigurationContextFactory.
    		createConfigurationContextFromFileSystem(configDir, 
    									configDir + "/conf/axis2.xml");
    	
    	this.service = new AttAuthorityServiceStub(ctx, endpointURI);
	}

	private void runServices() throws RemoteException 
	{
    	this.callGetX509Service();
    	
    	this.callGetAttCertService(null, null, null);
    	
    	this.callGetHostInfo();
    	
    	this.callGetTrustedHostInfo(null);
    	
    	this.callGetTrustedHostInfo("postgrad");
    	
    	this.callGetAllHostsInfo();
	}

	public GetX509CertResponse callGetX509Service() throws RemoteException 
	{
		System.out.println(LINE_BREAK);
		GetX509Cert getX509Cert = new GetX509Cert(); 
		GetX509CertResponse res = this.service.getX509Cert(getX509Cert);
		System.out.println("Service returned successfully - result:");
		System.out.println(res.localX509Cert);
		return res;
	}

	public GetAttCertResponse callGetAttCertService(String attCert, 
			String cert, String userID) throws RemoteException 
	{
		System.out.println(LINE_BREAK);
		GetAttCert getAttCert = new GetAttCert();
		if (attCert != null)
			getAttCert.setUserAttCert(attCert);
		if (cert != null)
			getAttCert.setUserCert(cert);
		if (userID != null)
			getAttCert.setUserId(userID);
		
		GetAttCertResponse res = this.service.getAttCert(getAttCert);
		System.out.println("Service returned successfully - result:");
		System.out.println("Cert: " + res.localAttCert);
		System.out.println("Message: " + res.localMsg);
		return res;
	}

	public GetHostInfoResponse callGetHostInfo() throws RemoteException 
	{
		System.out.println(LINE_BREAK);
		GetHostInfo getHostInfo = new GetHostInfo(); 
		GetHostInfoResponse res = this.service.getHostInfo(getHostInfo);
		System.out.println("Service returned successfully - result:");
		System.out.println("DN:" + res.localAaDN);
		System.out.println("URI:" + res.localAaURI);
		System.out.println("Hostname:" + res.localHostname);
		System.out.println("LoginRequestServerDN:" + res.localLoginRequestServerDN);
		System.out.println("LoginServerDN:" + res.localLoginServerDN);
		System.out.println("LoginURI:" + res.localLoginURI);
		return res;
	}

	public GetTrustedHostInfoResponse callGetTrustedHostInfo(String role) throws RemoteException 
	{
		System.out.println(LINE_BREAK);
		System.out.println("Getting trusted info for role: " + role);
		GetTrustedHostInfo getTrustedHostInfo = new GetTrustedHostInfo();
		getTrustedHostInfo.setRole(role);
		GetTrustedHostInfoResponse res = this.service.getTrustedHostInfo(getTrustedHostInfo);
		System.out.println("Service returned successfully - result:");
		AttAuthorityServiceStub.HostInfo[] hostInfo = res.localTrustedHosts;
		for (int i = 0; i < hostInfo.length; i++)
		{
			System.out.println("DN:" + hostInfo[i].localAaDN);
			System.out.println("URI:" + hostInfo[i].localAaURI);
			System.out.println("Hostname:" + hostInfo[i].localHostname);
			System.out.println("LoginRequestServerDN:" + hostInfo[i].localLoginRequestServerDN);
			System.out.println("LoginServerDN:" + hostInfo[i].localLoginServerDN);
			System.out.println("LoginURI:" + hostInfo[i].localLoginURI);
			String[] roles = hostInfo[i].localRoleList;
			System.out.println("Available roles:");
			for (int j = 0; j < roles.length; j++)
			{
				System.out.println(roles[j]);
			}
		}
		return res;
	}

	public GetAllHostsInfoResponse callGetAllHostsInfo() throws RemoteException 
	{
		System.out.println(LINE_BREAK);
		GetAllHostsInfo getAllHostsInfo = new GetAllHostsInfo();
		GetAllHostsInfoResponse res = this.service.getAllHostsInfo(getAllHostsInfo);
		System.out.println("Service returned successfully - result:");
		AttAuthorityServiceStub.HostInfo[] hostInfo = res.localHosts;
		for (int i = 0; i < hostInfo.length; i++)
		{
			System.out.println("DN:" + hostInfo[i].localAaDN);
			System.out.println("URI:" + hostInfo[i].localAaURI);
			System.out.println("Hostname:" + hostInfo[i].localHostname);
			System.out.println("LoginRequestServerDN:" + hostInfo[i].localLoginRequestServerDN);
			System.out.println("LoginServerDN:" + hostInfo[i].localLoginServerDN);
			System.out.println("LoginURI:" + hostInfo[i].localLoginURI);
			String[] roles = hostInfo[i].localRoleList;
			if (roles != null)
			{
				System.out.println("Available roles:");
				for (int j = 0; j < roles.length; j++)
				{
					System.out.println(roles[j]);
				}
			}
			else
			{
				System.out.println("No available roles for host.");
			}
			System.out.println(LINE_BREAK);
		}
		return res;
	}
}
