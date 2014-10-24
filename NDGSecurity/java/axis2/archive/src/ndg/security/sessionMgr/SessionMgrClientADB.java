package ndg.security.sessionMgr;

import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.rmi.RemoteException;
import java.util.Properties;

import ndg.security.sessionMgr.SessionMgrServiceStub.Connect;
import ndg.security.sessionMgr.SessionMgrServiceStub.ConnectResponse;
import ndg.security.sessionMgr.SessionMgrServiceStub.Disconnect;
import ndg.security.sessionMgr.SessionMgrServiceStub.DisconnectResponse;
import ndg.security.sessionMgr.SessionMgrServiceStub.GetAttCert;
import ndg.security.sessionMgr.SessionMgrServiceStub.GetAttCertResponse;
import ndg.security.sessionMgr.SessionMgrServiceStub.GetSessionStatus;
import ndg.security.sessionMgr.SessionMgrServiceStub.GetSessionStatusResponse;
import ndg.security.sessionMgr.SessionMgrServiceStub.GetX509Cert;
import ndg.security.sessionMgr.SessionMgrServiceStub.GetX509CertResponse;

import org.apache.axis2.AxisFault;
import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.context.ConfigurationContextFactory;


/**
 * A java client using Axis Data Bindings to access the SessionMgrClient service
 * 
 * @author Calum Byrom, Tessella
 * @date 05/08/08
 */
public class SessionMgrClientADB 
{
	private static final String LINE_BREAK = "-------------------------------";
	private static final String PROPERTIES_FILE = "test.properties";
	private static final String USER_ID = null;
	private static final String PW = null;
	private SessionMgrServiceStub service = null;
	
	private Properties properties = null;
	private String VALID_USER_ID;
	private String VALID_PW;
	private String VALID_USER_DN;
	private String VALID_ATT_AUTH_URI;
	
    public static void main(java.lang.String args[])
    {
        try
        {
    		SessionMgrClientADB client = new SessionMgrClientADB();
    		
    		client.loadProperties(PROPERTIES_FILE);

        	client.configureServiceConnection(
        			client.properties.getProperty("confDir"), 
    				client.properties.getProperty("endpoint"));
        	
        	client.runServices();
        }
       	catch(Exception e)
        {
       		System.out.println("Back to the drawing board...:");
            e.printStackTrace();
        }
    }

    private void loadProperties(String propertiesFile) throws IOException 
    {
		this.properties = new Properties();
		FileReader reader = new FileReader(getClass().getResource(propertiesFile).getFile());
		this.properties.load(reader);
		VALID_USER_ID = this.properties.getProperty("userID");
		VALID_PW = this.properties.getProperty("pw");
		VALID_USER_DN = this.properties.getProperty("userDN");
		VALID_ATT_AUTH_URI = this.properties.getProperty("attAuthURI");
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
    									configDir + "/conf/axis2-sessionMgr.xml");
    	
    	this.service = new SessionMgrServiceStub(ctx, endpointURI);
	}

	private void runServices() throws RemoteException 
	{
		this.callGetX509Service();
		ConnectResponse res = this.callConnectService(VALID_USER_ID, VALID_PW, true);
    	this.callGetSessionStatusService(null, res.localSessID);
    	this.callGetAttCertService(null, VALID_ATT_AUTH_URI, null, null, false, null, 
				true, res.localSessID, null);
    	this.callDisconnectService(res.localSessID, null);
	}

	public ConnectResponse callConnectService(String userName, String pw, boolean createServerSession) throws RemoteException 
	{
		System.out.println(LINE_BREAK);
		Connect connect = new Connect();
		if (userName != null)
			connect.setUsername(userName);
		if (pw != null)
			connect.setPassphrase(pw);
		if (createServerSession)
			connect.setCreateServerSess(createServerSession);
			
		ConnectResponse res = this.service.connect(connect);
		System.out.println("Connect service returned successfully - ");
		System.out.println("User cert: " + res.localUserCert);
		System.out.println("User key: " + res.localUserPriKey);
		System.out.println("Issuing cert: " + res.localIssuingCert);
		System.out.println("Session ID: " + res.localSessID);
		
		return res;
	}
	
	public GetSessionStatusResponse callGetSessionStatusService(String userDN, String sessionID) throws RemoteException
	{
		GetSessionStatus getSessionStatus = new GetSessionStatus();
		if (userDN != null)
			getSessionStatus.setUserDN(userDN);
		if (sessionID != null)
			getSessionStatus.setSessID(sessionID);
		GetSessionStatusResponse res = this.service.getSessionStatus(getSessionStatus);
		System.out.println("GetSessionStatus service returned successfully - ");
		System.out.println("Is alive: " + res.localIsAlive);
	

		return res;
	}
	

	public DisconnectResponse callDisconnectService(String sessionID, String userCert) throws RemoteException
	{
		Disconnect disconnect = new Disconnect();
		if (sessionID != null)
			disconnect.setSessID(sessionID);
	
		if (userCert != null)
			disconnect.setUserCert(userCert);
		
		DisconnectResponse res = this.service.disconnect(disconnect);
		System.out.println("Disconnect service returned successfully.");
		return res;
	}
	
	
	public GetAttCertResponse callGetAttCertService(String attAuthorityCert,
			String attAuthorityURI, String[] extAttCerts,
			String[] extTrustedHosts, boolean mapFromTrustedHosts,
			String requiredRole, boolean returnExtAttCertList,
			String sessionID, String userCert) throws RemoteException
	{
		GetAttCert getAttCert = new GetAttCert();
		if (attAuthorityCert != null)
			getAttCert.setAttAuthorityCert(attAuthorityCert);
		
		if (attAuthorityURI != null)
			getAttCert.setAttAuthorityURI(attAuthorityURI);
		
		if (extAttCerts != null && extAttCerts.length > 0)
			getAttCert.setExtAttCert(extAttCerts);
		
		if (extTrustedHosts != null && extTrustedHosts.length > 0)
			getAttCert.setExtTrustedHost(extTrustedHosts);
		
		getAttCert.setMapFromTrustedHosts(mapFromTrustedHosts);
		
		if (requiredRole != null)
			getAttCert.setReqRole(requiredRole);
		
		getAttCert.setRtnExtAttCertList(returnExtAttCertList);
		
		if (sessionID != null)
			getAttCert.setSessID(sessionID);
		
		if (userCert != null)
			getAttCert.setUserCert(userCert);
		
		GetAttCertResponse res = this.service.getAttCert(getAttCert);
		System.out.println("GetAttCert service returned successfully - result:");
		System.out.println("Cert: " + res.localAttCert);
		System.out.println("Message: " + res.localMsg);
		
		if (res.localExtAttCertOut != null)
		{
			System.out.println("Got extAttCerts:");
			for (int i = 0; i < res.localExtAttCertOut.length; i++)
			{
				System.out.println(res.localExtAttCertOut[i]);	
			}
		}
		return res;
	}
	

	public GetX509CertResponse callGetX509Service() throws RemoteException 
	{
		System.out.println(LINE_BREAK);
		GetX509Cert getX509Cert = new GetX509Cert(); 
		GetX509CertResponse res = this.service.getX509Cert(getX509Cert);
		System.out.println("GetX509 service returned successfully - result:");
		System.out.println("Cert: " + res.localX509Cert);
		return res;
	}

}
