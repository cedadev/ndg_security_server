package ndg.security.sessionMgr;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.rmi.RemoteException;
import java.util.Properties;

import junit.framework.TestCase;
import ndg.security.sessionMgr.SessionMgrServiceStub.ConnectResponse;
import ndg.security.sessionMgr.SessionMgrServiceStub.DisconnectResponse;
import ndg.security.sessionMgr.SessionMgrServiceStub.GetAttCertResponse;
import ndg.security.sessionMgr.SessionMgrServiceStub.GetSessionStatusResponse;
import ndg.security.sessionMgr.SessionMgrServiceStub.GetX509CertResponse;

import org.apache.axis2.AxisFault;

/**
 * Test suite to exercise the SessionMgrClientADB java client
 * 
 * @author Calum Byrom, Tessella
 * @date 07/08/08
 */
public class SessionMgrClientADBTest extends TestCase 
{
	private static final String PROPERTIES_FILE = "test.properties";
	private static final String START_CERTIFICATE_STRING = "-----BEGIN CERTIFICATE-----";
	private static final String END_CERTIFICATE_STRING = "-----END CERTIFICATE-----";
	private static String VALID_PW = null;
	private static String VALID_USER_ID = null;
	private static String VALID_ATT_AUTH_URI = null;
	private static final String VALID_ROLE = "academic";
	private static String VALID_USER_DN = null;
	private static final String INVALID_ATT_AUTH_CERT = "blah";
	private static final String INVALID_ATT_AUTH_URI = "blah";
	private static final String[] INVALID_EXT_ATT_CERTS = {"blah1", "blah2"};
	private static final String[] INVALID_EXT_TRUSTED_HOSTS = {"blah1", "blah2"};
	private static final String INVALID_ROLE = "lumberjack";
	private static final String INVALID_USER_CERT = "blah";
	private static final String STANDARD_AXIS_FAULT = "Processing Failure";

	private Properties properties = null;
	
	public SessionMgrClientADBTest() throws IOException 
	{
		this.properties = new Properties();
		FileReader reader = new FileReader(getClass().getResource(PROPERTIES_FILE).getFile());
		this.properties.load(reader);
		VALID_USER_ID = this.properties.getProperty("userID");
		VALID_PW = this.properties.getProperty("pw");
		VALID_USER_DN = this.properties.getProperty("userDN");
		VALID_ATT_AUTH_URI = this.properties.getProperty("attAuthURI");
	}

	SessionMgrClientADB client = null;
	
	@Override
	protected void setUp() throws Exception 
	{
		client = new SessionMgrClientADB();
		client.configureServiceConnection(this.properties.getProperty("confDir"), 
				this.properties.getProperty("endpoint"));
	}
	
	@Override
	protected void tearDown() throws Exception 
	{
		client = null;
	}
	
	public void testGetX509Cert()
	{
		try 
		{
			GetX509CertResponse res = client.callGetX509Service();
			assertNotNull(res.localX509Cert);
			
			// now check this file is the same as used by the server
			FileReader file = new FileReader(this.properties.getProperty("certFile"));
			BufferedReader reader = new BufferedReader(file);
			
			StringBuffer sb = new StringBuffer();
			String nextLine = null;
			try 
			{
				boolean foundCert = false;
				while ((nextLine = reader.readLine()) != null) 
				{
					if (nextLine.equals(END_CERTIFICATE_STRING))
					{
						break;
					} else if (foundCert)
					{
						sb.append(nextLine);
					}
					else if (nextLine.equals(START_CERTIFICATE_STRING))
					{
						foundCert = true;
					}
				}
				// remove line returns from the returned cert as these occur at different points
				// to the original file
				String cert = res.localX509Cert.replaceAll("[\\r\\n]","");

				assertEquals(cert, sb.toString());
			} catch (IOException e) {
				e.printStackTrace();
				fail("Unexpected exception thrown whilst reading cert file.");
			}
		} 
		catch (RemoteException e) 
		{
			e.printStackTrace();
			fail("A remote exception should not have been thrown here");
		} 
		catch (FileNotFoundException e) 
		{
			e.printStackTrace();
			fail("Could not find server cert file to compare results with");
		}
		catch (Exception e)
		{
			e.printStackTrace();
			fail("An exception should not have been thrown here");
		}
	}
	
	
	public void testGetAttCert()
	{
		try 
		{
			ConnectResponse res1 = this.client.callConnectService(
					VALID_USER_ID, VALID_PW, true);			
			GetAttCertResponse res = client.callGetAttCertService(
					null, VALID_ATT_AUTH_URI, null, null, true, VALID_ROLE, 
					true, res1.localSessID, null);
					
			// just to quick check of content - to avoid need for xml parsing
			assertNotNull(res.localAttCert);
			res.localAttCert.contains("<name>coapec</name>");
			res.localAttCert.contains("<provenance>original</provenance>");
			assertNull(res.localMsg);
			assertNull(res.localExtAttCertOut);
		}
		catch (Exception e)
		{
			e.printStackTrace();
			fail("An exception should not have been thrown here");
		}
	}
	
	
	public void testGetAttCertWithoutMapFromTrustedHosts()
	{
		try 
		{
			ConnectResponse res1 = this.client.callConnectService(
					VALID_USER_ID, VALID_PW, true);			
			GetAttCertResponse res = client.callGetAttCertService(
					null, VALID_ATT_AUTH_URI, null, null, false, null, 
					true, res1.localSessID, null);
					
			// just to quick check of content - to avoid need for xml parsing
			assertNotNull(res.localAttCert);
			res.localAttCert.contains("<name>coapec</name>");
			res.localAttCert.contains("<provenance>original</provenance>");
			assertNull(res.localMsg);
			assertNull(res.localExtAttCertOut);
		}
		catch (Exception e)
		{
			e.printStackTrace();
			fail("An exception should not have been thrown here");
		}
	}
	
	
	public void testGetAttCertInvalidAttAuthCert()
	{
		try 
		{
			ConnectResponse res1 = this.client.callConnectService(
					VALID_USER_ID, VALID_PW, true);			
			GetAttCertResponse res = client.callGetAttCertService(
					INVALID_ATT_AUTH_CERT, VALID_ATT_AUTH_URI,
					null, null, true, null, true, res1.localSessID , null);
					
			// just to quick check of content - to avoid need for xml parsing
			assertNotNull(res.localAttCert);
			res.localAttCert.contains("<name>coapec</name>");
			res.localAttCert.contains("<provenance>original</provenance>");
			assertNull(res.localMsg);
			assertNull(res.localExtAttCertOut);
		}
		catch (Exception e)
		{
			e.printStackTrace();
			fail("An exception should not have been thrown here");
		}
	}
	
	
	public void testGetAttCertInvalidAttAuthURI()
	{
		try 
		{
			ConnectResponse res1 = this.client.callConnectService(
					VALID_USER_ID, VALID_PW, true);			
			GetAttCertResponse res = client.callGetAttCertService(
					null, INVALID_ATT_AUTH_URI,
					null, null,
					true, VALID_ROLE, true, res1.localSessID , res1.localUserCert);
					
			fail("An AxisFault should have been thrown here");
		}
		catch (AxisFault e) 
		{
			assertEquals(STANDARD_AXIS_FAULT, e.getMessage());
		}
		catch (Exception e)
		{
			e.printStackTrace();
			fail("An AxisFault should have been thrown here");
		}
	}
	
	
	public void testGetAttCertInvalidExtAttCerts()
	{
		try 
		{
			ConnectResponse res1 = this.client.callConnectService(
					VALID_USER_ID, VALID_PW, true);			
			GetAttCertResponse res = client.callGetAttCertService(
					null, VALID_ATT_AUTH_URI,
					INVALID_EXT_ATT_CERTS, null,
					true, VALID_ROLE, true, res1.localSessID , res1.localUserCert);
					
			// just to quick check of content - to avoid need for xml parsing
			assertNotNull(res.localAttCert);
			res.localAttCert.contains("<name>coapec</name>");
			res.localAttCert.contains("<provenance>original</provenance>");
			assertNull(res.localMsg);
			assertNull(res.localExtAttCertOut);
		}
		catch (Exception e)
		{
			e.printStackTrace();
			fail("An exception should not have been thrown here");
		}
	}

	
	public void testGetAttCertInvalidExtTrustedHosts()
	{
		try 
		{
			ConnectResponse res1 = this.client.callConnectService(
					VALID_USER_ID, VALID_PW, true);			
			GetAttCertResponse res = client.callGetAttCertService(
					null, VALID_ATT_AUTH_URI,
					null, INVALID_EXT_TRUSTED_HOSTS,
					true, VALID_ROLE, true, res1.localSessID , res1.localUserCert);
					
			// just to quick check of content - to avoid need for xml parsing
			assertNotNull(res.localAttCert);
			res.localAttCert.contains("<name>coapec</name>");
			res.localAttCert.contains("<provenance>original</provenance>");
			assertNull(res.localMsg);
			assertNull(res.localExtAttCertOut);
		}
		catch (Exception e)
		{
			e.printStackTrace();
			fail("An exception should not have been thrown here");
		}
	}

	
	public void testGetAttCertValidExtTrustedHosts()
	{
		try 
		{
			// firstly do a call to retrieve an attcert
			ConnectResponse res1 = this.client.callConnectService(
					VALID_USER_ID, VALID_PW, true);			
			GetAttCertResponse res = client.callGetAttCertService(
					null, VALID_ATT_AUTH_URI, null, null, true, null, 
					true, res1.localSessID, null);
					
			// just to quick check of content - to avoid need for xml parsing
			assertNotNull(res.localAttCert);
			String[] extAttCerts = {res.localAttCert};
			res = client.callGetAttCertService(
					null, VALID_ATT_AUTH_URI, 
					extAttCerts, null,
					true, VALID_ROLE, true, res1.localSessID , res1.localUserCert);
					
			// just to quick check of content - to avoid need for xml parsing
			assertNotNull(res.localAttCert);
			res.localAttCert.contains("<name>coapec</name>");
			res.localAttCert.contains("<provenance>original</provenance>");
			assertNull(res.localMsg);
			assertNull(res.localExtAttCertOut);
		}
		catch (Exception e)
		{
			e.printStackTrace();
			fail("An exception should not have been thrown here");
		}
	}
	
	
	public void testGetAttCertInvalidUserCert()
	{
		try 
		{
			ConnectResponse res1 = this.client.callConnectService(
					VALID_USER_ID, VALID_PW, true);			
			GetAttCertResponse res = client.callGetAttCertService(
					null, VALID_ATT_AUTH_URI,
					null, null,
					true, VALID_ROLE, true, res1.localSessID , INVALID_USER_CERT);
					
			// just to quick check of content - to avoid need for xml parsing
			assertNotNull(res.localAttCert);
			res.localAttCert.contains("<name>coapec</name>");
			res.localAttCert.contains("<provenance>original</provenance>");
			assertNull(res.localMsg);
			assertNull(res.localExtAttCertOut);
		}
		catch (Exception e)
		{
			e.printStackTrace();
			fail("An exception should not have been thrown here");
		}
	}
	
	
	public void testGetAttCertInvalidRole()
	{
		try 
		{
			ConnectResponse res1 = this.client.callConnectService(
					VALID_USER_ID, VALID_PW, true);			
			GetAttCertResponse res = client.callGetAttCertService(
					null, VALID_ATT_AUTH_URI,
					null, null,
					true, INVALID_ROLE, true, res1.localSessID , res1.localUserCert);
					
			// just to quick check of content - to avoid need for xml parsing
			assertNotNull(res.localAttCert);
			res.localAttCert.contains("<name>coapec</name>");
			res.localAttCert.contains("<provenance>original</provenance>");
			assertNull(res.localMsg);
			assertNull(res.localExtAttCertOut);
		}
		catch (Exception e)
		{
			e.printStackTrace();
			fail("An exception should not have been thrown here");
		}
	}
	
	
	public void testGetAttCertInvalidSessionID()
	{
		try 
		{
			ConnectResponse res1 = this.client.callConnectService(
					VALID_USER_ID, VALID_PW, true);			
			GetAttCertResponse res = client.callGetAttCertService(
					null, VALID_ATT_AUTH_URI,
					null, null,
					true, VALID_ROLE, true, "blah", res1.localUserCert);
					
			fail("A remote exception should have been thrown here");
		}
		catch (AxisFault e) 
		{
			assertEquals(STANDARD_AXIS_FAULT, e.getMessage());
		}
		catch (Exception e)
		{
			e.printStackTrace();
			fail("An AxisFault should have been thrown here");
		}
	}

	public void testConnect()
	{
		try 
		{
			ConnectResponse res = this.client.callConnectService(
					VALID_USER_ID, VALID_PW, true);			
			// TODO: issuing cert is null - is this ok?
//			assertNotNull(res.localIssuingCert);
			assertNotNull(res.localSessID);
			assertNotNull(res.localUserCert);
			assertNotNull(res.localUserPriKey);
			
		} catch (RemoteException e) {
			e.printStackTrace();
			fail("A remote exception should not have been thrown here");
		}
	}

	public void testConnectNoServerSessionID()
	{
		try 
		{
			ConnectResponse res = this.client.callConnectService(
					VALID_USER_ID, VALID_PW, false);			
			
//			assertNotNull(res.localIssuingCert);
			assertNull(res.localSessID);
			assertNotNull(res.localUserCert);
			assertNotNull(res.localUserPriKey);
			
		} catch (RemoteException e) {
			e.printStackTrace();
			fail("A remote exception should not have been thrown here");
		}
	}
	
	
	public void testDisconnectWithSessionID()
	{
		try 
		{
			// firstly set up a connection
			ConnectResponse res1 = this.client.callConnectService(
					VALID_USER_ID, VALID_PW, true);			

			DisconnectResponse res2 = client.callDisconnectService(
					res1.localSessID, null);
			assertNotNull(res2);
			
			// check session is no longer valid
			GetSessionStatusResponse res3 = client.callGetSessionStatusService(
					null, res1.localSessID);
			
			assertFalse(res3.localIsAlive);
			
		} catch (RemoteException e) {
			e.printStackTrace();
			fail("A remote exception should not have been thrown here");
		}
	}
	
	
	public void testDisconnectWithOnlyUserCert()
	{
		try 
		{
			// firstly set up a connection
			ConnectResponse res1 = this.client.callConnectService(
					VALID_USER_ID, VALID_PW, true);			

			DisconnectResponse res2 = client.callDisconnectService(
					null, res1.localUserCert);
		}
		catch (AxisFault e) 
		{
			assertEquals(STANDARD_AXIS_FAULT, e.getMessage());
		}
		catch (Exception e)
		{
			e.printStackTrace();
			fail("An AxisFault should have been thrown here");
		}
	}

	
	
	public void testDisconnectWithUserIDAndUserCert()
	{
		try 
		{
			// firstly set up a connection
			ConnectResponse res1 = this.client.callConnectService(
					VALID_USER_ID, VALID_PW, true);			

			DisconnectResponse res2 = client.callDisconnectService(
					res1.localSessID, res1.localUserCert);
			assertNotNull(res2);
			
			// check session is no longer valid
			GetSessionStatusResponse res3 = client.callGetSessionStatusService(
					null, res1.localSessID);
			
			assertFalse(res3.localIsAlive);
			
		} catch (RemoteException e) {
			e.printStackTrace();
			fail("A remote exception should not have been thrown here");
		}
	}

	
	public void testInvalidDisconnect()
	{
		try 
		{
			DisconnectResponse res2 = client.callDisconnectService(
					"blah", "bloh");
			fail("A remote exception should have been thrown here");
			
		} 
		catch (AxisFault e) 
		{
			assertEquals(STANDARD_AXIS_FAULT, e.getMessage());
		}
		catch (Exception e)
		{
			e.printStackTrace();
			fail("An AxisFault should have been thrown here");
		}
	}
	
	
	public void testGetSessionStatus()
	{
		try 
		{
			// firstly set up a connection
			ConnectResponse res1 = this.client.callConnectService(
					VALID_USER_ID, VALID_PW, true);			

			GetSessionStatusResponse res2 = client.callGetSessionStatusService(
					VALID_USER_DN, res1.localSessID);
			
			fail("An exception should have been thrown; can only specify DN OR session ID - not both");
		}
		catch (AxisFault e) 
		{
			assertEquals(STANDARD_AXIS_FAULT, e.getMessage());
		}
		catch (Exception e)
		{
			e.printStackTrace();
			fail("An AxisFault should have been thrown here");
		}
	}
	
	
	public void testGetSessionStatusWithOnlyUserDN()
	{
		try 
		{
			// firstly set up a connection
			ConnectResponse res1 = this.client.callConnectService(
					VALID_USER_ID, VALID_PW, true);			

			GetSessionStatusResponse res2 = client.callGetSessionStatusService(
					VALID_USER_ID, null);
			
			assertTrue(res2.localIsAlive);
		} 
		catch (Exception e) {
			e.printStackTrace();
			fail("An exception should not have been thrown here");
		}
	}
	
	
	public void testGetSessionStatusWithOnlySessionID()
	{
		try 
		{
			// firstly set up a connection
			ConnectResponse res1 = this.client.callConnectService(
					VALID_USER_ID, VALID_PW, true);			

			GetSessionStatusResponse res2 = client.callGetSessionStatusService(
					null, res1.localSessID);
			
			assertTrue(res2.localIsAlive);
		} 
		catch (Exception e) {
			e.printStackTrace();
			fail("An exception should not have been thrown here");
		}
	}
	
	
	public void testGetInvalidSessionStatus()
	{
		try 
		{
			GetSessionStatusResponse res = client.callGetSessionStatusService(
					null, "blah");
			
			assertFalse(res.localIsAlive);
		} 
		catch (Exception e) {
			e.printStackTrace();
			fail("An exception should not have been thrown here");
		}
	}
}
