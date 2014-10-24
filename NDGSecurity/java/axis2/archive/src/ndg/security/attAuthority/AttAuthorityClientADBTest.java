package ndg.security.attAuthority;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.rmi.RemoteException;
import java.util.ArrayList;
import java.util.Properties;

import ndg.security.attAuthority.AttAuthorityServiceStub.GetAllHostsInfoResponse;
import ndg.security.attAuthority.AttAuthorityServiceStub.GetAttCertResponse;
import ndg.security.attAuthority.AttAuthorityServiceStub.GetHostInfoResponse;
import ndg.security.attAuthority.AttAuthorityServiceStub.GetTrustedHostInfoResponse;
import ndg.security.attAuthority.AttAuthorityServiceStub.GetX509CertResponse;

import junit.framework.TestCase;

/**
 * Test suite to exercise the AttAuthorityClientADB java client
 * 
 * @author Calum Byrom, Tessella
 * @date 06/08/08
 */
public class AttAuthorityClientADBTest extends TestCase 
{
	private static final String PROPERTIES_FILE = "test.properties";
	private static final String START_CERTIFICATE_STRING = "-----BEGIN CERTIFICATE-----";
	private static final String END_CERTIFICATE_STRING = "-----END CERTIFICATE-----";;

	private Properties properties = null;
	private ArrayList<String> VALID_ROLES = new ArrayList<String>();
	
	public AttAuthorityClientADBTest() throws IOException 
	{
		this.properties = new Properties();
		FileReader reader = new FileReader(getClass().getResource(PROPERTIES_FILE).getFile());
		this.properties.load(reader);
		VALID_ROLES.add("academic");
		VALID_ROLES.add("eoGroup");
		VALID_ROLES.add("student");
	}

	AttAuthorityClientADB client = null;
	
	@Override
	protected void setUp() throws Exception 
	{
		client = new AttAuthorityClientADB();
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
			String lineSep = System.getProperty("line.separator");
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
	}
	
	
	public void testGetAttCert()
	{
		try 
		{
			GetAttCertResponse res = client.callGetAttCertService(null, null, null);
			
			// just to quick queck of content - to avoid need for xml parsing
			assertNotNull(res.localAttCert);
			res.localAttCert.contains("<name>coapec</name>");
			res.localAttCert.contains("<provenance>original</provenance>");
			assertNull(res.localMsg);
			
		} catch (RemoteException e) {
			e.printStackTrace();
			fail("A remote exception should not have been thrown here");
		}
	}
	
	
	public void testGetAttCertWithRole()
	{
		try 
		{
			// NB, this shouldn't make any difference to the result - since the 
			// role mapper is stubbed out
			GetAttCertResponse res = client.callGetAttCertService(null, null, "blah");
			
			// just to quick queck of content - to avoid need for xml parsing
			assertNotNull(res.localAttCert);
			res.localAttCert.contains("<name>coapec</name>");
			res.localAttCert.contains("<provenance>original</provenance>");
			assertNull(res.localMsg);
			
		} catch (RemoteException e) {
			e.printStackTrace();
			fail("A remote exception should not have been thrown here");
		}
	}
	
	
	public void testGetAttCertWithAttCert()
	{
		try 
		{
			// firstly get an attcert to use
			GetAttCertResponse res = client.callGetAttCertService(null, null, null);
			
			String attCert = res.localAttCert;
			assertNotNull(attCert);
			
			// now use this cert to call the service again
			res = client.callGetAttCertService(attCert, null, null);
			assertNotNull(res.localAttCert);
			
		} catch (RemoteException e) {
			e.printStackTrace();
			fail("A remote exception should not have been thrown here");
		}
	}
	
	
	public void testGetAttCertWithCert()
	{
		try 
		{
			// firstly get an attcert to use
			GetAttCertResponse res = client.callGetAttCertService(null, null, null);
			
			String attCert = res.localAttCert;
			assertNotNull(attCert);
			
			// now use this cert to call the service again
			res = client.callGetAttCertService(null, attCert, null);
			assertNotNull(res.localAttCert);
			
		} catch (RemoteException e) {
			e.printStackTrace();
			fail("A remote exception should not have been thrown here");
		}
	}
	
	
	public void testGetAttCertWithAllInputs()
	{
		try 
		{
			// firstly get an attcert to use
			GetAttCertResponse res = client.callGetAttCertService(null, null, null);
			
			String attCert = res.localAttCert;
			assertNotNull(attCert);
			
			// now use this cert to call the service again
			res = client.callGetAttCertService(attCert, attCert, "mysteryShopper");
			assertNotNull(res.localAttCert);
			
		} catch (RemoteException e) {
			e.printStackTrace();
			fail("A remote exception should not have been thrown here");
		}
	}

	
	public void testGetHostInfo()
	{
		try 
		{
			GetHostInfoResponse res = client.callGetHostInfo();

			assertEquals("/O=NDG/OU=Site A/CN=AttributeAuthority", res.localAaDN);
			assertEquals("http://localhost:5000/AttributeAuthority", res.localAaURI);
			assertEquals("Site A", res.localHostname);
			assertEquals("/C=UK/ST=Oxfordshire/O=STFC/OU=BADC/CN=localhost", res.localLoginRequestServerDN);
			assertEquals("/C=UK/ST=Oxfordshire/O=STFC/OU=BADC/CN=localhost", res.localLoginServerDN);
			assertEquals("https://localhost/login", res.localLoginURI);
		} 
		catch (RemoteException e) 
		{
			e.printStackTrace();
			fail("A remote exception should not have been thrown here");
		}
	}
	
	public void testGetTrustedHostInfoNoRole() 
	{
		GetTrustedHostInfoResponse res;
		try {
			res = client.callGetTrustedHostInfo(null);
			AttAuthorityServiceStub.HostInfo[] hostInfo = res.localTrustedHosts;
			
			assertEquals(2, hostInfo.length);
			
			// do a quick check of one of the results
			for (int i = 0; i < hostInfo.length; i++)
			{
				if (! hostInfo[i].localHostname.equals("Site D"))
					continue;

				assertEquals("/O=SiteD/OU=Security/CN=AttributeAuthority", hostInfo[i].localAaDN);
				assertEquals("http://aa.sited.blah", hostInfo[i].localAaURI);
				assertEquals("Site D", hostInfo[i].localHostname);
				assertEquals("/O=SiteD/OU=D/CN=ndg.sited.blah", hostInfo[i].localLoginRequestServerDN);
				assertEquals("/O=SiteD/OU=D/CN=ndg.sited.blah", hostInfo[i].localLoginServerDN);
				assertEquals("https://www.sited.blah/login", hostInfo[i].localLoginURI);
				String[] roles = hostInfo[i].localRoleList;
				for (int j = 0; j < roles.length; j++)
				{
					assertTrue(VALID_ROLES.contains(roles[j]));
				}
			}
		} 
		catch (RemoteException e) 
		{
			e.printStackTrace();
			fail("A remote exception should not have been thrown here");
		}
	}
	
	public void testGetTrustedHostInfoPostgradRole() 
	{
		GetTrustedHostInfoResponse res;
		try {
			res = client.callGetTrustedHostInfo("postgrad");
			AttAuthorityServiceStub.HostInfo[] hostInfo = res.localTrustedHosts;
			
			assertEquals(1, hostInfo.length);
			
			for (int i = 0; i < hostInfo.length; i++)
			{
				if (! hostInfo[i].localHostname.equals("Site D"))
					continue;

				assertEquals("/O=SiteD/OU=Security/CN=AttributeAuthority", hostInfo[i].localAaDN);
				assertEquals("http://aa.sited.blah", hostInfo[i].localAaURI);
				assertEquals("Site D", hostInfo[i].localHostname);
				assertEquals("/O=SiteD/OU=D/CN=ndg.sited.blah", hostInfo[i].localLoginRequestServerDN);
				assertEquals("/O=SiteD/OU=D/CN=ndg.sited.blah", hostInfo[i].localLoginServerDN);
				assertEquals("https://www.sited.blah/login", hostInfo[i].localLoginURI);
				String[] roles = hostInfo[i].localRoleList;
				for (int j = 0; j < roles.length; j++)
				{
					assertTrue(VALID_ROLES.contains(roles[j]));
				}
			}
		} 
		catch (RemoteException e) 
		{
			e.printStackTrace();
			fail("A remote exception should not have been thrown here");
		}
	}
	
	public void testGetTrustedHostInfoInvalidRole() 
	{
		GetTrustedHostInfoResponse res;
		try {
			res = client.callGetTrustedHostInfo("blahdilocks");
			fail("A remote exception should have been thrown here");
		} 
		catch (RemoteException e) 
		{
		}
	}
	
	public void testGetAllHostsInfo()
	{
		try 
		{
			GetAllHostsInfoResponse res = client.callGetAllHostsInfo();
			AttAuthorityServiceStub.HostInfo[] hostInfo = res.localHosts;
			// do a quick check of one of the results
			for (int i = 0; i < hostInfo.length; i++)
			{
				if (! hostInfo[i].localHostname.equals("Site C"))
					continue;
				assertEquals("/O=SiteC/OU=Security/CN=AttributeAuthority", hostInfo[i].localAaDN);
				assertEquals("http://aa.sitec.blah", hostInfo[i].localAaURI);
				assertEquals("Site C", hostInfo[i].localHostname);
				assertEquals("/O=SiteD/OU=D/CN=ndg.sitec.blah", hostInfo[i].localLoginRequestServerDN);
				assertEquals("/O=SiteD/OU=D/CN=ndg.sitec.blah", hostInfo[i].localLoginServerDN);
				assertEquals("https://www.sitec.blah/login", hostInfo[i].localLoginURI);
				String[] roles = hostInfo[i].localRoleList;
				assertEquals("StaffMember", roles[0]);
			}
		} 
		catch (RemoteException e) 
		{
			e.printStackTrace();
			fail("A remote exception should not have been thrown here");
		}
	}
}
