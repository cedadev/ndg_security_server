package wssecurity.test.security.ndg;

import java.io.FileReader;
import java.io.IOException;
import java.rmi.RemoteException;
import java.util.Properties;

import org.apache.axis2.AxisFault;
import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.context.ConfigurationContextFactory;

import wssecurity.test.security.ndg.EchoServiceADBStub.EchoResponse;

import junit.framework.TestCase;

/**
 * Test suite to exercise the EchoClientADB java client
 * 
 * @author Calum Byrom, Tessella
 * @date 05/08/08
 */
public class EchoClientADBTest extends TestCase 
{
	private static final String PROPERTIES_FILE = "test.properties";

	private static final String VALID_MESSAGE = "eskimoSnow";

	private static final String RETURNED_VALID_MESSAGE = "Received message from client: " + VALID_MESSAGE;

	private Properties properties = null;
	
	public EchoClientADBTest() throws IOException 
	{
		this.properties = new Properties();
		FileReader reader = new FileReader(getClass().getResource(PROPERTIES_FILE).getFile());
		this.properties.load(reader);
	}

	
	EchoClientADB client = null;
	
	@Override
	protected void setUp() throws Exception 
	{
		client = new EchoClientADB();
		client.configureServiceConnection(this.properties.getProperty("confDir"), 
				this.properties.getProperty("endpoint"));
		}
	
	@Override
	protected void tearDown() throws Exception 
	{
		client = null;
	}

	
	public void testEcho()
	{
		String message = "midnightBlackberries";
		try 
		{
			EchoResponse res = client.callEchoService(VALID_MESSAGE);
			assertEquals(RETURNED_VALID_MESSAGE, res.localEchoResult);
		} 
		catch (RemoteException e) 
		{
			e.printStackTrace();
			fail("A remote exception should not have been thrown here");
		}
	}

	
	public void testEchoInvalidEndPoint()
	{
		String message = "midnightBlackberries";
		try 
		{
			client.configureServiceConnection(this.properties.getProperty("confDir"),
					"monkey");
			EchoResponse res = client.callEchoService(VALID_MESSAGE);
			fail("An exception should have been thrown here");
		} 
		catch (Exception e) 
		{
		}
	}

	
	public void testEchoInvalidConfDir()
	{
		try 
		{
			client.configureServiceConnection("carbuncle",
					this.properties.getProperty("endpoint"));
			EchoResponse res = client.callEchoService(VALID_MESSAGE);
			fail("An exception should have been thrown here");
		} 
		catch (AxisFault e) 
		{
		} 
		catch (Exception e) 
		{
			e.printStackTrace();
			fail("An AxisFault should have been thrown here");
		}
	}

	
	public void testEchoNoInflowSignature()
	{
		try 
		{
			this.setUpNewServiceConfig("/conf/axis2-no-inflow-signature.xml");
			EchoResponse res = client.callEchoService(VALID_MESSAGE);
			fail("An AxisFault should have been thrown here");
		} 
		catch (AxisFault e) 
		{
		} 
		catch (Exception e) 
		{
			e.printStackTrace();
			fail("An AxisFault should have been thrown here");
		}
	}

	
	public void testEchoNoInflowTimestamp()
	{
		try 
		{
			this.setUpNewServiceConfig("/conf/axis2-no-inflow-timestamp.xml");
			EchoResponse res = client.callEchoService(VALID_MESSAGE);
			fail("An AxisFault should have been thrown here");
		} 
		catch (AxisFault e) 
		{
			assertTrue(e.getMessage().contains("actions mismatch"));
		} 
		catch (Exception e) 
		{
			e.printStackTrace();
			fail("An AxisFault should have been thrown here");
		}
	}
	
	public void testEchoNoOutflowSignature()
	{
		try 
		{
			this.setUpNewServiceConfig("/conf/axis2-no-outflow-signature.xml");
			EchoResponse res = client.callEchoService(VALID_MESSAGE);
			fail("An AxisFault should have been thrown here");
		} 
		catch (AxisFault e) 
		{
			assertTrue(e.getMessage().contains(
					"Check Signature confirmation: got a SC element, but no stored SV"));
		} 
		catch (Exception e) 
		{
			e.printStackTrace();
			fail("An AxisFault should have been thrown here");
		}
	}

	
	public void testEchoNoOutflowTimestamp()
	{
		try 
		{
			this.setUpNewServiceConfig("/conf/axis2-no-outflow-timestamp.xml");
			EchoResponse res = client.callEchoService(VALID_MESSAGE);
			fail("An AxisFault should have been thrown here");
		} 
		catch (AxisFault e) 
		{
			assertTrue(e.getMessage().contains(
					"Element to encrypt/sign not found: http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd, Timestamp"));
		} 
		catch (Exception e) 
		{
			e.printStackTrace();
			fail("An AxisFault should have been thrown here");
		}
	}

	
	public void testEchoActionMismatch()
	{
		try 
		{
			this.setUpNewServiceConfig("/conf/axis2-action-mismatch.xml");
			EchoResponse res = client.callEchoService(VALID_MESSAGE);
			fail("An AxisFault should have been thrown here");
		} 
		catch (AxisFault e) 
		{
			assertTrue(e.getMessage().contains("actions mismatch"));
		} 
		catch (Exception e) 
		{
			e.printStackTrace();
			fail("An AxisFault should have been thrown here");
		}
	}

	private void setUpNewServiceConfig(String confFile) throws AxisFault 
	{
		String configDir = this.properties.getProperty("confDir");
    	ConfigurationContext ctx = 
    		ConfigurationContextFactory.
    		createConfigurationContextFromFileSystem(configDir, 
    									configDir + confFile);
    	
    	client.setService(new EchoServiceADBStub(ctx, 
    			this.properties.getProperty("endpoint")));
	}

}
