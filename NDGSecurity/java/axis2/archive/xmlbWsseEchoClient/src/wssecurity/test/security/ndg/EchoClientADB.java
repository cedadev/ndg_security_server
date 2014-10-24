package wssecurity.test.security.ndg;

import java.rmi.RemoteException;

import org.apache.axis2.AxisFault;
import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.context.ConfigurationContextFactory;

import wssecurity.test.security.ndg.EchoServiceADBStub.Echo;
import wssecurity.test.security.ndg.EchoServiceADBStub.EchoResponse;

/**
 * A java client demonstrating use of Axis Data Bindings to access the service
 * 
 * @author Calum Byrom, Tessella
 * @date 04/08/08
 */
public class EchoClientADB 
{
	private EchoServiceADBStub service = null;

	public static void main(java.lang.String args[])
    {
        try
        {
        	EchoClientADB client = new EchoClientADB();

        	client.configureServiceConnection("/home/users/cbyrom/eclipseWorkspace/TI12-security-java/axis2/xmlbWsseEchoClient",
        			"http://localhost:7000/Echo");
        	
        	client.runServices();
        }
       	catch(Exception e)
        {
       		System.out.println("Back to the drawing board...:");
            e.printStackTrace();
        }
    }


	private void runServices() throws RemoteException 
	{
    	this.callEchoService("Hello echo server!");
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
    	
    	this.service = new EchoServiceADBStub(ctx, endpointURI);
	}

	public EchoResponse callEchoService(String message) throws RemoteException 
	{
		Echo echoCall = new Echo();
		echoCall.setEchoIn(message);
		EchoResponse res = this.service.Echo(echoCall);
		System.out.println("Service returned successfully - result:");
		System.out.println(res.localEchoResult);
		return res;
	}


	public void setService(EchoServiceADBStub service) {
		this.service = service;
	}

}
