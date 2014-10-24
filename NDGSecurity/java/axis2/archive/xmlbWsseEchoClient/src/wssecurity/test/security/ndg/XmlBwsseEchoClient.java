package wssecurity.test.security.ndg;

import java.rmi.RemoteException;

import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.context.ConfigurationContextFactory;

/**
 * A java client demonstrating use of xmlbeans data bindings to access the service
 * 
 * @author Calum Byrom, Tessella
 * @date 04/08/08
 */
public class XmlBwsseEchoClient {

    public static void main(java.lang.String args[])
    {
        try{
        	String configDir = "/home/users/cbyrom/eclipseWorkspace/TI12-security-java/axis2/xmlbWsseEchoClient";
        	ConfigurationContext ctx = 
        		ConfigurationContextFactory.
        		createConfigurationContextFromFileSystem(configDir, 
        									configDir + "/conf/axis2.xml");
        	
        	String endpointURI = "http://localhost:7000/Echo";
        	EchoServiceStub serviceStub = new EchoServiceStub(ctx, endpointURI);

            callEchoService(serviceStub);
        } 
        catch(Exception e)
        {
        	System.out.println("Something bad happened:");
            e.printStackTrace();
        }
    }

    /* two way call/receive */
    public static void callEchoService(EchoServiceStub stub) throws RemoteException
    {
    	EchoDocument reqDoc = EchoDocument.Factory.newInstance();
        EchoDocument.Echo req = reqDoc.addNewEcho();
        req.setEchoIn("Hello echo server!");

        EchoResponseDocument res = stub.Echo(reqDoc);

        System.out.println("Service called successfully - reponse:");
        System.out.println(res.getEchoResponse().getEchoResult());
    }
}
