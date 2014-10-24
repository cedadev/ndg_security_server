package wssecurity.test.security.ndg;

import org.apache.axiom.om.OMAbstractFactory;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMFactory;
import org.apache.axiom.om.OMNamespace;
import org.apache.axis2.addressing.EndpointReference;
import org.apache.axis2.client.Options;
import org.apache.axis2.client.ServiceClient;
import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.context.ConfigurationContextFactory;
import org.apache.axis2.description.Parameter;
import org.apache.rampart.handler.WSSHandlerConstants;
import org.apache.rampart.handler.config.InflowConfiguration;
import org.apache.rampart.handler.config.OutflowConfiguration;

/**
 * A java client demonstrating setting of ws security config programmatically
 * 
 * @author Calum Byrom, Tessella
 * @date 04/08/08
 */
public class EchoClientProgrammatical {

    public static void main(java.lang.String args[]){
        try{
        	String configDir = "/home/users/cbyrom/eclipseWorkspace/TI12-security-java/axis2/xmlbWsseEchoClient";
        	ConfigurationContext ctx = 
        		ConfigurationContextFactory.
        		createConfigurationContextFromFileSystem(configDir, 
        									configDir + "/conf/axis2.xml");

        	ServiceClient client = new ServiceClient(ctx, null);
            Options options = new Options();
            options.setAction("Echo");
        	String endpointURI = "http://localhost:7000/Echo";
            options.setTo(new EndpointReference(endpointURI));
        	
            //Set the rampart parameters
            options.setProperty(WSSHandlerConstants.OUTFLOW_SECURITY, getOutflowConfiguration());
            options.setProperty(WSSHandlerConstants.INFLOW_SECURITY, getInflowConfiguration());
            
            client.setOptions(options);
            
            //Engage rampart
            client.engageModule("rampart");
            
            OMElement response = client.sendReceive(getPayload("Hello world"));
            
            System.out.println(response);

        } catch(Exception e){
            e.printStackTrace();
            System.err.println("\n\n\n");
        }
    }

    private static OMElement getPayload(String value) {
        OMFactory factory = OMAbstractFactory.getOMFactory();
        OMNamespace ns = factory.createOMNamespace("urn:ndg:security:test:wssecurity","");
        OMElement elem = factory.createOMElement("Echo", ns);
        OMElement childElem = factory.createOMElement("EchoIn", ns);
        childElem.setText(value);
        elem.addChild(childElem);
        
        return elem;
    }
    
    private static Parameter getOutflowConfiguration() {
        OutflowConfiguration ofc = new OutflowConfiguration();
        ofc.setActionItems("Timestamp Signature");
        ofc.setUser("client");
        ofc.setPasswordCallbackClass("wssecurity.test.security.ndg.PWCBHandler");
        ofc.setSignaturePropFile("client.properties");
        ofc.setSignatureParts("{Element}{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}Timestamp;{Element}{http://schemas.xmlsoap.org/soap/envelope/}Body");
        ofc.setSignatureKeyIdentifier("DirectReference");
        
        return ofc.getProperty();
    }
    
    private static Parameter getInflowConfiguration() {
        InflowConfiguration ifc = new InflowConfiguration();
        ifc.setActionItems("Signature Timestamp");
        ifc.setPasswordCallbackClass("wssecurity.test.security.ndg.PWCBHandler");
        ifc.setSignaturePropFile("client.properties");
        
        return ifc.getProperty();
    }
}
