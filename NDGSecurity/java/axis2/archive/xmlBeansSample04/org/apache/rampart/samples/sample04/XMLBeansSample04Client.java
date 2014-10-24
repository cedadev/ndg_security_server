package org.apache.rampart.samples.sample04;

import org.apache.rampart.samples.sample04.EchoDocument;
import org.apache.rampart.samples.sample04.EchoResponseDocument;

import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.context.ConfigurationContextFactory;

public class XMLBeansSample04Client {

    public static void main(java.lang.String args[]){
        try{
        	String configDir = "/home/pjkershaw/xmlBeansSample04";
        	ConfigurationContext ctx = 
        		ConfigurationContextFactory.
        		createConfigurationContextFromFileSystem(configDir, 
        									configDir + "/conf/axis2.xml");
        	
        	// http://localhost:8080/axis2/services/sample04 /home/pjkershaw/sample04/
        	String endpointURI = 
        		"http://localhost:8080/axis2/services/sample04";
        	Sample04Stub stub = new Sample04Stub(ctx, endpointURI);

            echo(stub);

        } catch(Exception e){
            e.printStackTrace();
            System.err.println("\n\n\n");
        }
    }

    /* two way call/receive */
    public static void echo(Sample04Stub stub){
        try{
        	EchoDocument reqDoc = EchoDocument.Factory.newInstance();
            EchoDocument.Echo req = reqDoc.addNewEcho();
            req.setParam0("Hello echo server!");

            EchoResponseDocument res =
                stub.echo(reqDoc);

            System.err.println(res.getEchoResponse().getReturn());
        } catch(Exception e){
            e.printStackTrace();
            System.err.println("\n\n\n");
        }
    }
}
