
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.soap.MessageFactory;
import javax.xml.soap.SOAPEnvelope;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPMessage;
import javax.xml.soap.SOAPPart;

import org.apache.xml.security.Init;
import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.junit.After;
import org.junit.Before;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

/**
 * 
 */

/**
 * @author pjkersha
 *
 */
public class C14nTest {

	/**
	 * @throws java.lang.Exception
	 */
	@Before
	public void setUp() throws Exception {
	}

	/**
	 * @throws java.lang.Exception
	 */
	@After
	public void tearDown() throws Exception {
	}
	
	
	public void testC14n() throws CanonicalizationException, SOAPException, 
			InvalidCanonicalizerException, SAXException, IOException, 
			ParserConfigurationException {
		
		System.out.println("testC14n ...");

		Init.init();
		
		File f = new File("./src/msg.xml");
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);

        javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();
		Document doc = db.parse(f);

//		MessageFactory messageFactory = MessageFactory.newInstance();
//		SOAPMessage message = messageFactory.createMessage();
//
//		SOAPPart soapPart = message.getSOAPPart(); 
//		SOAPEnvelope envelope = soapPart.getEnvelope();
//
//	    Document doc = envelope.getOwnerDocument();
        Canonicalizer c14n;
		c14n = Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

		String inclNS = "z Z";
        byte[] canonicalMessage = c14n.canonicalizeSubtree(doc, inclNS);

    	ByteArrayInputStream in = new ByteArrayInputStream(canonicalMessage);

    	File c14nFile = new File("./src/c14n.xml");
    	FileOutputStream fos = new FileOutputStream(c14nFile);
    	int data;
    	while ((data=in.read()) != -1)
    	{
    		char ch = (char)data;
    		fos.write(ch);
    		System.out.write(ch);
    	}
    	fos.flush();
    	fos.close();
    } 

    public static void main(java.lang.String args[]) throws SAXException, 
    		IOException, ParserConfigurationException {
    	try {
			(new C14nTest()).testC14n();
		} catch (CanonicalizationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidCanonicalizerException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SOAPException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    }
}
