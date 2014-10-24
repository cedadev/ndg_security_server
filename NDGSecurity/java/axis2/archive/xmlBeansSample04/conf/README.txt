Configuration notes for use with axis2.xml
------------------

The axis2.xml file contained in this directory is used by the java client, 
axis2/xmlbWsseEchoClient/src/wssecurity.test.security.ndg/EchoClient.java
to set up the required webservice security configuration for communicating with the 
secure Echo service - provided by TI12-security-trunk/python/ndg.security.test/ndg/security/test/wsSecurity/server/echoServer.py
- using the Rampart library which is built on the wss4j framework.

A brief explanation of the contents follows:

	<module ref="rampart" /> - enables the rampart module
	
	<parameter name="OutflowSecurity"> - the security set on outgoing SOAP messages
      <action>
        <items>Timestamp Signature</items> - add a timestamp to the SOAP Header and then add signature
        <user>client</user> - the username used to complete the action.  This is used by the passwordCallbackClass to determine the password to the keystore specified in client.properties.  NB, the example Handler is
        a dummy file; in a production system, this data should be looked up via LDAP or some other authentication/authorisation system
        <signaturePropFile>client.properties</signaturePropFile> - the client.properties file to use; if no filepath is included, the location is assumed to be the dir above the source package dir
        <passwordCallbackClass>ndg.security.client.PWCBHandler</passwordCallbackClass> - class to handle password callback - i.e. to lookup the keystore passoword for the user specified in the user element
        <signatureKeyIdentifier>DirectReference</signatureKeyIdentifier> - key id to be used in referring the key in the signature.  If 'DirectReference' is used, rampart adds the client's public key to the
        header as a BinarySecurityTokene and adds a reference to it from the signature; this allows the services to process the client request without needing to have the client public key
        in its keystore.
		<signatureParts>{Element}{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}Timestamp;{Element}{http://schemas.xmlsoap.org/soap/envelope/}Body</signatureParts> - use this
		to specify additional elements to add to the SOAP Header SignatureValue.  Also, see (3).
      </action>
    </parameter>

    <parameter name="InflowSecurity"> - the security to expect on incoming SOAP messages
      <action>
        <items>Signature Timestamp</items> - see (2)
        <signaturePropFile>client.properties</signaturePropFile>
        <passwordCallbackClass>wssecurity.test.security.ndg.PWCBHandler</passwordCallbackClass>
      </action>
    </parameter>
 

 Further notes:
 1) Other actions are available - including Encrypt, if the message body needs encrypting; if this is set, elements need to be included to identify
 the encrypt/decrypt user or key to use
 2) The order the actions are specified in is important; they must be mirrored across the
 the client-server comms.  If there is a mismatch, the following error is likely to be thrown
 by the client (NB, tcpmon will still show the correct message response):
 org.apache.axis2.AxisFault: WSDoAllReceiver: security processing failed (actions mismatch)
 3) It does not appear to be possible to add the BinarySecurityToken to the Signature; including it in
 the signatureParts element leads to the exception:
 General security error (WSEncryptBody/WSSignEnvelope: Element to encrypt/sign not found 
 