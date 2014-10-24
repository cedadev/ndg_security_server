Instructions for getting a working Java client
----------------------------------------------
* JDK 1.6 is assumed for this 

1. Download and unpack axis2-1.4 
(http://ws.apache.org/axis2/download/1_4/download.cgi#std-bin)
2. Download and unpack rampart1.3 
(http://ws.apache.org/rampart/download/1.3/download.cgi)
3. Ensure that the AXIS2_HOME environment variable is set correctly then 
run 'ant' in the $RAMPART_HOME/samples dir - this will copy the required 
rampart files into the axis2 install. (If ant is not installed it can be
downloaded from http://ant.apache.org/)
4. Download wss4j-1.5.3.jar (http://mirror.fubra.com/ftp.apache.org/ws/wss4j/) 
and add to the $AXIS2_HOME/lib dir
5. Create a java project in eclipse
6. In the top level directory of this project, run the following command:

$AXIS2_HOME/bin/wsdl2java.sh -uri <service>.wsdl -p ndg.security.client -d adb -s

[For Windows ...
%AXIS2_HOME%\bin\WSDL2Java -uri <service>.wsdl -p ndg.security.client -d adb -s
...]

NB: '-uri' should point to the wsdl to create the service against (can use
absolute file path if the wsdl if available locally)
 '-p' specifies the package to create
 '-d' specifies the databindings to create - here we use the Axis Data Binding 
 default - which is a simple, but not too flexible approach (other options are 
 available: xmlbeans - 
 http://ws.apache.org/axis2/1_4/userguide-creatingclients-xmlbeans.html; and
 JiBX - http://ws.apache.org/axis2/1_4/userguide-creatingclients-jibx.html)
 '-s' specifies synchronous invocation - i.e. the client will wait for a 
 response - use '-a' for asynch clients - i.e. with callback handlers)
 
 7. Refresh the project in eclipse to import the generated stub file - which 
 will be called <service>ServiceStub.java (NB, if other binding types are used 
 there will likely be many more stub files produced)
 8. Open the <service>ServiceStub.java file and correct the package name, if 
 need be.  Also make use of eclipse's auto formatting function (ctrl-F) to tidy
 up the code.
 9. Add the contents of $AXIS2_HOME/lib to the build classpath - this should 
 then remove all the errors displayed in eclipse for the stub file.
 10. Create a new class - <service>Client.java - in the same package as the 
 stub file.
 11. The new class should be based on the example client jar in this folder - 
 i.e. EchoClientADB.jar
 12. Download geronimo-j2ee_1.4_spec-1.0.jar and add this to the classpath 
 (otherwise you end up with a org.apache.axis2.deployment.DeploymentException: 
 javax/jms/JMSException error when running the client)
 13. Copy the $AXIS2_HOME\repository\modules directory to the top level of the 
 project - otherwise you'll get errors involving rampart not being engaged (NB,
  you can probably
 avoid this step by setting up the build path to include the original axis2 
 install home?)
 14. Copy the $AXIS2_HOME\conf directory to the top level of the project
 15. Copy the client.properties file from this project into the top level 
 directory of your project
 16. Set up security keys to use:
 	a) $JAVA_HOME/bin/keytool -genkey -alias client -keystore client.jks -keypass apache -storepass apache -keyalg RSA
 	(NB, can adjust names, but key needs to be RSA format to be accepted by the
 	python ZSI webservice library also, best to use the default keystore type 
 	of 'JKS' - since 'PKCS12' doesn't allow trusted certificates to be stored -
 	so it is not possible to store the service key - i.e. step (c), below)
 	
 	b) The key now needs to be signed by a Certificate Authority (CA) (to allow
 	ZSI processing to complete successfully):
 		i) Firstly generate a certificate request via:

$JAVA_HOME/bin/keytool -certreq -keystore client.jks -storepass apache -alias client -file client.cert.req

 		ii) Now, to get hold of a Certificate Authority key pair, copy the 
 		index.txt. openssl.cnf and serial files from 
		axis2/xmlbWsseEchoclient/opensslFiles/ (originally from 
		http://wso2.org/library/174)
 		iii) Run, 
 		
openssl req -x509 -newkey rsa:1024 -keyout cakey.pem -out cacert.pem -config openssl.cnf
		Enter a password for the CA private key when prompted.
		(NB, some of the DN data that you input whilst running this command 
		will need to match the DN data of the generated key that you want to 
		sign - so try and ensure the data is similar - especially, avoid
		using the default values since these are not the 'Unknown' values that 
		the keytool provides)

		iv) Create new certificates signed by the CA key using:

openssl ca -config openssl.cnf -out client.pem -infiles client.cert.req
 		(NB, this command will fail if the DN data between the CA cert and the 
 		generated key mismatches significantly - as described in (iii)

		v) To import the new signed key into the keystore, need to put into 
		binary format:
		
openssl x509 -outform DER -in client.pem -out client.cert
		
		and do the same for the CA certificate:
		
openssl x509 -outform DER -in cacert.pem -out cacert.cert

		vi) Lastly, import both the CA certificate and the new key (NB, the CA 
		cert needs to be imported first - 
		therwise you'll get a 'keytool error: java.lang.Exception: Failed to 
		establish chain from reply')
		 		
$JAVA_HOME/bin/keytool -import -file cacert.cert -keystore client.jks -storepass apache -alias ca
$JAVA_HOME/bin/keytool -import -file client.cert -keystore client.jks -storepass apache -alias client

	c) The last thing to do is import the public key of the service into the 
	client keystore:

$JAVA_HOME/bin/keytool -import -alias service -file service.cert -keystore client -storepass apache

17. Edit the contents of client.properties to ensure the file and password 
properties are set correctly.
18. Edit the contents of $AXIS2_HOME\conf\axis2.xml adjusting the rampart set 
up as appropriate.  NB, the
example file included in this codebase 
(axis2/xmlbWsseEchoclient/conf/axis2.xml) should be sufficient for the purposes
here.  The README.txt file in axis2/xmlbWsseEchoclient/conf/ gives a more 
detailed explanation of the various configurations of this file.
19. Include a password callback class, if this is set in axis2.xml, in the 
source code structure - NB, the basic PWCBHandler.java, included in this 
directory, can be used as a starting point.
20. Adjust the server configuration file - to include the CA cert file in pem 
format - i.e.
as created in step 16(iii) in the trusted CA cert file list.
21. Start up the service associated with the wsdl used in step 6. and run the 
client as a java app - with luck the service should return without a problem.

Further notes/examples
-------------------
XmlBwsseEchoClient.java is a client that uses xmlbeans bindings - to get this 
to work, you need to run the build in its top level directory - 
'ant client.jar' - then include the produced XBeans-packaged.jar file in the 
build path.

EchoClientProgrammatical.java is a client that sets up the wss settings 
programmatically.

EchoClientADB.java is a client that uses the Axis Data Bindings.

Running Tests
-----------------
The EchoClientADBTest class contains a number of tests to exercise the 
EchoClientADB class under a variety of circumstances.  To get this running, 
edit the test.properties file so that the configuration dir and the endpoint 
url are correct.  NB, the endpoints are currently set to allow tcpmon to be 
connected into the system - i.e. input port 7000, service port 7100.