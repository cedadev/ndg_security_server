Running the SessionMgr client tests
-------------------
In order to contact the server running through ssl on ndgbeta, firstly the server keys
need to be added to the client's keystore.  This can be done easily by running the
helper class, ndg.security.utils.InstallCert.java - with the input param, 'ndgbeta.badc.rl.ac.uk'
- when prompted, enter '1' to write the server certs to a local keystore, 'jssecacerts'.  
This then needs to be copied to $JAVA_HOME/jre/lib/security/ to be used by the client.

NB, if this isn't done you'll get the following error:

org.apache.axis2.AxisFault: sun.security.validator.ValidatorException: PKIX path building failed: sun.security.provider.certpath.SunCertPathBuilderException: unable to find valid certification path to requested targetBack to the drawing board...:

- if this keystore doesn't get picked up automatically (it didn't on windows for some reason), add
the following VM arg when running the tests:

-Djavax.net.ssl.trustStore=<add_path>\TI12-security-java\jssecacerts

For the tests to run correctly, the test.properties file in this folder needs to
be edited to provide valid inputs.  Additionally, if the SessionMgrClientADB client
is to be ran as a java app, the class should be edited to include a valid userID and
password.