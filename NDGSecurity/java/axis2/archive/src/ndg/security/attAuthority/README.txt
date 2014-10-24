Running Tests
-----------------
The AttAuthorityClientADBTest class contains a number of tests to exercise the 
AttAuthorityClientADB class under a variety of circumstances.  To get this 
running, edit the test.properties file so that the configuration dir, certFile
(which should point to the public cert of the server) and the endpoint url are 
correct.  NB, the endpoints are currently set to allow tcpmon to be connected 
into the system - i.e. input port 4900, service port 5000 and 5100.