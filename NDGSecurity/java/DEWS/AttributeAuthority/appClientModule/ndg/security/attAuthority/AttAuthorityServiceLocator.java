/**
 * AttAuthorityServiceLocator.java
 *
 * This file was auto-generated from WSDL
 * by the IBM Web services WSDL2Java emitter.
 * b0619.25 v51306165058
 */

package ndg.security.attAuthority;

public class AttAuthorityServiceLocator extends com.ibm.ws.webservices.multiprotocol.AgnosticService implements com.ibm.ws.webservices.multiprotocol.GeneratedService, ndg.security.attAuthority.AttAuthorityService {

     // NERC Data Grid Attribute Authority web service

    public AttAuthorityServiceLocator() {
        super(com.ibm.ws.webservices.engine.utils.QNameTable.createQName(
           "urn:ndg:security:attAuthority",
           "AttAuthorityService"));

        context.setLocatorName("ndg.security.attAuthority.AttAuthorityServiceLocator");
    }

    public AttAuthorityServiceLocator(com.ibm.ws.webservices.multiprotocol.ServiceContext ctx) {
        super(ctx);
        context.setLocatorName("ndg.security.attAuthority.AttAuthorityServiceLocator");
    }

    // Use to get a proxy class for attAuthority
    private final java.lang.String attAuthority_address = "http://localhost:5700";

    public java.lang.String getAttAuthorityAddress() {
        if (context.getOverriddingEndpointURIs() == null) {
            return attAuthority_address;
        }
        String overriddingEndpoint = (String) context.getOverriddingEndpointURIs().get("AttAuthority");
        if (overriddingEndpoint != null) {
            return overriddingEndpoint;
        }
        else {
            return attAuthority_address;
        }
    }

    private java.lang.String attAuthorityPortName = "AttAuthority";

    // The WSDD port name defaults to the port name.
    private java.lang.String attAuthorityWSDDPortName = "AttAuthority";

    public java.lang.String getAttAuthorityWSDDPortName() {
        return attAuthorityWSDDPortName;
    }

    public void setAttAuthorityWSDDPortName(java.lang.String name) {
        attAuthorityWSDDPortName = name;
    }

    public ndg.security.attAuthority.AttAuthority getAttAuthority() throws javax.xml.rpc.ServiceException {
       java.net.URL endpoint;
        try {
            endpoint = new java.net.URL(getAttAuthorityAddress());
        }
        catch (java.net.MalformedURLException e) {
            return null; // unlikely as URL was validated in WSDL2Java
        }
        return getAttAuthority(endpoint);
    }

    public ndg.security.attAuthority.AttAuthority getAttAuthority(java.net.URL portAddress) throws javax.xml.rpc.ServiceException {
        ndg.security.attAuthority.AttAuthority _stub =
            (ndg.security.attAuthority.AttAuthority) getStub(
                attAuthorityPortName,
                (String) getPort2NamespaceMap().get(attAuthorityPortName),
                ndg.security.attAuthority.AttAuthority.class,
                "ndg.security.attAuthority.AttAuthorityBindingStub",
                portAddress.toString());
        if (_stub instanceof com.ibm.ws.webservices.engine.client.Stub) {
            ((com.ibm.ws.webservices.engine.client.Stub) _stub).setPortName(attAuthorityWSDDPortName);
        }
        return _stub;
    }

    /**
     * For the given interface, get the stub implementation.
     * If this service has no port for the given interface,
     * then ServiceException is thrown.
     */
    public java.rmi.Remote getPort(Class serviceEndpointInterface) throws javax.xml.rpc.ServiceException {
        try {
            if (ndg.security.attAuthority.AttAuthority.class.isAssignableFrom(serviceEndpointInterface)) {
                return getAttAuthority();
            }
        }
        catch (java.lang.Throwable t) {
            throw new javax.xml.rpc.ServiceException(t);
        }
        throw new javax.xml.rpc.ServiceException("WSWS3273E: Error: There is no stub implementation for the interface:  " + (serviceEndpointInterface == null ? "null" : serviceEndpointInterface.getName()));
    }

    /**
     * For the given interface, get the stub implementation.
     * If this service has no port for the given interface,
     * then ServiceException is thrown.
     */
    public java.rmi.Remote getPort(javax.xml.namespace.QName portName, Class serviceEndpointInterface) throws javax.xml.rpc.ServiceException {
        String inputPortName = portName.getLocalPart();
        if ("AttAuthority".equals(inputPortName)) {
            return getAttAuthority();
        }
        else  {
            throw new javax.xml.rpc.ServiceException();
        }
    }

    public void setPortNamePrefix(java.lang.String prefix) {
        attAuthorityWSDDPortName = prefix + "/" + attAuthorityPortName;
    }

    public javax.xml.namespace.QName getServiceName() {
        return com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:attAuthority", "AttAuthorityService");
    }

    private java.util.Map port2NamespaceMap = null;

    protected synchronized java.util.Map getPort2NamespaceMap() {
        if (port2NamespaceMap == null) {
            port2NamespaceMap = new java.util.HashMap();
            port2NamespaceMap.put(
               "AttAuthority",
               "http://schemas.xmlsoap.org/wsdl/soap/");
        }
        return port2NamespaceMap;
    }

    private java.util.HashSet ports = null;

    public java.util.Iterator getPorts() {
        if (ports == null) {
            ports = new java.util.HashSet();
            String serviceNamespace = getServiceName().getNamespaceURI();
            for (java.util.Iterator i = getPort2NamespaceMap().keySet().iterator(); i.hasNext(); ) {
                ports.add(
                    com.ibm.ws.webservices.engine.utils.QNameTable.createQName(
                        serviceNamespace,
                        (String) i.next()));
            }
        }
        return ports.iterator();
    }

    public javax.xml.rpc.Call[] getCalls(javax.xml.namespace.QName portName) throws javax.xml.rpc.ServiceException {
        if (portName == null) {
            throw new javax.xml.rpc.ServiceException("WSWS3062E: Error: portName should not be null.");
        }
        if  (portName.getLocalPart().equals("AttAuthority")) {
            return new javax.xml.rpc.Call[] {
                createCall(portName, "getAttCert", "null"),
                createCall(portName, "getHostInfo", "null"),
                createCall(portName, "getTrustedHostInfo", "null"),
                createCall(portName, "getX509Cert", "null"),
            };
        }
        else {
            throw new javax.xml.rpc.ServiceException("WSWS3062E: Error: portName should not be null.");
        }
    }
}
