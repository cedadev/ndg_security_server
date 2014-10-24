/**
 * SessionMgrServiceLocator.java
 *
 * This file was auto-generated from WSDL
 * by the IBM Web services WSDL2Java emitter.
 * b0619.25 v51306165058
 */

package ndg.security.sessionMgr;

public class SessionMgrServiceLocator extends com.ibm.ws.webservices.multiprotocol.AgnosticService implements com.ibm.ws.webservices.multiprotocol.GeneratedService, ndg.security.sessionMgr.SessionMgrService {

     // NERC Data Grid Session Manager web service

    public SessionMgrServiceLocator() {
        super(com.ibm.ws.webservices.engine.utils.QNameTable.createQName(
           "urn:ndg:security:sessionMgr",
           "SessionMgrService"));

        context.setLocatorName("ndg.security.sessionMgr.SessionMgrServiceLocator");
    }

    public SessionMgrServiceLocator(com.ibm.ws.webservices.multiprotocol.ServiceContext ctx) {
        super(ctx);
        context.setLocatorName("ndg.security.sessionMgr.SessionMgrServiceLocator");
    }

    // Use to get a proxy class for sessionMgr
    private final java.lang.String sessionMgr_address = "http://localhost:5000";

    public java.lang.String getSessionMgrAddress() {
        if (context.getOverriddingEndpointURIs() == null) {
            return sessionMgr_address;
        }
        String overriddingEndpoint = (String) context.getOverriddingEndpointURIs().get("SessionMgr");
        if (overriddingEndpoint != null) {
            return overriddingEndpoint;
        }
        else {
            return sessionMgr_address;
        }
    }

    private java.lang.String sessionMgrPortName = "SessionMgr";

    // The WSDD port name defaults to the port name.
    private java.lang.String sessionMgrWSDDPortName = "SessionMgr";

    public java.lang.String getSessionMgrWSDDPortName() {
        return sessionMgrWSDDPortName;
    }

    public void setSessionMgrWSDDPortName(java.lang.String name) {
        sessionMgrWSDDPortName = name;
    }

    public ndg.security.sessionMgr.SessionMgr getSessionMgr() throws javax.xml.rpc.ServiceException {
       java.net.URL endpoint;
        try {
            endpoint = new java.net.URL(getSessionMgrAddress());
        }
        catch (java.net.MalformedURLException e) {
            return null; // unlikely as URL was validated in WSDL2Java
        }
        return getSessionMgr(endpoint);
    }

    public ndg.security.sessionMgr.SessionMgr getSessionMgr(java.net.URL portAddress) throws javax.xml.rpc.ServiceException {
        ndg.security.sessionMgr.SessionMgr _stub =
            (ndg.security.sessionMgr.SessionMgr) getStub(
                sessionMgrPortName,
                (String) getPort2NamespaceMap().get(sessionMgrPortName),
                ndg.security.sessionMgr.SessionMgr.class,
                "ndg.security.sessionMgr.SessionMgrBindingStub",
                portAddress.toString());
        if (_stub instanceof com.ibm.ws.webservices.engine.client.Stub) {
            ((com.ibm.ws.webservices.engine.client.Stub) _stub).setPortName(sessionMgrWSDDPortName);
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
            if (ndg.security.sessionMgr.SessionMgr.class.isAssignableFrom(serviceEndpointInterface)) {
                return getSessionMgr();
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
        if ("SessionMgr".equals(inputPortName)) {
            return getSessionMgr();
        }
        else  {
            throw new javax.xml.rpc.ServiceException();
        }
    }

    public void setPortNamePrefix(java.lang.String prefix) {
        sessionMgrWSDDPortName = prefix + "/" + sessionMgrPortName;
    }

    public javax.xml.namespace.QName getServiceName() {
        return com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:sessionMgr", "SessionMgrService");
    }

    private java.util.Map port2NamespaceMap = null;

    protected synchronized java.util.Map getPort2NamespaceMap() {
        if (port2NamespaceMap == null) {
            port2NamespaceMap = new java.util.HashMap();
            port2NamespaceMap.put(
               "SessionMgr",
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
        if  (portName.getLocalPart().equals("SessionMgr")) {
            return new javax.xml.rpc.Call[] {
                createCall(portName, "addUser", "null"),
                createCall(portName, "connect", "null"),
                createCall(portName, "disconnect", "null"),
                createCall(portName, "getAttCert", "null"),
                createCall(portName, "getX509Cert", "null"),
            };
        }
        else {
            throw new javax.xml.rpc.ServiceException("WSWS3062E: Error: portName should not be null.");
        }
    }
}
