/**
 * SessionMgrBindingStub.java
 *
 * This file was auto-generated from WSDL
 * by the IBM Web services WSDL2Java emitter.
 * b0619.25 v51306165058
 */

package ndg.security.sessionMgr;

public class SessionMgrBindingStub extends com.ibm.ws.webservices.engine.client.Stub implements ndg.security.sessionMgr.SessionMgr {
    public SessionMgrBindingStub(java.net.URL endpointURL, javax.xml.rpc.Service service) throws com.ibm.ws.webservices.engine.WebServicesFault {
        if (service == null) {
            super.service = new com.ibm.ws.webservices.engine.client.Service();
        }
        else {
            super.service = service;
        }
        super.engine = ((com.ibm.ws.webservices.engine.client.Service) super.service).getEngine();
        initTypeMapping();
        super.cachedEndpoint = endpointURL;
        super.connection = ((com.ibm.ws.webservices.engine.client.Service) super.service).getConnection(endpointURL);
        super.messageContexts = new com.ibm.ws.webservices.engine.MessageContext[5];
    }

    private void initTypeMapping() {
        javax.xml.rpc.encoding.TypeMapping tm = super.getTypeMapping(com.ibm.ws.webservices.engine.Constants.URI_LITERAL_ENC);
        java.lang.Class javaType = null;
        javax.xml.namespace.QName xmlType = null;
        javax.xml.namespace.QName compQName = null;
        javax.xml.namespace.QName compTypeQName = null;
        com.ibm.ws.webservices.engine.encoding.SerializerFactory sf = null;
        com.ibm.ws.webservices.engine.encoding.DeserializerFactory df = null;
    }

    private static final com.ibm.ws.webservices.engine.description.OperationDesc _addUserOperation0;
    static {
        com.ibm.ws.webservices.engine.description.ParameterDesc[]  _params0 = new com.ibm.ws.webservices.engine.description.ParameterDesc[] {
         new com.ibm.ws.webservices.engine.description.ParameterDesc(com.ibm.ws.webservices.engine.utils.QNameTable.createQName("", "username"), com.ibm.ws.webservices.engine.description.ParameterDesc.IN, com.ibm.ws.webservices.engine.utils.QNameTable.createQName("http://www.w3.org/2001/XMLSchema", "string"), java.lang.String.class, false, false, false, false, true, false), 
         new com.ibm.ws.webservices.engine.description.ParameterDesc(com.ibm.ws.webservices.engine.utils.QNameTable.createQName("", "passphrase"), com.ibm.ws.webservices.engine.description.ParameterDesc.IN, com.ibm.ws.webservices.engine.utils.QNameTable.createQName("http://www.w3.org/2001/XMLSchema", "string"), java.lang.String.class, false, false, false, false, true, false), 
          };
        _params0[0].setOption("partName","string");
        _params0[0].setOption("partQNameString","{http://www.w3.org/2001/XMLSchema}string");
        _params0[1].setOption("partName","string");
        _params0[1].setOption("partQNameString","{http://www.w3.org/2001/XMLSchema}string");
        com.ibm.ws.webservices.engine.description.ParameterDesc  _returnDesc0 = new com.ibm.ws.webservices.engine.description.ParameterDesc(null, com.ibm.ws.webservices.engine.description.ParameterDesc.OUT, com.ibm.ws.webservices.engine.utils.QNameTable.createQName("http://websphere.ibm.com/webservices/", "Void"), void.class, true, false, false, false, true, true); 
        com.ibm.ws.webservices.engine.description.FaultDesc[]  _faults0 = new com.ibm.ws.webservices.engine.description.FaultDesc[] {
          };
        _addUserOperation0 = new com.ibm.ws.webservices.engine.description.OperationDesc("addUser", com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:sessionMgr", "addUser"), _params0, _returnDesc0, _faults0, "addUser");
        _addUserOperation0.setOption("inputMessageQName",com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:sessionMgr", "addUserInputMsg"));
        _addUserOperation0.setOption("targetNamespace","urn:ndg:security:sessionMgr");
        _addUserOperation0.setOption("buildNum","b0619.25");
        _addUserOperation0.setOption("ServiceQName",com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:sessionMgr", "SessionMgrService"));
        _addUserOperation0.setOption("outputMessageQName",com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:sessionMgr", "addUserOutputMsg"));
        _addUserOperation0.setOption("portTypeQName",com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:sessionMgr", "SessionMgr"));
        _addUserOperation0.setUse(com.ibm.ws.webservices.engine.enumtype.Use.LITERAL);
        _addUserOperation0.setStyle(com.ibm.ws.webservices.engine.enumtype.Style.WRAPPED);
    }

    private int _addUserIndex0 = 0;
    private synchronized com.ibm.ws.webservices.engine.client.Stub.Invoke _getaddUserInvoke0(Object[] parameters) throws com.ibm.ws.webservices.engine.WebServicesFault  {
        com.ibm.ws.webservices.engine.MessageContext mc = super.messageContexts[_addUserIndex0];
        if (mc == null) {
            mc = new com.ibm.ws.webservices.engine.MessageContext(super.engine);
            mc.setOperation(SessionMgrBindingStub._addUserOperation0);
            mc.setUseSOAPAction(true);
            mc.setSOAPActionURI("addUser");
            mc.setEncodingStyle(com.ibm.ws.webservices.engine.Constants.URI_LITERAL_ENC);
            mc.setProperty(com.ibm.ws.webservices.engine.client.Call.SEND_TYPE_ATTR, Boolean.FALSE);
            mc.setProperty(com.ibm.ws.webservices.engine.WebServicesEngine.PROP_DOMULTIREFS, Boolean.FALSE);
            super.primeMessageContext(mc);
            super.messageContexts[_addUserIndex0] = mc;
        }
        try {
            mc = (com.ibm.ws.webservices.engine.MessageContext) mc.clone();
        }
        catch (CloneNotSupportedException cnse) {
            throw com.ibm.ws.webservices.engine.WebServicesFault.makeFault(cnse);
        }
        return new com.ibm.ws.webservices.engine.client.Stub.Invoke(connection, mc, parameters);
    }

    public void addUser(java.lang.String username, java.lang.String passphrase) throws java.rmi.RemoteException {
        if (super.cachedEndpoint == null) {
            throw new com.ibm.ws.webservices.engine.NoEndPointException();
        }
        try {
            _getaddUserInvoke0(new java.lang.Object[] {username, passphrase}).invoke();

        } catch (com.ibm.ws.webservices.engine.WebServicesFault wsf) {
            Exception e = wsf.getUserException();
            throw wsf;
        } 
    }

    private static final com.ibm.ws.webservices.engine.description.OperationDesc _connectOperation1;
    static {
        com.ibm.ws.webservices.engine.description.ParameterDesc[]  _params1 = new com.ibm.ws.webservices.engine.description.ParameterDesc[] {
         new com.ibm.ws.webservices.engine.description.ParameterDesc(com.ibm.ws.webservices.engine.utils.QNameTable.createQName("", "username"), com.ibm.ws.webservices.engine.description.ParameterDesc.IN, com.ibm.ws.webservices.engine.utils.QNameTable.createQName("http://www.w3.org/2001/XMLSchema", "string"), java.lang.String.class, false, false, false, false, true, false), 
         new com.ibm.ws.webservices.engine.description.ParameterDesc(com.ibm.ws.webservices.engine.utils.QNameTable.createQName("", "passphrase"), com.ibm.ws.webservices.engine.description.ParameterDesc.IN, com.ibm.ws.webservices.engine.utils.QNameTable.createQName("http://www.w3.org/2001/XMLSchema", "string"), java.lang.String.class, false, false, false, false, true, false), 
         new com.ibm.ws.webservices.engine.description.ParameterDesc(com.ibm.ws.webservices.engine.utils.QNameTable.createQName("", "createServerSess"), com.ibm.ws.webservices.engine.description.ParameterDesc.IN, com.ibm.ws.webservices.engine.utils.QNameTable.createQName("http://www.w3.org/2001/XMLSchema", "boolean"), boolean.class, false, false, false, false, true, false), 
         new com.ibm.ws.webservices.engine.description.ParameterDesc(com.ibm.ws.webservices.engine.utils.QNameTable.createQName("", "getCookie"), com.ibm.ws.webservices.engine.description.ParameterDesc.IN, com.ibm.ws.webservices.engine.utils.QNameTable.createQName("http://www.w3.org/2001/XMLSchema", "boolean"), boolean.class, false, false, false, false, true, false), 
         new com.ibm.ws.webservices.engine.description.ParameterDesc(com.ibm.ws.webservices.engine.utils.QNameTable.createQName("", "proxyCert"), com.ibm.ws.webservices.engine.description.ParameterDesc.OUT, com.ibm.ws.webservices.engine.utils.QNameTable.createQName("http://www.w3.org/2001/XMLSchema", "string"), java.lang.String.class, false, false, false, false, true, false), 
         new com.ibm.ws.webservices.engine.description.ParameterDesc(com.ibm.ws.webservices.engine.utils.QNameTable.createQName("", "proxyPriKey"), com.ibm.ws.webservices.engine.description.ParameterDesc.OUT, com.ibm.ws.webservices.engine.utils.QNameTable.createQName("http://www.w3.org/2001/XMLSchema", "string"), java.lang.String.class, false, false, false, false, true, false), 
         new com.ibm.ws.webservices.engine.description.ParameterDesc(com.ibm.ws.webservices.engine.utils.QNameTable.createQName("", "userCert"), com.ibm.ws.webservices.engine.description.ParameterDesc.OUT, com.ibm.ws.webservices.engine.utils.QNameTable.createQName("http://www.w3.org/2001/XMLSchema", "string"), java.lang.String.class, false, false, false, false, true, false), 
         new com.ibm.ws.webservices.engine.description.ParameterDesc(com.ibm.ws.webservices.engine.utils.QNameTable.createQName("", "cookie"), com.ibm.ws.webservices.engine.description.ParameterDesc.OUT, com.ibm.ws.webservices.engine.utils.QNameTable.createQName("http://www.w3.org/2001/XMLSchema", "string"), java.lang.String.class, false, false, false, true, true, false), 
          };
        _params1[0].setOption("partName","string");
        _params1[0].setOption("partQNameString","{http://www.w3.org/2001/XMLSchema}string");
        _params1[1].setOption("partName","string");
        _params1[1].setOption("partQNameString","{http://www.w3.org/2001/XMLSchema}string");
        _params1[2].setOption("partName","boolean");
        _params1[2].setOption("partQNameString","{http://www.w3.org/2001/XMLSchema}boolean");
        _params1[3].setOption("partName","boolean");
        _params1[3].setOption("partQNameString","{http://www.w3.org/2001/XMLSchema}boolean");
        _params1[4].setOption("partName","string");
        _params1[4].setOption("partQNameString","{http://www.w3.org/2001/XMLSchema}string");
        _params1[5].setOption("partName","string");
        _params1[5].setOption("partQNameString","{http://www.w3.org/2001/XMLSchema}string");
        _params1[6].setOption("partName","string");
        _params1[6].setOption("partQNameString","{http://www.w3.org/2001/XMLSchema}string");
        _params1[7].setOption("partName","string");
        _params1[7].setOption("partQNameString","{http://www.w3.org/2001/XMLSchema}string");
        com.ibm.ws.webservices.engine.description.ParameterDesc  _returnDesc1 = new com.ibm.ws.webservices.engine.description.ParameterDesc(null, com.ibm.ws.webservices.engine.description.ParameterDesc.OUT, com.ibm.ws.webservices.engine.utils.QNameTable.createQName("http://websphere.ibm.com/webservices/", "Void"), void.class, true, false, false, false, true, true); 
        com.ibm.ws.webservices.engine.description.FaultDesc[]  _faults1 = new com.ibm.ws.webservices.engine.description.FaultDesc[] {
          };
        _connectOperation1 = new com.ibm.ws.webservices.engine.description.OperationDesc("connect", com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:sessionMgr", "connect"), _params1, _returnDesc1, _faults1, "connect");
        _connectOperation1.setOption("inputMessageQName",com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:sessionMgr", "connectInputMsg"));
        _connectOperation1.setOption("targetNamespace","urn:ndg:security:sessionMgr");
        _connectOperation1.setOption("buildNum","b0619.25");
        _connectOperation1.setOption("ServiceQName",com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:sessionMgr", "SessionMgrService"));
        _connectOperation1.setOption("outputMessageQName",com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:sessionMgr", "connectOutputMsg"));
        _connectOperation1.setOption("portTypeQName",com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:sessionMgr", "SessionMgr"));
        _connectOperation1.setUse(com.ibm.ws.webservices.engine.enumtype.Use.LITERAL);
        _connectOperation1.setStyle(com.ibm.ws.webservices.engine.enumtype.Style.WRAPPED);
    }

    private int _connectIndex1 = 1;
    private synchronized com.ibm.ws.webservices.engine.client.Stub.Invoke _getconnectInvoke1(Object[] parameters) throws com.ibm.ws.webservices.engine.WebServicesFault  {
        com.ibm.ws.webservices.engine.MessageContext mc = super.messageContexts[_connectIndex1];
        if (mc == null) {
            mc = new com.ibm.ws.webservices.engine.MessageContext(super.engine);
            mc.setOperation(SessionMgrBindingStub._connectOperation1);
            mc.setUseSOAPAction(true);
            mc.setSOAPActionURI("connect");
            mc.setEncodingStyle(com.ibm.ws.webservices.engine.Constants.URI_LITERAL_ENC);
            mc.setProperty(com.ibm.ws.webservices.engine.client.Call.SEND_TYPE_ATTR, Boolean.FALSE);
            mc.setProperty(com.ibm.ws.webservices.engine.WebServicesEngine.PROP_DOMULTIREFS, Boolean.FALSE);
            super.primeMessageContext(mc);
            super.messageContexts[_connectIndex1] = mc;
        }
        try {
            mc = (com.ibm.ws.webservices.engine.MessageContext) mc.clone();
        }
        catch (CloneNotSupportedException cnse) {
            throw com.ibm.ws.webservices.engine.WebServicesFault.makeFault(cnse);
        }
        return new com.ibm.ws.webservices.engine.client.Stub.Invoke(connection, mc, parameters);
    }

    public void connect(java.lang.String username, java.lang.String passphrase, boolean createServerSess, boolean getCookie, javax.xml.rpc.holders.StringHolder proxyCert, javax.xml.rpc.holders.StringHolder proxyPriKey, javax.xml.rpc.holders.StringHolder userCert, javax.xml.rpc.holders.StringHolder cookie) throws java.rmi.RemoteException {
        if (super.cachedEndpoint == null) {
            throw new com.ibm.ws.webservices.engine.NoEndPointException();
        }
        java.util.Vector _resp = null;
        try {
            _resp = _getconnectInvoke1(new java.lang.Object[] {username, passphrase, new java.lang.Boolean(createServerSess), new java.lang.Boolean(getCookie)}).invoke();

        } catch (com.ibm.ws.webservices.engine.WebServicesFault wsf) {
            Exception e = wsf.getUserException();
            throw wsf;
        } 
        for (int _i = 0; _i < _resp.size(); ++_i) {
            com.ibm.ws.webservices.engine.xmlsoap.ext.ParamValue _param = (com.ibm.ws.webservices.engine.xmlsoap.ext.ParamValue) _resp.get(_i);
            if (com.ibm.ws.webservices.engine.utils.QNameTable.createQName("", "proxyCert").equals(_param.getQName())) {
                try {
                    proxyCert.value = (java.lang.String) _param.getValue();
                } catch (java.lang.Exception _exception) {
                    proxyCert.value = (java.lang.String) super.convert(_param.getValue(), java.lang.String.class);
                }
            }
            else if (com.ibm.ws.webservices.engine.utils.QNameTable.createQName("", "proxyPriKey").equals(_param.getQName())) {
                try {
                    proxyPriKey.value = (java.lang.String) _param.getValue();
                } catch (java.lang.Exception _exception) {
                    proxyPriKey.value = (java.lang.String) super.convert(_param.getValue(), java.lang.String.class);
                }
            }
            else if (com.ibm.ws.webservices.engine.utils.QNameTable.createQName("", "userCert").equals(_param.getQName())) {
                try {
                    userCert.value = (java.lang.String) _param.getValue();
                } catch (java.lang.Exception _exception) {
                    userCert.value = (java.lang.String) super.convert(_param.getValue(), java.lang.String.class);
                }
            }
            else if (com.ibm.ws.webservices.engine.utils.QNameTable.createQName("", "cookie").equals(_param.getQName())) {
                try {
                    cookie.value = (java.lang.String) _param.getValue();
                } catch (java.lang.Exception _exception) {
                    cookie.value = (java.lang.String) super.convert(_param.getValue(), java.lang.String.class);
                }
            }
        }
    }

    private static final com.ibm.ws.webservices.engine.description.OperationDesc _disconnectOperation2;
    static {
        com.ibm.ws.webservices.engine.description.ParameterDesc[]  _params2 = new com.ibm.ws.webservices.engine.description.ParameterDesc[] {
         new com.ibm.ws.webservices.engine.description.ParameterDesc(com.ibm.ws.webservices.engine.utils.QNameTable.createQName("", "userCert"), com.ibm.ws.webservices.engine.description.ParameterDesc.IN, com.ibm.ws.webservices.engine.utils.QNameTable.createQName("http://www.w3.org/2001/XMLSchema", "string"), java.lang.String.class, false, false, false, true, true, false), 
         new com.ibm.ws.webservices.engine.description.ParameterDesc(com.ibm.ws.webservices.engine.utils.QNameTable.createQName("", "sessID"), com.ibm.ws.webservices.engine.description.ParameterDesc.IN, com.ibm.ws.webservices.engine.utils.QNameTable.createQName("http://www.w3.org/2001/XMLSchema", "string"), java.lang.String.class, false, false, false, true, true, false), 
         new com.ibm.ws.webservices.engine.description.ParameterDesc(com.ibm.ws.webservices.engine.utils.QNameTable.createQName("", "encrSessionMgrURI"), com.ibm.ws.webservices.engine.description.ParameterDesc.IN, com.ibm.ws.webservices.engine.utils.QNameTable.createQName("http://www.w3.org/2001/XMLSchema", "string"), java.lang.String.class, false, false, false, true, true, false), 
          };
        _params2[0].setOption("partName","string");
        _params2[0].setOption("partQNameString","{http://www.w3.org/2001/XMLSchema}string");
        _params2[1].setOption("partName","string");
        _params2[1].setOption("partQNameString","{http://www.w3.org/2001/XMLSchema}string");
        _params2[2].setOption("partName","string");
        _params2[2].setOption("partQNameString","{http://www.w3.org/2001/XMLSchema}string");
        com.ibm.ws.webservices.engine.description.ParameterDesc  _returnDesc2 = new com.ibm.ws.webservices.engine.description.ParameterDesc(null, com.ibm.ws.webservices.engine.description.ParameterDesc.OUT, com.ibm.ws.webservices.engine.utils.QNameTable.createQName("http://websphere.ibm.com/webservices/", "Void"), void.class, true, false, false, false, true, true); 
        com.ibm.ws.webservices.engine.description.FaultDesc[]  _faults2 = new com.ibm.ws.webservices.engine.description.FaultDesc[] {
          };
        _disconnectOperation2 = new com.ibm.ws.webservices.engine.description.OperationDesc("disconnect", com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:sessionMgr", "disconnect"), _params2, _returnDesc2, _faults2, "disconnect");
        _disconnectOperation2.setOption("inputMessageQName",com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:sessionMgr", "disconnectInputMsg"));
        _disconnectOperation2.setOption("targetNamespace","urn:ndg:security:sessionMgr");
        _disconnectOperation2.setOption("buildNum","b0619.25");
        _disconnectOperation2.setOption("ServiceQName",com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:sessionMgr", "SessionMgrService"));
        _disconnectOperation2.setOption("outputMessageQName",com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:sessionMgr", "disconnectOutputMsg"));
        _disconnectOperation2.setOption("portTypeQName",com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:sessionMgr", "SessionMgr"));
        _disconnectOperation2.setUse(com.ibm.ws.webservices.engine.enumtype.Use.LITERAL);
        _disconnectOperation2.setStyle(com.ibm.ws.webservices.engine.enumtype.Style.WRAPPED);
    }

    private int _disconnectIndex2 = 2;
    private synchronized com.ibm.ws.webservices.engine.client.Stub.Invoke _getdisconnectInvoke2(Object[] parameters) throws com.ibm.ws.webservices.engine.WebServicesFault  {
        com.ibm.ws.webservices.engine.MessageContext mc = super.messageContexts[_disconnectIndex2];
        if (mc == null) {
            mc = new com.ibm.ws.webservices.engine.MessageContext(super.engine);
            mc.setOperation(SessionMgrBindingStub._disconnectOperation2);
            mc.setUseSOAPAction(true);
            mc.setSOAPActionURI("disconnect");
            mc.setEncodingStyle(com.ibm.ws.webservices.engine.Constants.URI_LITERAL_ENC);
            mc.setProperty(com.ibm.ws.webservices.engine.client.Call.SEND_TYPE_ATTR, Boolean.FALSE);
            mc.setProperty(com.ibm.ws.webservices.engine.WebServicesEngine.PROP_DOMULTIREFS, Boolean.FALSE);
            super.primeMessageContext(mc);
            super.messageContexts[_disconnectIndex2] = mc;
        }
        try {
            mc = (com.ibm.ws.webservices.engine.MessageContext) mc.clone();
        }
        catch (CloneNotSupportedException cnse) {
            throw com.ibm.ws.webservices.engine.WebServicesFault.makeFault(cnse);
        }
        return new com.ibm.ws.webservices.engine.client.Stub.Invoke(connection, mc, parameters);
    }

    public void disconnect(java.lang.String userCert, java.lang.String sessID, java.lang.String encrSessionMgrURI) throws java.rmi.RemoteException {
        if (super.cachedEndpoint == null) {
            throw new com.ibm.ws.webservices.engine.NoEndPointException();
        }
        try {
            _getdisconnectInvoke2(new java.lang.Object[] {userCert, sessID, encrSessionMgrURI}).invoke();

        } catch (com.ibm.ws.webservices.engine.WebServicesFault wsf) {
            Exception e = wsf.getUserException();
            throw wsf;
        } 
    }

    private static final com.ibm.ws.webservices.engine.description.OperationDesc _getAttCertOperation3;
    static {
        com.ibm.ws.webservices.engine.description.ParameterDesc[]  _params3 = new com.ibm.ws.webservices.engine.description.ParameterDesc[] {
         new com.ibm.ws.webservices.engine.description.ParameterDesc(com.ibm.ws.webservices.engine.utils.QNameTable.createQName("", "userCert"), com.ibm.ws.webservices.engine.description.ParameterDesc.IN, com.ibm.ws.webservices.engine.utils.QNameTable.createQName("http://www.w3.org/2001/XMLSchema", "string"), java.lang.String.class, false, false, false, true, true, false), 
         new com.ibm.ws.webservices.engine.description.ParameterDesc(com.ibm.ws.webservices.engine.utils.QNameTable.createQName("", "sessID"), com.ibm.ws.webservices.engine.description.ParameterDesc.IN, com.ibm.ws.webservices.engine.utils.QNameTable.createQName("http://www.w3.org/2001/XMLSchema", "string"), java.lang.String.class, false, false, false, true, true, false), 
         new com.ibm.ws.webservices.engine.description.ParameterDesc(com.ibm.ws.webservices.engine.utils.QNameTable.createQName("", "encrSessionMgrURI"), com.ibm.ws.webservices.engine.description.ParameterDesc.IN, com.ibm.ws.webservices.engine.utils.QNameTable.createQName("http://www.w3.org/2001/XMLSchema", "string"), java.lang.String.class, false, false, false, true, true, false), 
         new com.ibm.ws.webservices.engine.description.ParameterDesc(com.ibm.ws.webservices.engine.utils.QNameTable.createQName("", "attAuthorityURI"), com.ibm.ws.webservices.engine.description.ParameterDesc.IN, com.ibm.ws.webservices.engine.utils.QNameTable.createQName("http://www.w3.org/2001/XMLSchema", "string"), java.lang.String.class, false, false, false, false, true, false), 
         new com.ibm.ws.webservices.engine.description.ParameterDesc(com.ibm.ws.webservices.engine.utils.QNameTable.createQName("", "attAuthorityCert"), com.ibm.ws.webservices.engine.description.ParameterDesc.IN, com.ibm.ws.webservices.engine.utils.QNameTable.createQName("http://www.w3.org/2001/XMLSchema", "string"), java.lang.String.class, false, false, false, true, true, false), 
         new com.ibm.ws.webservices.engine.description.ParameterDesc(com.ibm.ws.webservices.engine.utils.QNameTable.createQName("", "reqRole"), com.ibm.ws.webservices.engine.description.ParameterDesc.IN, com.ibm.ws.webservices.engine.utils.QNameTable.createQName("http://www.w3.org/2001/XMLSchema", "string"), java.lang.String.class, false, false, false, true, true, false), 
         new com.ibm.ws.webservices.engine.description.ParameterDesc(com.ibm.ws.webservices.engine.utils.QNameTable.createQName("", "mapFromTrustedHosts"), com.ibm.ws.webservices.engine.description.ParameterDesc.IN, com.ibm.ws.webservices.engine.utils.QNameTable.createQName("http://www.w3.org/2001/XMLSchema", "boolean"), boolean.class, false, false, false, false, true, false), 
         new com.ibm.ws.webservices.engine.description.ParameterDesc(com.ibm.ws.webservices.engine.utils.QNameTable.createQName("", "rtnExtAttCertList"), com.ibm.ws.webservices.engine.description.ParameterDesc.IN, com.ibm.ws.webservices.engine.utils.QNameTable.createQName("http://www.w3.org/2001/XMLSchema", "boolean"), boolean.class, false, false, false, false, true, false), 
         new com.ibm.ws.webservices.engine.description.ParameterDesc(com.ibm.ws.webservices.engine.utils.QNameTable.createQName("", "extAttCert"), com.ibm.ws.webservices.engine.description.ParameterDesc.IN, com.ibm.ws.webservices.engine.utils.QNameTable.createQName("http://www.w3.org/2001/XMLSchema", "string"), java.lang.String[].class, false, false, false, true, false, false), 
         new com.ibm.ws.webservices.engine.description.ParameterDesc(com.ibm.ws.webservices.engine.utils.QNameTable.createQName("", "extTrustedHost"), com.ibm.ws.webservices.engine.description.ParameterDesc.IN, com.ibm.ws.webservices.engine.utils.QNameTable.createQName("http://www.w3.org/2001/XMLSchema", "string"), java.lang.String[].class, false, false, false, true, false, false), 
         new com.ibm.ws.webservices.engine.description.ParameterDesc(com.ibm.ws.webservices.engine.utils.QNameTable.createQName("", "attCert"), com.ibm.ws.webservices.engine.description.ParameterDesc.OUT, com.ibm.ws.webservices.engine.utils.QNameTable.createQName("http://www.w3.org/2001/XMLSchema", "string"), java.lang.String.class, false, false, false, true, true, false), 
         new com.ibm.ws.webservices.engine.description.ParameterDesc(com.ibm.ws.webservices.engine.utils.QNameTable.createQName("", "msg"), com.ibm.ws.webservices.engine.description.ParameterDesc.OUT, com.ibm.ws.webservices.engine.utils.QNameTable.createQName("http://www.w3.org/2001/XMLSchema", "string"), java.lang.String.class, false, false, false, true, true, false), 
         new com.ibm.ws.webservices.engine.description.ParameterDesc(com.ibm.ws.webservices.engine.utils.QNameTable.createQName("", "extAttCertOut"), com.ibm.ws.webservices.engine.description.ParameterDesc.OUT, com.ibm.ws.webservices.engine.utils.QNameTable.createQName("http://www.w3.org/2001/XMLSchema", "string"), java.lang.String[].class, false, false, false, true, false, false), 
          };
        _params3[0].setOption("partName","string");
        _params3[0].setOption("partQNameString","{http://www.w3.org/2001/XMLSchema}string");
        _params3[1].setOption("partName","string");
        _params3[1].setOption("partQNameString","{http://www.w3.org/2001/XMLSchema}string");
        _params3[2].setOption("partName","string");
        _params3[2].setOption("partQNameString","{http://www.w3.org/2001/XMLSchema}string");
        _params3[3].setOption("partName","string");
        _params3[3].setOption("partQNameString","{http://www.w3.org/2001/XMLSchema}string");
        _params3[4].setOption("partName","string");
        _params3[4].setOption("partQNameString","{http://www.w3.org/2001/XMLSchema}string");
        _params3[5].setOption("partName","string");
        _params3[5].setOption("partQNameString","{http://www.w3.org/2001/XMLSchema}string");
        _params3[6].setOption("partName","boolean");
        _params3[6].setOption("partQNameString","{http://www.w3.org/2001/XMLSchema}boolean");
        _params3[7].setOption("partName","boolean");
        _params3[7].setOption("partQNameString","{http://www.w3.org/2001/XMLSchema}boolean");
        _params3[8].setOption("partName","string[0,unbounded]");
        _params3[8].setOption("partQNameString","{http://www.w3.org/2001/XMLSchema}string[0,unbounded]");
        _params3[9].setOption("partName","string[0,unbounded]");
        _params3[9].setOption("partQNameString","{http://www.w3.org/2001/XMLSchema}string[0,unbounded]");
        _params3[10].setOption("partName","string");
        _params3[10].setOption("partQNameString","{http://www.w3.org/2001/XMLSchema}string");
        _params3[11].setOption("partName","string");
        _params3[11].setOption("partQNameString","{http://www.w3.org/2001/XMLSchema}string");
        _params3[12].setOption("partName","string[0,unbounded]");
        _params3[12].setOption("partQNameString","{http://www.w3.org/2001/XMLSchema}string[0,unbounded]");
        com.ibm.ws.webservices.engine.description.ParameterDesc  _returnDesc3 = new com.ibm.ws.webservices.engine.description.ParameterDesc(null, com.ibm.ws.webservices.engine.description.ParameterDesc.OUT, com.ibm.ws.webservices.engine.utils.QNameTable.createQName("http://websphere.ibm.com/webservices/", "Void"), void.class, true, false, false, false, true, true); 
        com.ibm.ws.webservices.engine.description.FaultDesc[]  _faults3 = new com.ibm.ws.webservices.engine.description.FaultDesc[] {
          };
        _getAttCertOperation3 = new com.ibm.ws.webservices.engine.description.OperationDesc("getAttCert", com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:sessionMgr", "getAttCert"), _params3, _returnDesc3, _faults3, "getAttCert");
        _getAttCertOperation3.setOption("inputMessageQName",com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:sessionMgr", "getAttCertInputMsg"));
        _getAttCertOperation3.setOption("targetNamespace","urn:ndg:security:sessionMgr");
        _getAttCertOperation3.setOption("buildNum","b0619.25");
        _getAttCertOperation3.setOption("ServiceQName",com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:sessionMgr", "SessionMgrService"));
        _getAttCertOperation3.setOption("outputMessageQName",com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:sessionMgr", "getAttCertOutputMsg"));
        _getAttCertOperation3.setOption("portTypeQName",com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:sessionMgr", "SessionMgr"));
        _getAttCertOperation3.setUse(com.ibm.ws.webservices.engine.enumtype.Use.LITERAL);
        _getAttCertOperation3.setStyle(com.ibm.ws.webservices.engine.enumtype.Style.WRAPPED);
    }

    private int _getAttCertIndex3 = 3;
    private synchronized com.ibm.ws.webservices.engine.client.Stub.Invoke _getgetAttCertInvoke3(Object[] parameters) throws com.ibm.ws.webservices.engine.WebServicesFault  {
        com.ibm.ws.webservices.engine.MessageContext mc = super.messageContexts[_getAttCertIndex3];
        if (mc == null) {
            mc = new com.ibm.ws.webservices.engine.MessageContext(super.engine);
            mc.setOperation(SessionMgrBindingStub._getAttCertOperation3);
            mc.setUseSOAPAction(true);
            mc.setSOAPActionURI("getAttCert");
            mc.setEncodingStyle(com.ibm.ws.webservices.engine.Constants.URI_LITERAL_ENC);
            mc.setProperty(com.ibm.ws.webservices.engine.client.Call.SEND_TYPE_ATTR, Boolean.FALSE);
            mc.setProperty(com.ibm.ws.webservices.engine.WebServicesEngine.PROP_DOMULTIREFS, Boolean.FALSE);
            super.primeMessageContext(mc);
            super.messageContexts[_getAttCertIndex3] = mc;
        }
        try {
            mc = (com.ibm.ws.webservices.engine.MessageContext) mc.clone();
        }
        catch (CloneNotSupportedException cnse) {
            throw com.ibm.ws.webservices.engine.WebServicesFault.makeFault(cnse);
        }
        return new com.ibm.ws.webservices.engine.client.Stub.Invoke(connection, mc, parameters);
    }

    public void getAttCert(java.lang.String userCert, java.lang.String sessID, java.lang.String encrSessionMgrURI, java.lang.String attAuthorityURI, java.lang.String attAuthorityCert, java.lang.String reqRole, boolean mapFromTrustedHosts, boolean rtnExtAttCertList, java.lang.String[] extAttCert, java.lang.String[] extTrustedHost, javax.xml.rpc.holders.StringHolder attCert, javax.xml.rpc.holders.StringHolder msg, ndg.security.sessionMgr.holders.StringArrayHolder extAttCertOut) throws java.rmi.RemoteException {
        if (super.cachedEndpoint == null) {
            throw new com.ibm.ws.webservices.engine.NoEndPointException();
        }
        java.util.Vector _resp = null;
        try {
            _resp = _getgetAttCertInvoke3(new java.lang.Object[] {userCert, sessID, encrSessionMgrURI, attAuthorityURI, attAuthorityCert, reqRole, new java.lang.Boolean(mapFromTrustedHosts), new java.lang.Boolean(rtnExtAttCertList), extAttCert, extTrustedHost}).invoke();

        } catch (com.ibm.ws.webservices.engine.WebServicesFault wsf) {
            Exception e = wsf.getUserException();
            throw wsf;
        } 
        for (int _i = 0; _i < _resp.size(); ++_i) {
            com.ibm.ws.webservices.engine.xmlsoap.ext.ParamValue _param = (com.ibm.ws.webservices.engine.xmlsoap.ext.ParamValue) _resp.get(_i);
            if (com.ibm.ws.webservices.engine.utils.QNameTable.createQName("", "attCert").equals(_param.getQName())) {
                try {
                    attCert.value = (java.lang.String) _param.getValue();
                } catch (java.lang.Exception _exception) {
                    attCert.value = (java.lang.String) super.convert(_param.getValue(), java.lang.String.class);
                }
            }
            else if (com.ibm.ws.webservices.engine.utils.QNameTable.createQName("", "msg").equals(_param.getQName())) {
                try {
                    msg.value = (java.lang.String) _param.getValue();
                } catch (java.lang.Exception _exception) {
                    msg.value = (java.lang.String) super.convert(_param.getValue(), java.lang.String.class);
                }
            }
            else if (com.ibm.ws.webservices.engine.utils.QNameTable.createQName("", "extAttCertOut").equals(_param.getQName())) {
                try {
                    extAttCertOut.value = (java.lang.String[]) _param.getValue();
                } catch (java.lang.Exception _exception) {
                    extAttCertOut.value = (java.lang.String[]) super.convert(_param.getValue(), java.lang.String[].class);
                }
            }
        }
    }

    private static final com.ibm.ws.webservices.engine.description.OperationDesc _getX509CertOperation4;
    static {
        com.ibm.ws.webservices.engine.description.ParameterDesc[]  _params4 = new com.ibm.ws.webservices.engine.description.ParameterDesc[] {
          };
        com.ibm.ws.webservices.engine.description.ParameterDesc  _returnDesc4 = new com.ibm.ws.webservices.engine.description.ParameterDesc(com.ibm.ws.webservices.engine.utils.QNameTable.createQName("", "x509Cert"), com.ibm.ws.webservices.engine.description.ParameterDesc.OUT, com.ibm.ws.webservices.engine.utils.QNameTable.createQName("http://www.w3.org/2001/XMLSchema", "string"), java.lang.String.class, true, false, false, false, true, false); 
        _returnDesc4.setOption("partName","string");
        _returnDesc4.setOption("partQNameString","{http://www.w3.org/2001/XMLSchema}string");
        com.ibm.ws.webservices.engine.description.FaultDesc[]  _faults4 = new com.ibm.ws.webservices.engine.description.FaultDesc[] {
          };
        _getX509CertOperation4 = new com.ibm.ws.webservices.engine.description.OperationDesc("getX509Cert", com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:sessionMgr", "getX509Cert"), _params4, _returnDesc4, _faults4, "getX509Cert");
        _getX509CertOperation4.setOption("inputMessageQName",com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:sessionMgr", "getX509CertInputMsg"));
        _getX509CertOperation4.setOption("targetNamespace","urn:ndg:security:sessionMgr");
        _getX509CertOperation4.setOption("buildNum","b0619.25");
        _getX509CertOperation4.setOption("ServiceQName",com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:sessionMgr", "SessionMgrService"));
        _getX509CertOperation4.setOption("outputMessageQName",com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:sessionMgr", "getX509CertOutputMsg"));
        _getX509CertOperation4.setOption("portTypeQName",com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:sessionMgr", "SessionMgr"));
        _getX509CertOperation4.setUse(com.ibm.ws.webservices.engine.enumtype.Use.LITERAL);
        _getX509CertOperation4.setStyle(com.ibm.ws.webservices.engine.enumtype.Style.WRAPPED);
    }

    private int _getX509CertIndex4 = 4;
    private synchronized com.ibm.ws.webservices.engine.client.Stub.Invoke _getgetX509CertInvoke4(Object[] parameters) throws com.ibm.ws.webservices.engine.WebServicesFault  {
        com.ibm.ws.webservices.engine.MessageContext mc = super.messageContexts[_getX509CertIndex4];
        if (mc == null) {
            mc = new com.ibm.ws.webservices.engine.MessageContext(super.engine);
            mc.setOperation(SessionMgrBindingStub._getX509CertOperation4);
            mc.setUseSOAPAction(true);
            mc.setSOAPActionURI("getX509Cert");
            mc.setEncodingStyle(com.ibm.ws.webservices.engine.Constants.URI_LITERAL_ENC);
            mc.setProperty(com.ibm.ws.webservices.engine.client.Call.SEND_TYPE_ATTR, Boolean.FALSE);
            mc.setProperty(com.ibm.ws.webservices.engine.WebServicesEngine.PROP_DOMULTIREFS, Boolean.FALSE);
            super.primeMessageContext(mc);
            super.messageContexts[_getX509CertIndex4] = mc;
        }
        try {
            mc = (com.ibm.ws.webservices.engine.MessageContext) mc.clone();
        }
        catch (CloneNotSupportedException cnse) {
            throw com.ibm.ws.webservices.engine.WebServicesFault.makeFault(cnse);
        }
        return new com.ibm.ws.webservices.engine.client.Stub.Invoke(connection, mc, parameters);
    }

    public java.lang.String getX509Cert() throws java.rmi.RemoteException {
        if (super.cachedEndpoint == null) {
            throw new com.ibm.ws.webservices.engine.NoEndPointException();
        }
        java.util.Vector _resp = null;
        try {
            _resp = _getgetX509CertInvoke4(new java.lang.Object[] {}).invoke();

        } catch (com.ibm.ws.webservices.engine.WebServicesFault wsf) {
            Exception e = wsf.getUserException();
            throw wsf;
        } 
        try {
            return (java.lang.String) ((com.ibm.ws.webservices.engine.xmlsoap.ext.ParamValue) _resp.get(0)).getValue();
        } catch (java.lang.Exception _exception) {
            return (java.lang.String) super.convert(((com.ibm.ws.webservices.engine.xmlsoap.ext.ParamValue) _resp.get(0)).getValue(), java.lang.String.class);
        }
    }

}
