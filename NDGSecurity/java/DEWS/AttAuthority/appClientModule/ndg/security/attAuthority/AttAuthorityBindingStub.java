/**
 * AttAuthorityBindingStub.java
 *
 * This file was auto-generated from WSDL
 * by the IBM Web services WSDL2Java emitter.
 * b0619.25 v51306165058
 */

package ndg.security.attAuthority;

public class AttAuthorityBindingStub extends com.ibm.ws.webservices.engine.client.Stub implements ndg.security.attAuthority.AttAuthority {
    public AttAuthorityBindingStub(java.net.URL endpointURL, javax.xml.rpc.Service service) throws com.ibm.ws.webservices.engine.WebServicesFault {
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
        super.messageContexts = new com.ibm.ws.webservices.engine.MessageContext[4];
    }

    private void initTypeMapping() {
        javax.xml.rpc.encoding.TypeMapping tm = super.getTypeMapping(com.ibm.ws.webservices.engine.Constants.URI_LITERAL_ENC);
        java.lang.Class javaType = null;
        javax.xml.namespace.QName xmlType = null;
        javax.xml.namespace.QName compQName = null;
        javax.xml.namespace.QName compTypeQName = null;
        com.ibm.ws.webservices.engine.encoding.SerializerFactory sf = null;
        com.ibm.ws.webservices.engine.encoding.DeserializerFactory df = null;
        javaType = ndg.security.attAuthority.HostInfo.class;
        xmlType = com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:attAuthority", "HostInfo");
        sf = com.ibm.ws.webservices.engine.encoding.ser.BaseSerializerFactory.createFactory(com.ibm.ws.webservices.engine.encoding.ser.BeanSerializerFactory.class, javaType, xmlType);
        df = com.ibm.ws.webservices.engine.encoding.ser.BaseDeserializerFactory.createFactory(com.ibm.ws.webservices.engine.encoding.ser.BeanDeserializerFactory.class, javaType, xmlType);
        if (sf != null || df != null) {
            tm.register(javaType, xmlType, sf, df);
        }

    }

    private static final com.ibm.ws.webservices.engine.description.OperationDesc _getAttCertOperation0;
    static {
        com.ibm.ws.webservices.engine.description.ParameterDesc[]  _params0 = new com.ibm.ws.webservices.engine.description.ParameterDesc[] {
         new com.ibm.ws.webservices.engine.description.ParameterDesc(com.ibm.ws.webservices.engine.utils.QNameTable.createQName("", "userCert"), com.ibm.ws.webservices.engine.description.ParameterDesc.IN, com.ibm.ws.webservices.engine.utils.QNameTable.createQName("http://www.w3.org/2001/XMLSchema", "string"), java.lang.String.class, false, false, false, true, true, false), 
         new com.ibm.ws.webservices.engine.description.ParameterDesc(com.ibm.ws.webservices.engine.utils.QNameTable.createQName("", "userAttCert"), com.ibm.ws.webservices.engine.description.ParameterDesc.IN, com.ibm.ws.webservices.engine.utils.QNameTable.createQName("http://www.w3.org/2001/XMLSchema", "string"), java.lang.String.class, false, false, false, true, true, false), 
         new com.ibm.ws.webservices.engine.description.ParameterDesc(com.ibm.ws.webservices.engine.utils.QNameTable.createQName("", "attCert"), com.ibm.ws.webservices.engine.description.ParameterDesc.OUT, com.ibm.ws.webservices.engine.utils.QNameTable.createQName("http://www.w3.org/2001/XMLSchema", "string"), java.lang.String.class, false, false, false, true, true, false), 
         new com.ibm.ws.webservices.engine.description.ParameterDesc(com.ibm.ws.webservices.engine.utils.QNameTable.createQName("", "msg"), com.ibm.ws.webservices.engine.description.ParameterDesc.OUT, com.ibm.ws.webservices.engine.utils.QNameTable.createQName("http://www.w3.org/2001/XMLSchema", "string"), java.lang.String.class, false, false, false, true, true, false), 
          };
        _params0[0].setOption("partName","string");
        _params0[0].setOption("partQNameString","{http://www.w3.org/2001/XMLSchema}string");
        _params0[1].setOption("partName","string");
        _params0[1].setOption("partQNameString","{http://www.w3.org/2001/XMLSchema}string");
        _params0[2].setOption("partName","string");
        _params0[2].setOption("partQNameString","{http://www.w3.org/2001/XMLSchema}string");
        _params0[3].setOption("partName","string");
        _params0[3].setOption("partQNameString","{http://www.w3.org/2001/XMLSchema}string");
        com.ibm.ws.webservices.engine.description.ParameterDesc  _returnDesc0 = new com.ibm.ws.webservices.engine.description.ParameterDesc(null, com.ibm.ws.webservices.engine.description.ParameterDesc.OUT, com.ibm.ws.webservices.engine.utils.QNameTable.createQName("http://websphere.ibm.com/webservices/", "Void"), void.class, true, false, false, false, true, true); 
        com.ibm.ws.webservices.engine.description.FaultDesc[]  _faults0 = new com.ibm.ws.webservices.engine.description.FaultDesc[] {
          };
        _getAttCertOperation0 = new com.ibm.ws.webservices.engine.description.OperationDesc("getAttCert", com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:attAuthority", "getAttCert"), _params0, _returnDesc0, _faults0, "getAttCert");
        _getAttCertOperation0.setOption("inputMessageQName",com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:attAuthority", "getAttCertInputMsg"));
        _getAttCertOperation0.setOption("targetNamespace","urn:ndg:security:attAuthority");
        _getAttCertOperation0.setOption("buildNum","b0619.25");
        _getAttCertOperation0.setOption("ServiceQName",com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:attAuthority", "AttAuthorityService"));
        _getAttCertOperation0.setOption("outputMessageQName",com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:attAuthority", "getAttCertOutputMsg"));
        _getAttCertOperation0.setOption("portTypeQName",com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:attAuthority", "AttAuthority"));
        _getAttCertOperation0.setUse(com.ibm.ws.webservices.engine.enumtype.Use.LITERAL);
        _getAttCertOperation0.setStyle(com.ibm.ws.webservices.engine.enumtype.Style.WRAPPED);
    }

    private int _getAttCertIndex0 = 0;
    private synchronized com.ibm.ws.webservices.engine.client.Stub.Invoke _getgetAttCertInvoke0(Object[] parameters) throws com.ibm.ws.webservices.engine.WebServicesFault  {
        com.ibm.ws.webservices.engine.MessageContext mc = super.messageContexts[_getAttCertIndex0];
        if (mc == null) {
            mc = new com.ibm.ws.webservices.engine.MessageContext(super.engine);
            mc.setOperation(AttAuthorityBindingStub._getAttCertOperation0);
            mc.setUseSOAPAction(true);
            mc.setSOAPActionURI("getAttCert");
            mc.setEncodingStyle(com.ibm.ws.webservices.engine.Constants.URI_LITERAL_ENC);
            mc.setProperty(com.ibm.ws.webservices.engine.client.Call.SEND_TYPE_ATTR, Boolean.FALSE);
            mc.setProperty(com.ibm.ws.webservices.engine.WebServicesEngine.PROP_DOMULTIREFS, Boolean.FALSE);
            super.primeMessageContext(mc);
            super.messageContexts[_getAttCertIndex0] = mc;
        }
        try {
            mc = (com.ibm.ws.webservices.engine.MessageContext) mc.clone();
        }
        catch (CloneNotSupportedException cnse) {
            throw com.ibm.ws.webservices.engine.WebServicesFault.makeFault(cnse);
        }
        return new com.ibm.ws.webservices.engine.client.Stub.Invoke(connection, mc, parameters);
    }

    public void getAttCert(java.lang.String userCert, java.lang.String userAttCert, javax.xml.rpc.holders.StringHolder attCert, javax.xml.rpc.holders.StringHolder msg) throws java.rmi.RemoteException {
        if (super.cachedEndpoint == null) {
            throw new com.ibm.ws.webservices.engine.NoEndPointException();
        }
        java.util.Vector _resp = null;
        try {
            _resp = _getgetAttCertInvoke0(new java.lang.Object[] {userCert, userAttCert}).invoke();

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
        }
    }

    private static final com.ibm.ws.webservices.engine.description.OperationDesc _getHostInfoOperation1;
    static {
        com.ibm.ws.webservices.engine.description.ParameterDesc[]  _params1 = new com.ibm.ws.webservices.engine.description.ParameterDesc[] {
         new com.ibm.ws.webservices.engine.description.ParameterDesc(com.ibm.ws.webservices.engine.utils.QNameTable.createQName("", "hostname"), com.ibm.ws.webservices.engine.description.ParameterDesc.OUT, com.ibm.ws.webservices.engine.utils.QNameTable.createQName("http://www.w3.org/2001/XMLSchema", "string"), java.lang.String.class, false, false, false, false, true, false), 
         new com.ibm.ws.webservices.engine.description.ParameterDesc(com.ibm.ws.webservices.engine.utils.QNameTable.createQName("", "aaURI"), com.ibm.ws.webservices.engine.description.ParameterDesc.OUT, com.ibm.ws.webservices.engine.utils.QNameTable.createQName("http://www.w3.org/2001/XMLSchema", "string"), java.lang.String.class, false, false, false, false, true, false), 
         new com.ibm.ws.webservices.engine.description.ParameterDesc(com.ibm.ws.webservices.engine.utils.QNameTable.createQName("", "loginURI"), com.ibm.ws.webservices.engine.description.ParameterDesc.OUT, com.ibm.ws.webservices.engine.utils.QNameTable.createQName("http://www.w3.org/2001/XMLSchema", "string"), java.lang.String.class, false, false, false, false, true, false), 
          };
        _params1[0].setOption("partName","string");
        _params1[0].setOption("partQNameString","{http://www.w3.org/2001/XMLSchema}string");
        _params1[1].setOption("partName","string");
        _params1[1].setOption("partQNameString","{http://www.w3.org/2001/XMLSchema}string");
        _params1[2].setOption("partName","string");
        _params1[2].setOption("partQNameString","{http://www.w3.org/2001/XMLSchema}string");
        com.ibm.ws.webservices.engine.description.ParameterDesc  _returnDesc1 = new com.ibm.ws.webservices.engine.description.ParameterDesc(null, com.ibm.ws.webservices.engine.description.ParameterDesc.OUT, com.ibm.ws.webservices.engine.utils.QNameTable.createQName("http://websphere.ibm.com/webservices/", "Void"), void.class, true, false, false, false, true, true); 
        com.ibm.ws.webservices.engine.description.FaultDesc[]  _faults1 = new com.ibm.ws.webservices.engine.description.FaultDesc[] {
          };
        _getHostInfoOperation1 = new com.ibm.ws.webservices.engine.description.OperationDesc("getHostInfo", com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:attAuthority", "getHostInfo"), _params1, _returnDesc1, _faults1, "getHostInfo");
        _getHostInfoOperation1.setOption("inputMessageQName",com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:attAuthority", "getHostInfoInputMsg"));
        _getHostInfoOperation1.setOption("targetNamespace","urn:ndg:security:attAuthority");
        _getHostInfoOperation1.setOption("buildNum","b0619.25");
        _getHostInfoOperation1.setOption("ServiceQName",com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:attAuthority", "AttAuthorityService"));
        _getHostInfoOperation1.setOption("outputMessageQName",com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:attAuthority", "getHostInfoOutputMsg"));
        _getHostInfoOperation1.setOption("portTypeQName",com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:attAuthority", "AttAuthority"));
        _getHostInfoOperation1.setUse(com.ibm.ws.webservices.engine.enumtype.Use.LITERAL);
        _getHostInfoOperation1.setStyle(com.ibm.ws.webservices.engine.enumtype.Style.WRAPPED);
    }

    private int _getHostInfoIndex1 = 1;
    private synchronized com.ibm.ws.webservices.engine.client.Stub.Invoke _getgetHostInfoInvoke1(Object[] parameters) throws com.ibm.ws.webservices.engine.WebServicesFault  {
        com.ibm.ws.webservices.engine.MessageContext mc = super.messageContexts[_getHostInfoIndex1];
        if (mc == null) {
            mc = new com.ibm.ws.webservices.engine.MessageContext(super.engine);
            mc.setOperation(AttAuthorityBindingStub._getHostInfoOperation1);
            mc.setUseSOAPAction(true);
            mc.setSOAPActionURI("getHostInfo");
            mc.setEncodingStyle(com.ibm.ws.webservices.engine.Constants.URI_LITERAL_ENC);
            mc.setProperty(com.ibm.ws.webservices.engine.client.Call.SEND_TYPE_ATTR, Boolean.FALSE);
            mc.setProperty(com.ibm.ws.webservices.engine.WebServicesEngine.PROP_DOMULTIREFS, Boolean.FALSE);
            super.primeMessageContext(mc);
            super.messageContexts[_getHostInfoIndex1] = mc;
        }
        try {
            mc = (com.ibm.ws.webservices.engine.MessageContext) mc.clone();
        }
        catch (CloneNotSupportedException cnse) {
            throw com.ibm.ws.webservices.engine.WebServicesFault.makeFault(cnse);
        }
        return new com.ibm.ws.webservices.engine.client.Stub.Invoke(connection, mc, parameters);
    }

    public void getHostInfo(javax.xml.rpc.holders.StringHolder hostname, javax.xml.rpc.holders.StringHolder aaURI, javax.xml.rpc.holders.StringHolder loginURI) throws java.rmi.RemoteException {
        if (super.cachedEndpoint == null) {
            throw new com.ibm.ws.webservices.engine.NoEndPointException();
        }
        java.util.Vector _resp = null;
        try {
            _resp = _getgetHostInfoInvoke1(new java.lang.Object[] {}).invoke();

        } catch (com.ibm.ws.webservices.engine.WebServicesFault wsf) {
            Exception e = wsf.getUserException();
            throw wsf;
        } 
        for (int _i = 0; _i < _resp.size(); ++_i) {
            com.ibm.ws.webservices.engine.xmlsoap.ext.ParamValue _param = (com.ibm.ws.webservices.engine.xmlsoap.ext.ParamValue) _resp.get(_i);
            if (com.ibm.ws.webservices.engine.utils.QNameTable.createQName("", "hostname").equals(_param.getQName())) {
                try {
                    hostname.value = (java.lang.String) _param.getValue();
                } catch (java.lang.Exception _exception) {
                    hostname.value = (java.lang.String) super.convert(_param.getValue(), java.lang.String.class);
                }
            }
            else if (com.ibm.ws.webservices.engine.utils.QNameTable.createQName("", "aaURI").equals(_param.getQName())) {
                try {
                    aaURI.value = (java.lang.String) _param.getValue();
                } catch (java.lang.Exception _exception) {
                    aaURI.value = (java.lang.String) super.convert(_param.getValue(), java.lang.String.class);
                }
            }
            else if (com.ibm.ws.webservices.engine.utils.QNameTable.createQName("", "loginURI").equals(_param.getQName())) {
                try {
                    loginURI.value = (java.lang.String) _param.getValue();
                } catch (java.lang.Exception _exception) {
                    loginURI.value = (java.lang.String) super.convert(_param.getValue(), java.lang.String.class);
                }
            }
        }
    }

    private static final com.ibm.ws.webservices.engine.description.OperationDesc _getTrustedHostInfoOperation2;
    static {
        com.ibm.ws.webservices.engine.description.ParameterDesc[]  _params2 = new com.ibm.ws.webservices.engine.description.ParameterDesc[] {
         new com.ibm.ws.webservices.engine.description.ParameterDesc(com.ibm.ws.webservices.engine.utils.QNameTable.createQName("", "role"), com.ibm.ws.webservices.engine.description.ParameterDesc.IN, com.ibm.ws.webservices.engine.utils.QNameTable.createQName("http://www.w3.org/2001/XMLSchema", "string"), java.lang.String.class, false, false, false, true, true, false), 
          };
        _params2[0].setOption("partName","string");
        _params2[0].setOption("partQNameString","{http://www.w3.org/2001/XMLSchema}string");
        com.ibm.ws.webservices.engine.description.ParameterDesc  _returnDesc2 = new com.ibm.ws.webservices.engine.description.ParameterDesc(com.ibm.ws.webservices.engine.utils.QNameTable.createQName("", "trustedHosts"), com.ibm.ws.webservices.engine.description.ParameterDesc.OUT, com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:attAuthority", "HostInfo"), ndg.security.attAuthority.HostInfo[].class, true, false, false, true, false, false); 
        _returnDesc2.setOption("partName","HostInfo[0,unbounded]");
        _returnDesc2.setOption("partQNameString","{urn:ndg:security:attAuthority}HostInfo[0,unbounded]");
        com.ibm.ws.webservices.engine.description.FaultDesc[]  _faults2 = new com.ibm.ws.webservices.engine.description.FaultDesc[] {
          };
        _getTrustedHostInfoOperation2 = new com.ibm.ws.webservices.engine.description.OperationDesc("getTrustedHostInfo", com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:attAuthority", "getTrustedHostInfo"), _params2, _returnDesc2, _faults2, "getTrustedHostInfo");
        _getTrustedHostInfoOperation2.setOption("inputMessageQName",com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:attAuthority", "getTrustedHostInfoInputMsg"));
        _getTrustedHostInfoOperation2.setOption("targetNamespace","urn:ndg:security:attAuthority");
        _getTrustedHostInfoOperation2.setOption("buildNum","b0619.25");
        _getTrustedHostInfoOperation2.setOption("ServiceQName",com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:attAuthority", "AttAuthorityService"));
        _getTrustedHostInfoOperation2.setOption("outputMessageQName",com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:attAuthority", "getTrustedHostInfoOutputMsg"));
        _getTrustedHostInfoOperation2.setOption("portTypeQName",com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:attAuthority", "AttAuthority"));
        _getTrustedHostInfoOperation2.setUse(com.ibm.ws.webservices.engine.enumtype.Use.LITERAL);
        _getTrustedHostInfoOperation2.setStyle(com.ibm.ws.webservices.engine.enumtype.Style.WRAPPED);
    }

    private int _getTrustedHostInfoIndex2 = 2;
    private synchronized com.ibm.ws.webservices.engine.client.Stub.Invoke _getgetTrustedHostInfoInvoke2(Object[] parameters) throws com.ibm.ws.webservices.engine.WebServicesFault  {
        com.ibm.ws.webservices.engine.MessageContext mc = super.messageContexts[_getTrustedHostInfoIndex2];
        if (mc == null) {
            mc = new com.ibm.ws.webservices.engine.MessageContext(super.engine);
            mc.setOperation(AttAuthorityBindingStub._getTrustedHostInfoOperation2);
            mc.setUseSOAPAction(true);
            mc.setSOAPActionURI("getTrustedHostInfo");
            mc.setEncodingStyle(com.ibm.ws.webservices.engine.Constants.URI_LITERAL_ENC);
            mc.setProperty(com.ibm.ws.webservices.engine.client.Call.SEND_TYPE_ATTR, Boolean.FALSE);
            mc.setProperty(com.ibm.ws.webservices.engine.WebServicesEngine.PROP_DOMULTIREFS, Boolean.FALSE);
            super.primeMessageContext(mc);
            super.messageContexts[_getTrustedHostInfoIndex2] = mc;
        }
        try {
            mc = (com.ibm.ws.webservices.engine.MessageContext) mc.clone();
        }
        catch (CloneNotSupportedException cnse) {
            throw com.ibm.ws.webservices.engine.WebServicesFault.makeFault(cnse);
        }
        return new com.ibm.ws.webservices.engine.client.Stub.Invoke(connection, mc, parameters);
    }

    public ndg.security.attAuthority.HostInfo[] getTrustedHostInfo(java.lang.String role) throws java.rmi.RemoteException {
        if (super.cachedEndpoint == null) {
            throw new com.ibm.ws.webservices.engine.NoEndPointException();
        }
        java.util.Vector _resp = null;
        try {
            _resp = _getgetTrustedHostInfoInvoke2(new java.lang.Object[] {role}).invoke();

        } catch (com.ibm.ws.webservices.engine.WebServicesFault wsf) {
            Exception e = wsf.getUserException();
            throw wsf;
        } 
        try {
            return (ndg.security.attAuthority.HostInfo[]) ((com.ibm.ws.webservices.engine.xmlsoap.ext.ParamValue) _resp.get(0)).getValue();
        } catch (java.lang.Exception _exception) {
            return (ndg.security.attAuthority.HostInfo[]) super.convert(((com.ibm.ws.webservices.engine.xmlsoap.ext.ParamValue) _resp.get(0)).getValue(), ndg.security.attAuthority.HostInfo[].class);
        }
    }

    private static final com.ibm.ws.webservices.engine.description.OperationDesc _getX509CertOperation3;
    static {
        com.ibm.ws.webservices.engine.description.ParameterDesc[]  _params3 = new com.ibm.ws.webservices.engine.description.ParameterDesc[] {
          };
        com.ibm.ws.webservices.engine.description.ParameterDesc  _returnDesc3 = new com.ibm.ws.webservices.engine.description.ParameterDesc(com.ibm.ws.webservices.engine.utils.QNameTable.createQName("", "x509Cert"), com.ibm.ws.webservices.engine.description.ParameterDesc.OUT, com.ibm.ws.webservices.engine.utils.QNameTable.createQName("http://www.w3.org/2001/XMLSchema", "string"), java.lang.String.class, true, false, false, false, true, false); 
        _returnDesc3.setOption("partName","string");
        _returnDesc3.setOption("partQNameString","{http://www.w3.org/2001/XMLSchema}string");
        com.ibm.ws.webservices.engine.description.FaultDesc[]  _faults3 = new com.ibm.ws.webservices.engine.description.FaultDesc[] {
          };
        _getX509CertOperation3 = new com.ibm.ws.webservices.engine.description.OperationDesc("getX509Cert", com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:attAuthority", "getX509Cert"), _params3, _returnDesc3, _faults3, "getX509Cert");
        _getX509CertOperation3.setOption("inputMessageQName",com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:attAuthority", "getX509CertInputMsg"));
        _getX509CertOperation3.setOption("targetNamespace","urn:ndg:security:attAuthority");
        _getX509CertOperation3.setOption("buildNum","b0619.25");
        _getX509CertOperation3.setOption("ServiceQName",com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:attAuthority", "AttAuthorityService"));
        _getX509CertOperation3.setOption("outputMessageQName",com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:attAuthority", "getX509CertOutputMsg"));
        _getX509CertOperation3.setOption("portTypeQName",com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:attAuthority", "AttAuthority"));
        _getX509CertOperation3.setUse(com.ibm.ws.webservices.engine.enumtype.Use.LITERAL);
        _getX509CertOperation3.setStyle(com.ibm.ws.webservices.engine.enumtype.Style.WRAPPED);
    }

    private int _getX509CertIndex3 = 3;
    private synchronized com.ibm.ws.webservices.engine.client.Stub.Invoke _getgetX509CertInvoke3(Object[] parameters) throws com.ibm.ws.webservices.engine.WebServicesFault  {
        com.ibm.ws.webservices.engine.MessageContext mc = super.messageContexts[_getX509CertIndex3];
        if (mc == null) {
            mc = new com.ibm.ws.webservices.engine.MessageContext(super.engine);
            mc.setOperation(AttAuthorityBindingStub._getX509CertOperation3);
            mc.setUseSOAPAction(true);
            mc.setSOAPActionURI("getX509Cert");
            mc.setEncodingStyle(com.ibm.ws.webservices.engine.Constants.URI_LITERAL_ENC);
            mc.setProperty(com.ibm.ws.webservices.engine.client.Call.SEND_TYPE_ATTR, Boolean.FALSE);
            mc.setProperty(com.ibm.ws.webservices.engine.WebServicesEngine.PROP_DOMULTIREFS, Boolean.FALSE);
            super.primeMessageContext(mc);
            super.messageContexts[_getX509CertIndex3] = mc;
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
            _resp = _getgetX509CertInvoke3(new java.lang.Object[] {}).invoke();

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
