/**
 * SessionMgrServiceInformation.java
 *
 * This file was auto-generated from WSDL
 * by the IBM Web services WSDL2Java emitter.
 * b0619.25 v51306165058
 */

package ndg.security.sessionMgr;

public class SessionMgrServiceInformation implements com.ibm.ws.webservices.multiprotocol.ServiceInformation {

     // NERC Data Grid Session Manager web service

    private static java.util.Map operationDescriptions;
    private static java.util.Map typeMappings;

    static {
         initOperationDescriptions();
         initTypeMappings();
    }

    private static void initOperationDescriptions() { 
        operationDescriptions = new java.util.HashMap();

        java.util.Map inner0 = new java.util.HashMap();

        java.util.List list0 = new java.util.ArrayList();
        inner0.put("addUser", list0);

        com.ibm.ws.webservices.engine.description.OperationDesc addUser0Op = _addUser0Op();
        list0.add(addUser0Op);

        java.util.List list1 = new java.util.ArrayList();
        inner0.put("connect", list1);

        com.ibm.ws.webservices.engine.description.OperationDesc connect1Op = _connect1Op();
        list1.add(connect1Op);

        java.util.List list2 = new java.util.ArrayList();
        inner0.put("disconnect", list2);

        com.ibm.ws.webservices.engine.description.OperationDesc disconnect2Op = _disconnect2Op();
        list2.add(disconnect2Op);

        java.util.List list3 = new java.util.ArrayList();
        inner0.put("getAttCert", list3);

        com.ibm.ws.webservices.engine.description.OperationDesc getAttCert3Op = _getAttCert3Op();
        list3.add(getAttCert3Op);

        java.util.List list4 = new java.util.ArrayList();
        inner0.put("getX509Cert", list4);

        com.ibm.ws.webservices.engine.description.OperationDesc getX509Cert4Op = _getX509Cert4Op();
        list4.add(getX509Cert4Op);

        operationDescriptions.put("SessionMgr",inner0);
        operationDescriptions = java.util.Collections.unmodifiableMap(operationDescriptions);
    }

    private static com.ibm.ws.webservices.engine.description.OperationDesc _addUser0Op() {
        com.ibm.ws.webservices.engine.description.OperationDesc addUser0Op = null;
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
        addUser0Op = new com.ibm.ws.webservices.engine.description.OperationDesc("addUser", com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:sessionMgr", "addUser"), _params0, _returnDesc0, _faults0, null);
        addUser0Op.setOption("inputMessageQName",com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:sessionMgr", "addUserInputMsg"));
        addUser0Op.setOption("targetNamespace","urn:ndg:security:sessionMgr");
        addUser0Op.setOption("buildNum","b0619.25");
        addUser0Op.setOption("ServiceQName",com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:sessionMgr", "SessionMgrService"));
        addUser0Op.setOption("outputMessageQName",com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:sessionMgr", "addUserOutputMsg"));
        addUser0Op.setOption("portTypeQName",com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:sessionMgr", "SessionMgr"));
        addUser0Op.setStyle(com.ibm.ws.webservices.engine.enumtype.Style.WRAPPED);
        return addUser0Op;

    }

    private static com.ibm.ws.webservices.engine.description.OperationDesc _connect1Op() {
        com.ibm.ws.webservices.engine.description.OperationDesc connect1Op = null;
        com.ibm.ws.webservices.engine.description.ParameterDesc[]  _params0 = new com.ibm.ws.webservices.engine.description.ParameterDesc[] {
         new com.ibm.ws.webservices.engine.description.ParameterDesc(com.ibm.ws.webservices.engine.utils.QNameTable.createQName("", "username"), com.ibm.ws.webservices.engine.description.ParameterDesc.IN, com.ibm.ws.webservices.engine.utils.QNameTable.createQName("http://www.w3.org/2001/XMLSchema", "string"), java.lang.String.class, false, false, false, false, true, false), 
         new com.ibm.ws.webservices.engine.description.ParameterDesc(com.ibm.ws.webservices.engine.utils.QNameTable.createQName("", "passphrase"), com.ibm.ws.webservices.engine.description.ParameterDesc.IN, com.ibm.ws.webservices.engine.utils.QNameTable.createQName("http://www.w3.org/2001/XMLSchema", "string"), java.lang.String.class, false, false, false, false, true, false), 
         new com.ibm.ws.webservices.engine.description.ParameterDesc(com.ibm.ws.webservices.engine.utils.QNameTable.createQName("", "createServerSess"), com.ibm.ws.webservices.engine.description.ParameterDesc.IN, com.ibm.ws.webservices.engine.utils.QNameTable.createQName("http://www.w3.org/2001/XMLSchema", "boolean"), boolean.class, false, false, false, false, true, false), 
         new com.ibm.ws.webservices.engine.description.ParameterDesc(com.ibm.ws.webservices.engine.utils.QNameTable.createQName("", "getCookie"), com.ibm.ws.webservices.engine.description.ParameterDesc.IN, com.ibm.ws.webservices.engine.utils.QNameTable.createQName("http://www.w3.org/2001/XMLSchema", "boolean"), boolean.class, false, false, false, false, true, false), 
         new com.ibm.ws.webservices.engine.description.ParameterDesc(com.ibm.ws.webservices.engine.utils.QNameTable.createQName("", "proxyCert"), com.ibm.ws.webservices.engine.description.ParameterDesc.OUT, com.ibm.ws.webservices.engine.utils.QNameTable.createQName("http://www.w3.org/2001/XMLSchema", "string"), java.lang.String.class, false, false, false, false, true, false), 
         new com.ibm.ws.webservices.engine.description.ParameterDesc(com.ibm.ws.webservices.engine.utils.QNameTable.createQName("", "proxyPriKey"), com.ibm.ws.webservices.engine.description.ParameterDesc.OUT, com.ibm.ws.webservices.engine.utils.QNameTable.createQName("http://www.w3.org/2001/XMLSchema", "string"), java.lang.String.class, false, false, false, false, true, false), 
         new com.ibm.ws.webservices.engine.description.ParameterDesc(com.ibm.ws.webservices.engine.utils.QNameTable.createQName("", "userCert"), com.ibm.ws.webservices.engine.description.ParameterDesc.OUT, com.ibm.ws.webservices.engine.utils.QNameTable.createQName("http://www.w3.org/2001/XMLSchema", "string"), java.lang.String.class, false, false, false, false, true, false), 
         new com.ibm.ws.webservices.engine.description.ParameterDesc(com.ibm.ws.webservices.engine.utils.QNameTable.createQName("", "cookie"), com.ibm.ws.webservices.engine.description.ParameterDesc.OUT, com.ibm.ws.webservices.engine.utils.QNameTable.createQName("http://www.w3.org/2001/XMLSchema", "string"), java.lang.String.class, false, false, false, true, true, false), 
          };
        _params0[0].setOption("partName","string");
        _params0[0].setOption("partQNameString","{http://www.w3.org/2001/XMLSchema}string");
        _params0[1].setOption("partName","string");
        _params0[1].setOption("partQNameString","{http://www.w3.org/2001/XMLSchema}string");
        _params0[2].setOption("partName","boolean");
        _params0[2].setOption("partQNameString","{http://www.w3.org/2001/XMLSchema}boolean");
        _params0[3].setOption("partName","boolean");
        _params0[3].setOption("partQNameString","{http://www.w3.org/2001/XMLSchema}boolean");
        _params0[4].setOption("partName","string");
        _params0[4].setOption("partQNameString","{http://www.w3.org/2001/XMLSchema}string");
        _params0[5].setOption("partName","string");
        _params0[5].setOption("partQNameString","{http://www.w3.org/2001/XMLSchema}string");
        _params0[6].setOption("partName","string");
        _params0[6].setOption("partQNameString","{http://www.w3.org/2001/XMLSchema}string");
        _params0[7].setOption("partName","string");
        _params0[7].setOption("partQNameString","{http://www.w3.org/2001/XMLSchema}string");
        com.ibm.ws.webservices.engine.description.ParameterDesc  _returnDesc0 = new com.ibm.ws.webservices.engine.description.ParameterDesc(null, com.ibm.ws.webservices.engine.description.ParameterDesc.OUT, com.ibm.ws.webservices.engine.utils.QNameTable.createQName("http://websphere.ibm.com/webservices/", "Void"), void.class, true, false, false, false, true, true); 
        com.ibm.ws.webservices.engine.description.FaultDesc[]  _faults0 = new com.ibm.ws.webservices.engine.description.FaultDesc[] {
          };
        connect1Op = new com.ibm.ws.webservices.engine.description.OperationDesc("connect", com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:sessionMgr", "connect"), _params0, _returnDesc0, _faults0, null);
        connect1Op.setOption("inputMessageQName",com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:sessionMgr", "connectInputMsg"));
        connect1Op.setOption("targetNamespace","urn:ndg:security:sessionMgr");
        connect1Op.setOption("buildNum","b0619.25");
        connect1Op.setOption("ServiceQName",com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:sessionMgr", "SessionMgrService"));
        connect1Op.setOption("outputMessageQName",com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:sessionMgr", "connectOutputMsg"));
        connect1Op.setOption("portTypeQName",com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:sessionMgr", "SessionMgr"));
        connect1Op.setStyle(com.ibm.ws.webservices.engine.enumtype.Style.WRAPPED);
        return connect1Op;

    }

    private static com.ibm.ws.webservices.engine.description.OperationDesc _disconnect2Op() {
        com.ibm.ws.webservices.engine.description.OperationDesc disconnect2Op = null;
        com.ibm.ws.webservices.engine.description.ParameterDesc[]  _params0 = new com.ibm.ws.webservices.engine.description.ParameterDesc[] {
         new com.ibm.ws.webservices.engine.description.ParameterDesc(com.ibm.ws.webservices.engine.utils.QNameTable.createQName("", "userCert"), com.ibm.ws.webservices.engine.description.ParameterDesc.IN, com.ibm.ws.webservices.engine.utils.QNameTable.createQName("http://www.w3.org/2001/XMLSchema", "string"), java.lang.String.class, false, false, false, true, true, false), 
         new com.ibm.ws.webservices.engine.description.ParameterDesc(com.ibm.ws.webservices.engine.utils.QNameTable.createQName("", "sessID"), com.ibm.ws.webservices.engine.description.ParameterDesc.IN, com.ibm.ws.webservices.engine.utils.QNameTable.createQName("http://www.w3.org/2001/XMLSchema", "string"), java.lang.String.class, false, false, false, true, true, false), 
         new com.ibm.ws.webservices.engine.description.ParameterDesc(com.ibm.ws.webservices.engine.utils.QNameTable.createQName("", "encrSessionMgrURI"), com.ibm.ws.webservices.engine.description.ParameterDesc.IN, com.ibm.ws.webservices.engine.utils.QNameTable.createQName("http://www.w3.org/2001/XMLSchema", "string"), java.lang.String.class, false, false, false, true, true, false), 
          };
        _params0[0].setOption("partName","string");
        _params0[0].setOption("partQNameString","{http://www.w3.org/2001/XMLSchema}string");
        _params0[1].setOption("partName","string");
        _params0[1].setOption("partQNameString","{http://www.w3.org/2001/XMLSchema}string");
        _params0[2].setOption("partName","string");
        _params0[2].setOption("partQNameString","{http://www.w3.org/2001/XMLSchema}string");
        com.ibm.ws.webservices.engine.description.ParameterDesc  _returnDesc0 = new com.ibm.ws.webservices.engine.description.ParameterDesc(null, com.ibm.ws.webservices.engine.description.ParameterDesc.OUT, com.ibm.ws.webservices.engine.utils.QNameTable.createQName("http://websphere.ibm.com/webservices/", "Void"), void.class, true, false, false, false, true, true); 
        com.ibm.ws.webservices.engine.description.FaultDesc[]  _faults0 = new com.ibm.ws.webservices.engine.description.FaultDesc[] {
          };
        disconnect2Op = new com.ibm.ws.webservices.engine.description.OperationDesc("disconnect", com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:sessionMgr", "disconnect"), _params0, _returnDesc0, _faults0, null);
        disconnect2Op.setOption("inputMessageQName",com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:sessionMgr", "disconnectInputMsg"));
        disconnect2Op.setOption("targetNamespace","urn:ndg:security:sessionMgr");
        disconnect2Op.setOption("buildNum","b0619.25");
        disconnect2Op.setOption("ServiceQName",com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:sessionMgr", "SessionMgrService"));
        disconnect2Op.setOption("outputMessageQName",com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:sessionMgr", "disconnectOutputMsg"));
        disconnect2Op.setOption("portTypeQName",com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:sessionMgr", "SessionMgr"));
        disconnect2Op.setStyle(com.ibm.ws.webservices.engine.enumtype.Style.WRAPPED);
        return disconnect2Op;

    }

    private static com.ibm.ws.webservices.engine.description.OperationDesc _getAttCert3Op() {
        com.ibm.ws.webservices.engine.description.OperationDesc getAttCert3Op = null;
        com.ibm.ws.webservices.engine.description.ParameterDesc[]  _params0 = new com.ibm.ws.webservices.engine.description.ParameterDesc[] {
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
        _params0[0].setOption("partName","string");
        _params0[0].setOption("partQNameString","{http://www.w3.org/2001/XMLSchema}string");
        _params0[1].setOption("partName","string");
        _params0[1].setOption("partQNameString","{http://www.w3.org/2001/XMLSchema}string");
        _params0[2].setOption("partName","string");
        _params0[2].setOption("partQNameString","{http://www.w3.org/2001/XMLSchema}string");
        _params0[3].setOption("partName","string");
        _params0[3].setOption("partQNameString","{http://www.w3.org/2001/XMLSchema}string");
        _params0[4].setOption("partName","string");
        _params0[4].setOption("partQNameString","{http://www.w3.org/2001/XMLSchema}string");
        _params0[5].setOption("partName","string");
        _params0[5].setOption("partQNameString","{http://www.w3.org/2001/XMLSchema}string");
        _params0[6].setOption("partName","boolean");
        _params0[6].setOption("partQNameString","{http://www.w3.org/2001/XMLSchema}boolean");
        _params0[7].setOption("partName","boolean");
        _params0[7].setOption("partQNameString","{http://www.w3.org/2001/XMLSchema}boolean");
        _params0[8].setOption("partName","string[0,unbounded]");
        _params0[8].setOption("partQNameString","{http://www.w3.org/2001/XMLSchema}string[0,unbounded]");
        _params0[9].setOption("partName","string[0,unbounded]");
        _params0[9].setOption("partQNameString","{http://www.w3.org/2001/XMLSchema}string[0,unbounded]");
        _params0[10].setOption("partName","string");
        _params0[10].setOption("partQNameString","{http://www.w3.org/2001/XMLSchema}string");
        _params0[11].setOption("partName","string");
        _params0[11].setOption("partQNameString","{http://www.w3.org/2001/XMLSchema}string");
        _params0[12].setOption("partName","string[0,unbounded]");
        _params0[12].setOption("partQNameString","{http://www.w3.org/2001/XMLSchema}string[0,unbounded]");
        com.ibm.ws.webservices.engine.description.ParameterDesc  _returnDesc0 = new com.ibm.ws.webservices.engine.description.ParameterDesc(null, com.ibm.ws.webservices.engine.description.ParameterDesc.OUT, com.ibm.ws.webservices.engine.utils.QNameTable.createQName("http://websphere.ibm.com/webservices/", "Void"), void.class, true, false, false, false, true, true); 
        com.ibm.ws.webservices.engine.description.FaultDesc[]  _faults0 = new com.ibm.ws.webservices.engine.description.FaultDesc[] {
          };
        getAttCert3Op = new com.ibm.ws.webservices.engine.description.OperationDesc("getAttCert", com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:sessionMgr", "getAttCert"), _params0, _returnDesc0, _faults0, null);
        getAttCert3Op.setOption("inputMessageQName",com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:sessionMgr", "getAttCertInputMsg"));
        getAttCert3Op.setOption("targetNamespace","urn:ndg:security:sessionMgr");
        getAttCert3Op.setOption("buildNum","b0619.25");
        getAttCert3Op.setOption("ServiceQName",com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:sessionMgr", "SessionMgrService"));
        getAttCert3Op.setOption("outputMessageQName",com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:sessionMgr", "getAttCertOutputMsg"));
        getAttCert3Op.setOption("portTypeQName",com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:sessionMgr", "SessionMgr"));
        getAttCert3Op.setStyle(com.ibm.ws.webservices.engine.enumtype.Style.WRAPPED);
        return getAttCert3Op;

    }

    private static com.ibm.ws.webservices.engine.description.OperationDesc _getX509Cert4Op() {
        com.ibm.ws.webservices.engine.description.OperationDesc getX509Cert4Op = null;
        com.ibm.ws.webservices.engine.description.ParameterDesc[]  _params0 = new com.ibm.ws.webservices.engine.description.ParameterDesc[] {
          };
        com.ibm.ws.webservices.engine.description.ParameterDesc  _returnDesc0 = new com.ibm.ws.webservices.engine.description.ParameterDesc(com.ibm.ws.webservices.engine.utils.QNameTable.createQName("", "x509Cert"), com.ibm.ws.webservices.engine.description.ParameterDesc.OUT, com.ibm.ws.webservices.engine.utils.QNameTable.createQName("http://www.w3.org/2001/XMLSchema", "string"), java.lang.String.class, true, false, false, false, true, false); 
        _returnDesc0.setOption("partName","string");
        _returnDesc0.setOption("partQNameString","{http://www.w3.org/2001/XMLSchema}string");
        com.ibm.ws.webservices.engine.description.FaultDesc[]  _faults0 = new com.ibm.ws.webservices.engine.description.FaultDesc[] {
          };
        getX509Cert4Op = new com.ibm.ws.webservices.engine.description.OperationDesc("getX509Cert", com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:sessionMgr", "getX509Cert"), _params0, _returnDesc0, _faults0, null);
        getX509Cert4Op.setOption("inputMessageQName",com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:sessionMgr", "getX509CertInputMsg"));
        getX509Cert4Op.setOption("targetNamespace","urn:ndg:security:sessionMgr");
        getX509Cert4Op.setOption("buildNum","b0619.25");
        getX509Cert4Op.setOption("ServiceQName",com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:sessionMgr", "SessionMgrService"));
        getX509Cert4Op.setOption("outputMessageQName",com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:sessionMgr", "getX509CertOutputMsg"));
        getX509Cert4Op.setOption("portTypeQName",com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:sessionMgr", "SessionMgr"));
        getX509Cert4Op.setStyle(com.ibm.ws.webservices.engine.enumtype.Style.WRAPPED);
        return getX509Cert4Op;

    }


    private static void initTypeMappings() {
        typeMappings = new java.util.HashMap();
        typeMappings = java.util.Collections.unmodifiableMap(typeMappings);
    }

    public java.util.Map getTypeMappings() {
        return typeMappings;
    }

    public Class getJavaType(javax.xml.namespace.QName xmlName) {
        return (Class) typeMappings.get(xmlName);
    }

    public java.util.Map getOperationDescriptions(String portName) {
        return (java.util.Map) operationDescriptions.get(portName);
    }

    public java.util.List getOperationDescriptions(String portName, String operationName) {
        java.util.Map map = (java.util.Map) operationDescriptions.get(portName);
        if (map != null) {
            return (java.util.List) map.get(operationName);
        }
        return null;
    }

}
