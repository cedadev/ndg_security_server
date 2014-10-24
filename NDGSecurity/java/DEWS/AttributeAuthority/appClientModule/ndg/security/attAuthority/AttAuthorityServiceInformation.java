/**
 * AttAuthorityServiceInformation.java
 *
 * This file was auto-generated from WSDL
 * by the IBM Web services WSDL2Java emitter.
 * b0619.25 v51306165058
 */

package ndg.security.attAuthority;

public class AttAuthorityServiceInformation implements com.ibm.ws.webservices.multiprotocol.ServiceInformation {

     // NERC Data Grid Attribute Authority web service

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
        inner0.put("getAttCert", list0);

        com.ibm.ws.webservices.engine.description.OperationDesc getAttCert0Op = _getAttCert0Op();
        list0.add(getAttCert0Op);

        java.util.List list1 = new java.util.ArrayList();
        inner0.put("getHostInfo", list1);

        com.ibm.ws.webservices.engine.description.OperationDesc getHostInfo1Op = _getHostInfo1Op();
        list1.add(getHostInfo1Op);

        java.util.List list2 = new java.util.ArrayList();
        inner0.put("getTrustedHostInfo", list2);

        com.ibm.ws.webservices.engine.description.OperationDesc getTrustedHostInfo2Op = _getTrustedHostInfo2Op();
        list2.add(getTrustedHostInfo2Op);

        java.util.List list3 = new java.util.ArrayList();
        inner0.put("getX509Cert", list3);

        com.ibm.ws.webservices.engine.description.OperationDesc getX509Cert3Op = _getX509Cert3Op();
        list3.add(getX509Cert3Op);

        operationDescriptions.put("AttAuthority",inner0);
        operationDescriptions = java.util.Collections.unmodifiableMap(operationDescriptions);
    }

    private static com.ibm.ws.webservices.engine.description.OperationDesc _getAttCert0Op() {
        com.ibm.ws.webservices.engine.description.OperationDesc getAttCert0Op = null;
        com.ibm.ws.webservices.engine.description.ParameterDesc[]  _params0 = new com.ibm.ws.webservices.engine.description.ParameterDesc[] {
         new com.ibm.ws.webservices.engine.description.ParameterDesc(com.ibm.ws.webservices.engine.utils.QNameTable.createQName("", "userId"), com.ibm.ws.webservices.engine.description.ParameterDesc.IN, com.ibm.ws.webservices.engine.utils.QNameTable.createQName("http://www.w3.org/2001/XMLSchema", "string"), java.lang.String.class, false, false, false, true, true, false), 
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
        _params0[4].setOption("partName","string");
        _params0[4].setOption("partQNameString","{http://www.w3.org/2001/XMLSchema}string");
        com.ibm.ws.webservices.engine.description.ParameterDesc  _returnDesc0 = new com.ibm.ws.webservices.engine.description.ParameterDesc(null, com.ibm.ws.webservices.engine.description.ParameterDesc.OUT, com.ibm.ws.webservices.engine.utils.QNameTable.createQName("http://websphere.ibm.com/webservices/", "Void"), void.class, true, false, false, false, true, true); 
        com.ibm.ws.webservices.engine.description.FaultDesc[]  _faults0 = new com.ibm.ws.webservices.engine.description.FaultDesc[] {
          };
        getAttCert0Op = new com.ibm.ws.webservices.engine.description.OperationDesc("getAttCert", com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:attAuthority", "getAttCert"), _params0, _returnDesc0, _faults0, null);
        getAttCert0Op.setOption("inputMessageQName",com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:attAuthority", "getAttCertInputMsg"));
        getAttCert0Op.setOption("targetNamespace","urn:ndg:security:attAuthority");
        getAttCert0Op.setOption("buildNum","b0619.25");
        getAttCert0Op.setOption("ServiceQName",com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:attAuthority", "AttAuthorityService"));
        getAttCert0Op.setOption("outputMessageQName",com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:attAuthority", "getAttCertOutputMsg"));
        getAttCert0Op.setOption("portTypeQName",com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:attAuthority", "AttAuthority"));
        getAttCert0Op.setStyle(com.ibm.ws.webservices.engine.enumtype.Style.WRAPPED);
        return getAttCert0Op;

    }

    private static com.ibm.ws.webservices.engine.description.OperationDesc _getHostInfo1Op() {
        com.ibm.ws.webservices.engine.description.OperationDesc getHostInfo1Op = null;
        com.ibm.ws.webservices.engine.description.ParameterDesc[]  _params0 = new com.ibm.ws.webservices.engine.description.ParameterDesc[] {
         new com.ibm.ws.webservices.engine.description.ParameterDesc(com.ibm.ws.webservices.engine.utils.QNameTable.createQName("", "hostname"), com.ibm.ws.webservices.engine.description.ParameterDesc.OUT, com.ibm.ws.webservices.engine.utils.QNameTable.createQName("http://www.w3.org/2001/XMLSchema", "string"), java.lang.String.class, false, false, false, false, true, false), 
         new com.ibm.ws.webservices.engine.description.ParameterDesc(com.ibm.ws.webservices.engine.utils.QNameTable.createQName("", "aaURI"), com.ibm.ws.webservices.engine.description.ParameterDesc.OUT, com.ibm.ws.webservices.engine.utils.QNameTable.createQName("http://www.w3.org/2001/XMLSchema", "string"), java.lang.String.class, false, false, false, false, true, false), 
         new com.ibm.ws.webservices.engine.description.ParameterDesc(com.ibm.ws.webservices.engine.utils.QNameTable.createQName("", "loginURI"), com.ibm.ws.webservices.engine.description.ParameterDesc.OUT, com.ibm.ws.webservices.engine.utils.QNameTable.createQName("http://www.w3.org/2001/XMLSchema", "string"), java.lang.String.class, false, false, false, false, true, false), 
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
        getHostInfo1Op = new com.ibm.ws.webservices.engine.description.OperationDesc("getHostInfo", com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:attAuthority", "getHostInfo"), _params0, _returnDesc0, _faults0, null);
        getHostInfo1Op.setOption("inputMessageQName",com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:attAuthority", "getHostInfoInputMsg"));
        getHostInfo1Op.setOption("targetNamespace","urn:ndg:security:attAuthority");
        getHostInfo1Op.setOption("buildNum","b0619.25");
        getHostInfo1Op.setOption("ServiceQName",com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:attAuthority", "AttAuthorityService"));
        getHostInfo1Op.setOption("outputMessageQName",com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:attAuthority", "getHostInfoOutputMsg"));
        getHostInfo1Op.setOption("portTypeQName",com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:attAuthority", "AttAuthority"));
        getHostInfo1Op.setStyle(com.ibm.ws.webservices.engine.enumtype.Style.WRAPPED);
        return getHostInfo1Op;

    }

    private static com.ibm.ws.webservices.engine.description.OperationDesc _getTrustedHostInfo2Op() {
        com.ibm.ws.webservices.engine.description.OperationDesc getTrustedHostInfo2Op = null;
        com.ibm.ws.webservices.engine.description.ParameterDesc[]  _params0 = new com.ibm.ws.webservices.engine.description.ParameterDesc[] {
         new com.ibm.ws.webservices.engine.description.ParameterDesc(com.ibm.ws.webservices.engine.utils.QNameTable.createQName("", "role"), com.ibm.ws.webservices.engine.description.ParameterDesc.IN, com.ibm.ws.webservices.engine.utils.QNameTable.createQName("http://www.w3.org/2001/XMLSchema", "string"), java.lang.String.class, false, false, false, true, true, false), 
          };
        _params0[0].setOption("partName","string");
        _params0[0].setOption("partQNameString","{http://www.w3.org/2001/XMLSchema}string");
        com.ibm.ws.webservices.engine.description.ParameterDesc  _returnDesc0 = new com.ibm.ws.webservices.engine.description.ParameterDesc(com.ibm.ws.webservices.engine.utils.QNameTable.createQName("", "trustedHosts"), com.ibm.ws.webservices.engine.description.ParameterDesc.OUT, com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:attAuthority", "HostInfo"), ndg.security.attAuthority.HostInfo[].class, true, false, false, true, false, false); 
        _returnDesc0.setOption("partName","HostInfo[0,unbounded]");
        _returnDesc0.setOption("partQNameString","{urn:ndg:security:attAuthority}HostInfo[0,unbounded]");
        com.ibm.ws.webservices.engine.description.FaultDesc[]  _faults0 = new com.ibm.ws.webservices.engine.description.FaultDesc[] {
          };
        getTrustedHostInfo2Op = new com.ibm.ws.webservices.engine.description.OperationDesc("getTrustedHostInfo", com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:attAuthority", "getTrustedHostInfo"), _params0, _returnDesc0, _faults0, null);
        getTrustedHostInfo2Op.setOption("inputMessageQName",com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:attAuthority", "getTrustedHostInfoInputMsg"));
        getTrustedHostInfo2Op.setOption("targetNamespace","urn:ndg:security:attAuthority");
        getTrustedHostInfo2Op.setOption("buildNum","b0619.25");
        getTrustedHostInfo2Op.setOption("ServiceQName",com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:attAuthority", "AttAuthorityService"));
        getTrustedHostInfo2Op.setOption("outputMessageQName",com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:attAuthority", "getTrustedHostInfoOutputMsg"));
        getTrustedHostInfo2Op.setOption("portTypeQName",com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:attAuthority", "AttAuthority"));
        getTrustedHostInfo2Op.setStyle(com.ibm.ws.webservices.engine.enumtype.Style.WRAPPED);
        return getTrustedHostInfo2Op;

    }

    private static com.ibm.ws.webservices.engine.description.OperationDesc _getX509Cert3Op() {
        com.ibm.ws.webservices.engine.description.OperationDesc getX509Cert3Op = null;
        com.ibm.ws.webservices.engine.description.ParameterDesc[]  _params0 = new com.ibm.ws.webservices.engine.description.ParameterDesc[] {
          };
        com.ibm.ws.webservices.engine.description.ParameterDesc  _returnDesc0 = new com.ibm.ws.webservices.engine.description.ParameterDesc(com.ibm.ws.webservices.engine.utils.QNameTable.createQName("", "x509Cert"), com.ibm.ws.webservices.engine.description.ParameterDesc.OUT, com.ibm.ws.webservices.engine.utils.QNameTable.createQName("http://www.w3.org/2001/XMLSchema", "string"), java.lang.String.class, true, false, false, false, true, false); 
        _returnDesc0.setOption("partName","string");
        _returnDesc0.setOption("partQNameString","{http://www.w3.org/2001/XMLSchema}string");
        com.ibm.ws.webservices.engine.description.FaultDesc[]  _faults0 = new com.ibm.ws.webservices.engine.description.FaultDesc[] {
          };
        getX509Cert3Op = new com.ibm.ws.webservices.engine.description.OperationDesc("getX509Cert", com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:attAuthority", "getX509Cert"), _params0, _returnDesc0, _faults0, null);
        getX509Cert3Op.setOption("inputMessageQName",com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:attAuthority", "getX509CertInputMsg"));
        getX509Cert3Op.setOption("targetNamespace","urn:ndg:security:attAuthority");
        getX509Cert3Op.setOption("buildNum","b0619.25");
        getX509Cert3Op.setOption("ServiceQName",com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:attAuthority", "AttAuthorityService"));
        getX509Cert3Op.setOption("outputMessageQName",com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:attAuthority", "getX509CertOutputMsg"));
        getX509Cert3Op.setOption("portTypeQName",com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:attAuthority", "AttAuthority"));
        getX509Cert3Op.setStyle(com.ibm.ws.webservices.engine.enumtype.Style.WRAPPED);
        return getX509Cert3Op;

    }


    private static void initTypeMappings() {
        typeMappings = new java.util.HashMap();
        typeMappings.put(com.ibm.ws.webservices.engine.utils.QNameTable.createQName("urn:ndg:security:attAuthority", "HostInfo"),
                         ndg.security.attAuthority.HostInfo.class);

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
