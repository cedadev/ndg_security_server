package ndg.security;

public class SessionMgrProxy implements ndg.security.SessionMgr {
  private boolean _useJNDI = true;
  private String _endpoint = null;
  private ndg.security.SessionMgr __sessionMgr = null;
  
  public SessionMgrProxy() {
    _initSessionMgrProxy();
  }
  
  private void _initSessionMgrProxy() {
  
  if (_useJNDI) {
    try{
      javax.naming.InitialContext ctx = new javax.naming.InitialContext();
      __sessionMgr = ((ndg.security.SessionMgrService)ctx.lookup("java:comp/env/service/SessionMgrService")).getSessionMgr();
      }
    catch (javax.naming.NamingException namingException) {}
    catch (javax.xml.rpc.ServiceException serviceException) {}
  }
  if (__sessionMgr == null) {
    try{
      __sessionMgr = (new ndg.security.SessionMgrServiceLocator()).getSessionMgr();
      }
    catch (javax.xml.rpc.ServiceException serviceException) {}
  }
  if (__sessionMgr != null) {
    if (_endpoint != null)
      ((javax.xml.rpc.Stub)__sessionMgr)._setProperty("javax.xml.rpc.service.endpoint.address", _endpoint);
    else
      _endpoint = (String)((javax.xml.rpc.Stub)__sessionMgr)._getProperty("javax.xml.rpc.service.endpoint.address");
  }
  
}


public void useJNDI(boolean useJNDI) {
  _useJNDI = useJNDI;
  __sessionMgr = null;
  
}

public String getEndpoint() {
  return _endpoint;
}

public void setEndpoint(String endpoint) {
  _endpoint = endpoint;
  if (__sessionMgr != null)
    ((javax.xml.rpc.Stub)__sessionMgr)._setProperty("javax.xml.rpc.service.endpoint.address", _endpoint);
  
}

public ndg.security.SessionMgr getSessionMgr() {
  if (__sessionMgr == null)
    _initSessionMgrProxy();
  return __sessionMgr;
}

public void addUser(java.lang.String username, java.lang.String passPhrase) throws java.rmi.RemoteException{
  if (__sessionMgr == null)
    _initSessionMgrProxy();
  __sessionMgr.addUser(username, passPhrase);
}

public void connect(java.lang.String username, java.lang.String passPhrase, boolean createServerSess, boolean getCookie, javax.xml.rpc.holders.StringHolder cookie, javax.xml.rpc.holders.StringHolder proxyCert) throws java.rmi.RemoteException{
  if (__sessionMgr == null)
    _initSessionMgrProxy();
  __sessionMgr.connect(username, passPhrase, createServerSess, getCookie, cookie, proxyCert);
}

public void disconnect(java.lang.String proxyCert, java.lang.String sessID, java.lang.String encrSessionMgrURI) throws java.rmi.RemoteException{
  if (__sessionMgr == null)
    _initSessionMgrProxy();
  __sessionMgr.disconnect(proxyCert, sessID, encrSessionMgrURI);
}

public java.lang.String getX509Cert() throws java.rmi.RemoteException{
  if (__sessionMgr == null)
    _initSessionMgrProxy();
  return __sessionMgr.getX509Cert();
}

public void reqAuthorisation(java.lang.String proxyCert, java.lang.String sessID, java.lang.String encrSessionMgrURI, java.lang.String attAuthorityURI, java.lang.String attAuthorityCert, java.lang.String reqRole, boolean mapFromTrustedHosts, boolean rtnExtAttCertList, java.lang.String[] extAttCertList, java.lang.String[] extTrustedHostList, javax.xml.rpc.holders.StringHolder attCert, javax.xml.rpc.holders.StringHolder statusCode, ndg.security.holders.StringArrayHolder extAttCert) throws java.rmi.RemoteException{
  if (__sessionMgr == null)
    _initSessionMgrProxy();
  __sessionMgr.reqAuthorisation(proxyCert, sessID, encrSessionMgrURI, attAuthorityURI, attAuthorityCert, reqRole, mapFromTrustedHosts, rtnExtAttCertList, extAttCertList, extTrustedHostList, attCert, statusCode, extAttCert);
}


}