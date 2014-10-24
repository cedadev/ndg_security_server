package ndg.security.sessionMgr;

public class SessionMgrProxy implements ndg.security.sessionMgr.SessionMgr {
  private boolean _useJNDI = true;
  private String _endpoint = null;
  private ndg.security.sessionMgr.SessionMgr __sessionMgr = null;
  
  public SessionMgrProxy() {
    _initSessionMgrProxy();
  }
  
  private void _initSessionMgrProxy() {
  
  if (_useJNDI) {
    try{
      javax.naming.InitialContext ctx = new javax.naming.InitialContext();
      __sessionMgr = ((ndg.security.sessionMgr.SessionMgrService)ctx.lookup("java:comp/env/service/SessionMgrService")).getSessionMgr();
      }
    catch (javax.naming.NamingException namingException) {}
    catch (javax.xml.rpc.ServiceException serviceException) {}
  }
  if (__sessionMgr == null) {
    try{
      __sessionMgr = (new ndg.security.sessionMgr.SessionMgrServiceLocator()).getSessionMgr();
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

public ndg.security.sessionMgr.SessionMgr getSessionMgr() {
  if (__sessionMgr == null)
    _initSessionMgrProxy();
  return __sessionMgr;
}

public void addUser(java.lang.String username, java.lang.String passphrase) throws java.rmi.RemoteException{
  if (__sessionMgr == null)
    _initSessionMgrProxy();
  __sessionMgr.addUser(username, passphrase);
}

public void connect(java.lang.String username, java.lang.String passphrase, boolean createServerSess, boolean getCookie, javax.xml.rpc.holders.StringHolder proxyCert, javax.xml.rpc.holders.StringHolder proxyPriKey, javax.xml.rpc.holders.StringHolder userCert, javax.xml.rpc.holders.StringHolder cookie) throws java.rmi.RemoteException{
  if (__sessionMgr == null)
    _initSessionMgrProxy();
  __sessionMgr.connect(username, passphrase, createServerSess, getCookie, proxyCert, proxyPriKey, userCert, cookie);
}

public void disconnect(java.lang.String userCert, java.lang.String sessID, java.lang.String encrSessionMgrURI) throws java.rmi.RemoteException{
  if (__sessionMgr == null)
    _initSessionMgrProxy();
  __sessionMgr.disconnect(userCert, sessID, encrSessionMgrURI);
}

public void getAttCert(java.lang.String userCert, java.lang.String sessID, java.lang.String encrSessionMgrURI, java.lang.String attAuthorityURI, java.lang.String attAuthorityCert, java.lang.String reqRole, boolean mapFromTrustedHosts, boolean rtnExtAttCertList, java.lang.String[] extAttCert, java.lang.String[] extTrustedHost, javax.xml.rpc.holders.StringHolder attCert, javax.xml.rpc.holders.StringHolder msg, ndg.security.sessionMgr.holders.StringArrayHolder extAttCertOut) throws java.rmi.RemoteException{
  if (__sessionMgr == null)
    _initSessionMgrProxy();
  __sessionMgr.getAttCert(userCert, sessID, encrSessionMgrURI, attAuthorityURI, attAuthorityCert, reqRole, mapFromTrustedHosts, rtnExtAttCertList, extAttCert, extTrustedHost, attCert, msg, extAttCertOut);
}

public java.lang.String getX509Cert() throws java.rmi.RemoteException{
  if (__sessionMgr == null)
    _initSessionMgrProxy();
  return __sessionMgr.getX509Cert();
}


}