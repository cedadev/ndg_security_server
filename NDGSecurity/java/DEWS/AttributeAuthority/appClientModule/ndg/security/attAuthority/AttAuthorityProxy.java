package ndg.security.attAuthority;

public class AttAuthorityProxy implements ndg.security.attAuthority.AttAuthority {
  private boolean _useJNDI = true;
  private String _endpoint = null;
  private ndg.security.attAuthority.AttAuthority __attAuthority = null;
  
  public AttAuthorityProxy() {
    _initAttAuthorityProxy();
  }
  
  private void _initAttAuthorityProxy() {
  
  if (_useJNDI) {
    try{
      javax.naming.InitialContext ctx = new javax.naming.InitialContext();
      __attAuthority = ((ndg.security.attAuthority.AttAuthorityService)ctx.lookup("java:comp/env/service/AttAuthorityService")).getAttAuthority();
      }
    catch (javax.naming.NamingException namingException) {}
    catch (javax.xml.rpc.ServiceException serviceException) {}
  }
  if (__attAuthority == null) {
    try{
      __attAuthority = (new ndg.security.attAuthority.AttAuthorityServiceLocator()).getAttAuthority();
      }
    catch (javax.xml.rpc.ServiceException serviceException) {}
  }
  if (__attAuthority != null) {
    if (_endpoint != null)
      ((javax.xml.rpc.Stub)__attAuthority)._setProperty("javax.xml.rpc.service.endpoint.address", _endpoint);
    else
      _endpoint = (String)((javax.xml.rpc.Stub)__attAuthority)._getProperty("javax.xml.rpc.service.endpoint.address");
  }
  
}


public void useJNDI(boolean useJNDI) {
  _useJNDI = useJNDI;
  __attAuthority = null;
  
}

public String getEndpoint() {
  return _endpoint;
}

public void setEndpoint(String endpoint) {
  _endpoint = endpoint;
  if (__attAuthority != null)
    ((javax.xml.rpc.Stub)__attAuthority)._setProperty("javax.xml.rpc.service.endpoint.address", _endpoint);
  
}

public ndg.security.attAuthority.AttAuthority getAttAuthority() {
  if (__attAuthority == null)
    _initAttAuthorityProxy();
  return __attAuthority;
}

public void getAttCert(java.lang.String userId, java.lang.String userCert, java.lang.String userAttCert, javax.xml.rpc.holders.StringHolder attCert, javax.xml.rpc.holders.StringHolder msg) throws java.rmi.RemoteException{
  if (__attAuthority == null)
    _initAttAuthorityProxy();
  __attAuthority.getAttCert(userId, userCert, userAttCert, attCert, msg);
}

public void getHostInfo(javax.xml.rpc.holders.StringHolder hostname, javax.xml.rpc.holders.StringHolder aaURI, javax.xml.rpc.holders.StringHolder loginURI) throws java.rmi.RemoteException{
  if (__attAuthority == null)
    _initAttAuthorityProxy();
  __attAuthority.getHostInfo(hostname, aaURI, loginURI);
}

public ndg.security.attAuthority.HostInfo[] getTrustedHostInfo(java.lang.String role) throws java.rmi.RemoteException{
  if (__attAuthority == null)
    _initAttAuthorityProxy();
  return __attAuthority.getTrustedHostInfo(role);
}

public java.lang.String getX509Cert() throws java.rmi.RemoteException{
  if (__attAuthority == null)
    _initAttAuthorityProxy();
  return __attAuthority.getX509Cert();
}


}