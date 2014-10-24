/**
 * SessionMgr.java
 *
 * This file was auto-generated from WSDL
 * by the IBM Web services WSDL2Java emitter.
 * cf30645.70 v111306193218
 */

package ndg.security;

public interface SessionMgr extends java.rmi.Remote {
    public void addUser(java.lang.String username, java.lang.String passPhrase) throws java.rmi.RemoteException;
    public void connect(java.lang.String username, java.lang.String passPhrase, boolean createServerSess, boolean getCookie, javax.xml.rpc.holders.StringHolder cookie, javax.xml.rpc.holders.StringHolder proxyCert) throws java.rmi.RemoteException;
    public void disconnect(java.lang.String proxyCert, java.lang.String sessID, java.lang.String encrSessionMgrURI) throws java.rmi.RemoteException;
    public void reqAuthorisation(java.lang.String proxyCert, java.lang.String sessID, java.lang.String encrSessionMgrURI, java.lang.String attAuthorityURI, java.lang.String attAuthorityCert, java.lang.String reqRole, boolean mapFromTrustedHosts, boolean rtnExtAttCertList, java.lang.String[] extAttCertList, java.lang.String[] extTrustedHostList, javax.xml.rpc.holders.StringHolder attCert, javax.xml.rpc.holders.StringHolder statusCode, ndg.security.holders.StringArrayHolder extAttCert) throws java.rmi.RemoteException;
    public java.lang.String getX509Cert() throws java.rmi.RemoteException;
}
