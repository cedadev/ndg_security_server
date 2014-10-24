/**
 * SessionMgr.java
 *
 * This file was auto-generated from WSDL
 * by the IBM Web services WSDL2Java emitter.
 * b0619.25 v51306165058
 */

package ndg.security.sessionMgr;

public interface SessionMgr extends java.rmi.Remote {
    public void addUser(java.lang.String username, java.lang.String passphrase) throws java.rmi.RemoteException;
    public void connect(java.lang.String username, java.lang.String passphrase, boolean createServerSess, boolean getCookie, javax.xml.rpc.holders.StringHolder proxyCert, javax.xml.rpc.holders.StringHolder proxyPriKey, javax.xml.rpc.holders.StringHolder userCert, javax.xml.rpc.holders.StringHolder cookie) throws java.rmi.RemoteException;
    public void disconnect(java.lang.String userCert, java.lang.String sessID, java.lang.String encrSessionMgrURI) throws java.rmi.RemoteException;
    public void getAttCert(java.lang.String userCert, java.lang.String sessID, java.lang.String encrSessionMgrURI, java.lang.String attAuthorityURI, java.lang.String attAuthorityCert, java.lang.String reqRole, boolean mapFromTrustedHosts, boolean rtnExtAttCertList, java.lang.String[] extAttCert, java.lang.String[] extTrustedHost, javax.xml.rpc.holders.StringHolder attCert, javax.xml.rpc.holders.StringHolder msg, ndg.security.sessionMgr.holders.StringArrayHolder extAttCertOut) throws java.rmi.RemoteException;
    public java.lang.String getX509Cert() throws java.rmi.RemoteException;
}
