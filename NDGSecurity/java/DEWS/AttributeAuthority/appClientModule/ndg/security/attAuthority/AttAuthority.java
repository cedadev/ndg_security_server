/**
 * AttAuthority.java
 *
 * This file was auto-generated from WSDL
 * by the IBM Web services WSDL2Java emitter.
 * b0619.25 v51306165058
 */

package ndg.security.attAuthority;

public interface AttAuthority extends java.rmi.Remote {
    public void getAttCert(java.lang.String userId, java.lang.String userCert, java.lang.String userAttCert, javax.xml.rpc.holders.StringHolder attCert, javax.xml.rpc.holders.StringHolder msg) throws java.rmi.RemoteException;
    public void getHostInfo(javax.xml.rpc.holders.StringHolder hostname, javax.xml.rpc.holders.StringHolder aaURI, javax.xml.rpc.holders.StringHolder loginURI) throws java.rmi.RemoteException;
    public ndg.security.attAuthority.HostInfo[] getTrustedHostInfo(java.lang.String role) throws java.rmi.RemoteException;
    public java.lang.String getX509Cert() throws java.rmi.RemoteException;
}
