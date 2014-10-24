/**
 * AttAuthorityService.java
 *
 * This file was auto-generated from WSDL
 * by the IBM Web services WSDL2Java emitter.
 * b0619.25 v51306165058
 */

package ndg.security.attAuthority;

public interface AttAuthorityService extends javax.xml.rpc.Service {

     // NERC Data Grid Attribute Authority web service
    public ndg.security.attAuthority.AttAuthority getAttAuthority() throws javax.xml.rpc.ServiceException;

    public java.lang.String getAttAuthorityAddress();

    public ndg.security.attAuthority.AttAuthority getAttAuthority(java.net.URL portAddress) throws javax.xml.rpc.ServiceException;
}
