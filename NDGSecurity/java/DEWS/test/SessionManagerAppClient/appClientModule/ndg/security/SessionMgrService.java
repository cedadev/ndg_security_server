/**
 * SessionMgrService.java
 *
 * This file was auto-generated from WSDL
 * by the IBM Web services WSDL2Java emitter.
 * cf30645.70 v111306193218
 */

package ndg.security;

public interface SessionMgrService extends javax.xml.rpc.Service {

     // NERC Data Grid Session Manager web service
    public ndg.security.SessionMgr getSessionMgr() throws javax.xml.rpc.ServiceException;

    public java.lang.String getSessionMgrAddress();

    public ndg.security.SessionMgr getSessionMgr(java.net.URL portAddress) throws javax.xml.rpc.ServiceException;
}
