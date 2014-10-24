/**
 * SessionMgrService.java
 *
 * This file was auto-generated from WSDL
 * by the IBM Web services WSDL2Java emitter.
 * b0619.25 v51306165058
 */

package ndg.security.sessionMgr;

public interface SessionMgrService extends javax.xml.rpc.Service {

     // NERC Data Grid Session Manager web service
    public ndg.security.sessionMgr.SessionMgr getSessionMgr() throws javax.xml.rpc.ServiceException;

    public java.lang.String getSessionMgrAddress();

    public ndg.security.sessionMgr.SessionMgr getSessionMgr(java.net.URL portAddress) throws javax.xml.rpc.ServiceException;
}
