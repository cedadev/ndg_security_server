/**
 * HostInfo.java
 *
 * This file was auto-generated from WSDL
 * by the IBM Web services WSDL2Java emitter.
 * b0619.25 v51306165058
 */

package ndg.security.attAuthority;

public class HostInfo  {
    private java.lang.String hostname;
    private java.lang.String aaURI;
    private java.lang.String loginURI;
    private java.lang.String[] roleList;

    public HostInfo() {
    }

    public java.lang.String getHostname() {
        return hostname;
    }

    public void setHostname(java.lang.String hostname) {
        this.hostname = hostname;
    }

    public java.lang.String getAaURI() {
        return aaURI;
    }

    public void setAaURI(java.lang.String aaURI) {
        this.aaURI = aaURI;
    }

    public java.lang.String getLoginURI() {
        return loginURI;
    }

    public void setLoginURI(java.lang.String loginURI) {
        this.loginURI = loginURI;
    }

    public java.lang.String[] getRoleList() {
        return roleList;
    }

    public void setRoleList(java.lang.String[] roleList) {
        this.roleList = roleList;
    }

    public java.lang.String getRoleList(int i) {
        return this.roleList[i];
    }

    public void setRoleList(int i, java.lang.String value) {
        this.roleList[i] = value;
    }

}
