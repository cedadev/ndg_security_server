

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;


/**
 * Extend PKIX X.509 Trust Manager to support whitelisting of peer certificate
 * Distinguished Names
 * 
 * @author pjkersha
 */
public class CertDnFilteringX509TrustMgr implements X509TrustManager {

	protected static String BASE_TRUST_MGR_ID = "PKIX";
	protected static String TRUSTSTORE_TYPE = "JKS";
	
	/**
	 * list of peer certificate distinguished names that are acceptable to
	 * the client in SSL connections
	 */
	protected Set<X500Principal> certificateDnWhiteList;
	
    /**
     * The default PKIX X509TrustManager.  Delegate decisions to it, and fall 
     * back to the logic in this class if the default X509TrustManager doesn't 
     * trust it.
     */
    X509TrustManager pkixTrustManager;
    
    /**
     * Instantiate from a given certificate DN whitelist
     * 
     * @param certificateDnWhiteList list of peer certificate distinguished 
     * names that are acceptable to the client in SSL connections
     * @throws Exception 
     */
    public CertDnFilteringX509TrustMgr(X500Principal[] certificateDnWhiteList) 
    	throws Exception {
    	
    	this.certificateDnWhiteList = new HashSet<X500Principal>();
    	if (certificateDnWhiteList != null)
    		for (X500Principal dn : certificateDnWhiteList)
    			this.certificateDnWhiteList.add(dn);
    	
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
        KeyStore ks = null;
		tmf.init(ks);
		
        TrustManager tms [] = tmf.getTrustManagers();

        /*
         * Iterate over the returned trust managers, look for an instance of 
         * X509TrustManager.  If found, use that as "default" trust manager.
         */
        for (Object tm : tms) {
            if (tm instanceof X509TrustManager) {
                pkixTrustManager = (X509TrustManager) tm;
                return;
            }
        }

        /*
         * Got to here so no X509TrustManager was found
         */
        throw new Exception(
        	"No X509TrustManager found in trust manager factory instance");
    }
    
    /**
     * SSL Client certificate authentication
     * 
     * Delegate to the default trust manager but also includes DN whitelist 
     * checking
     */
    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType)
                throws CertificateException {
        pkixTrustManager.checkClientTrusted(chain, authType);
        
		// If chain is OK following previous check, then execute whitelisting of 
        // DN
		X500Principal peerCertDN = null;
		
		if (certificateDnWhiteList == null)
			return;
		
		for (X509Certificate cert : chain)
		{
			peerCertDN = cert.getSubjectX500Principal();
			
			for (Principal dn : certificateDnWhiteList)
				if (peerCertDN.equals(dn))
					return;
		}
		throw new CertificateException("No match for peer certificate " + 
				peerCertDN + "against Certificate DN whitelist");
    }

    /**
     * SSL Server certificate authentication
     * 
     * Delegate to the default trust manager but also includes DN whitelist 
     * checking
     */
    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType)
                throws CertificateException {
    	
    	// Default trust manager may throw a certificate exception
        pkixTrustManager.checkServerTrusted(chain, authType);
        
		// If chain is OK following previous check, then execute whitelisting of 
        // DN
		X500Principal peerCertDN = null;
		
		if (certificateDnWhiteList == null || certificateDnWhiteList.isEmpty())
			return;
		
		int basicConstraints = -1;
		for (X509Certificate cert : chain) {
			// Check for CA certificate first - ignore if this is the case
			basicConstraints = cert.getBasicConstraints();
			if (basicConstraints > -1)
				continue;

			peerCertDN = cert.getSubjectX500Principal();
			for (X500Principal dn : certificateDnWhiteList)
				if (peerCertDN.getName().equals(dn.getName()))
					return;
		}
		throw new CertificateException("No match for peer certificate \"" + 
				peerCertDN + "\" against Certificate DN whitelist");
	}

    /**
     * Merely pass this through.
     */
    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return pkixTrustManager.getAcceptedIssuers();
    }
    
    public static void main(String[] args) throws 
    	Exception {
    	assert args.length == 0 : "Pass a URL to retrieve";
    	URL url = new URL(args[0]);
		SSLContext ctx = null;

		ctx = SSLContext.getInstance("SSL");

		X500Principal[] dn = {new X500Principal(
			"CN=www.google.com, O=Google Inc, L=Mountain View, ST=California, C=US"
			)};
		CertDnFilteringX509TrustMgr x509TrustMgr = new 
			CertDnFilteringX509TrustMgr(dn);
		
		X509TrustManager tm[] = {x509TrustMgr};

		ctx.init(null, tm, null);
		
		SSLSocketFactory socketFactory = ctx.getSocketFactory();
		HttpsURLConnection connection = null;

		connection = (HttpsURLConnection)url.openConnection();
		connection.setSSLSocketFactory(socketFactory);
				
		InputStream ins = null;
		ins = connection.getInputStream();
	    InputStreamReader isr = new InputStreamReader(ins);
	    BufferedReader in = new BufferedReader(isr);
	    StringBuffer buf = new StringBuffer();
	    String inputLine = null;

		while ((inputLine = in.readLine()) != null)
		{
		    buf.append(inputLine);
		    buf.append(System.getProperty("line.separator"));
		}
		in.close();

	    System.out.println(buf.toString());
	}
}
