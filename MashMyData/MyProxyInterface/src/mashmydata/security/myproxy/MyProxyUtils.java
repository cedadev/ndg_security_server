/**
 * Interface to MyProxy servers for Portal.  Enables portal to get a credential
 * from a MyProxyCA and set up a delegated one another MyProxy Server.
 * 
 * MashMyData Project
 *
 * Date: 22/11/10
 * 
 * Copyright: (C) 2010 Science and Technology Facilities Council
 * 
 * Licence: BSD
 * 
 * $Id$
 * 
 * @author Philip Kershaw
 * @version $Revision$
 */
package mashmydata.security.myproxy;

import java.io.IOException;
import java.net.URL;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.globus.myproxy.InitParams;
import org.globus.myproxy.MyProxy;
import org.globus.myproxy.MyProxyException;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.globus.gsi.gssapi.GlobusGSSCredentialImpl;


public class MyProxyUtils {

	/**
	 * Credential Translation Service MyProxy server
	 */
	protected MyProxy cts = null;
	
	/**
	 * Staging Service MyProxy Server
	 */
	protected MyProxy stagingService = null;
	
	/**
	 * Initialise Translation and Staging Service MyProxy servers.  The 
	 * Translation Service converts an OpenID to a short lived End Entity
	 * Certificate.  The Staging Service takes a proxy to that EEC to provision
	 * other services so that they can be delegated authority to act on behalf
	 * of that identity.
	 * 
	 * @param ctsName Credential MyProxy Translation Service domain name
	 * @param ctsPort Credential MyProxy Translation Service port number
	 * @param stagingServiceName MyProxy Staging Service domain name
	 * @param stagingServicePort MyProxy Staging Service port number
	 */
	MyProxyUtils(final String ctsName, int ctsPort,
			final String stagingServiceName, int stagingServicePort) {
		if (ctsPort == -1)
			ctsPort = MyProxy.DEFAULT_PORT;
		
		if (stagingServicePort == -1)
			stagingServicePort = MyProxy.DEFAULT_PORT;
		
		cts = new MyProxy(ctsName, ctsPort);
		stagingService = new MyProxy(stagingServiceName, stagingServicePort);
	}
	
	/**
	 * Initialise Translation and Staging Service MyProxy servers assuming
	 * standard port numbers for each
	 * 
	 * @param ctsName Credential MyProxy Translation Service domain name
	 * @param stagingServiceName MyProxy Staging Service domain name
	 */
	MyProxyUtils(final String ctsName, final String stagingServiceName) {
		this(ctsName, -1, stagingServiceName, -1);
	}

	/**
	 * Translate input OpenID to a Short lived EEC
	 * 
	 * @param openid
	 * @param passphrase
	 * @throws MyProxyException
	 */
	public final GSSCredential translateCredentials(
			final URL openid, 
			final String passphrase) 
		throws MyProxyException {
		
		return translateCredentials(openid.toString(), passphrase);
	}
	
	/**
	 * Translate input username to a Short lived EEC
	 * 
	 * @param username
	 * @param passphrase
	 * @return new credential
	 * @throws MyProxyException
	 */
	public final GSSCredential translateCredentials(
			final String username, 
			final String passphrase) 
		throws MyProxyException {
		
		final int lifetime = 86400;
		GSSCredential cred = cts.get(username, passphrase, lifetime);
		return cred;
	}
	
	/**
	 * Create new credential on staging MyProxy server delegating from the 
	 * input cred
	 * 
	 * @param cred credential for MyProxy server to delegate from
	 * @param retriever Subject for entity to be given authority to later
	 * retrieve the delegated credential.  Set to null to not set a retriever
	 * @throws MyProxyException
	 * @throws GSSException
	 */
	public void stageCredentials(
			final GSSCredential cred, 
			final String credentialName,
			final String retriever) 
		throws MyProxyException, GSSException {
		
		InitParams initParams = new InitParams();
		initParams.setCredentialName(credentialName);
		initParams.setUserName(cred.getName().toString());
		
		if (retriever != null) 
			initParams.setRetriever(retriever);
		
		stagingService.put(cred, initParams);
	}
	
	/**
	 * Added Credential obtained from MyProxy into a KeyStore for subsequent
	 * use in SSL calls to other services
	 * 
	 * @param cred Globus credential obtained from MyProxy
	 * @param certAlias alias for credential to be referred to once added to
	 * the keystore
	 * @return new KeyStore instance
	 * @throws KeyStoreException
	 * @throws NoSuchProviderException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws IOException
	 */
	public KeyStore generateKeyStore(final GSSCredential cred,
			final String certAlias,
			final char[] keyPass) 
		throws KeyStoreException, NoSuchProviderException, 
			NoSuchAlgorithmException, CertificateException, IOException {
		
		GlobusGSSCredentialImpl gCred = (GlobusGSSCredentialImpl) cred;
		X509Certificate[] certChain = gCred.getCertificateChain();
		PrivateKey priKey = gCred.getPrivateKey();
		
        KeyStore ks = KeyStore.getInstance("JKS", "SUN");
        ks.load(null, keyPass);
        ks.setKeyEntry(certAlias, priKey, keyPass, certChain);
        
        return ks;
	}
	
	/**
	 * TODO: Move this test stub to unit test
	 * 
	 * @param args
	 * @throws MyProxyException 
	 * @throws GSSException 
	 * @throws IOException 
	 * @throws CertificateException 
	 * @throws NoSuchAlgorithmException 
	 * @throws NoSuchProviderException 
	 * @throws KeyStoreException 
	 */
	public static void main(String[] args) 
		throws MyProxyException, GSSException, KeyStoreException, 
			NoSuchProviderException, NoSuchAlgorithmException, 
			CertificateException, IOException {
		
		String tlsName = args[0];
		String ssName = args[1];
		String username = args[2];
		String passphrase = args[3];
		
		MyProxyUtils myProxyUtils = new MyProxyUtils(tlsName, ssName);
		
		// Call MyProxyCA TLS to issue new cert
		GSSCredential cred = myProxyUtils.translateCredentials(
														username, passphrase);
		String keyPass = "keystorepass";
		KeyStore ks = myProxyUtils.generateKeyStore(cred, "certAlias",
				keyPass.toCharArray());
		
		java.security.cert.Certificate cert = ks.getCertificate("certAlias");
		System.out.printf("Cert = %s%n", cert.toString());
		
		// Stage new delegated credential on second MyProxy Server
		myProxyUtils.stageCredentials(cred, "myCredential", null);
	}
}
