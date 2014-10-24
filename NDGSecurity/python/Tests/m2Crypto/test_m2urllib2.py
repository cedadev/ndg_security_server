from openid.fetchers import USER_AGENT, _allowedURL, Urllib2Fetcher
import urllib2
from M2Crypto.m2urllib2 import HTTPSHandler
from M2Crypto import SSL
from M2Crypto.X509 import X509_Store_Context

def installOpener():
    def verifyCallback(preVerifyOK, x509StoreCtx):
        '''callback function used to control the behaviour when the 
        SSL_VERIFY_PEER flag is set
        
        http://www.openssl.org/docs/ssl/SSL_CTX_set_verify.html
        
        @type preVerifyOK: int
        @param preVerifyOK: If a verification error is found, this parameter 
        will be set to 0
        @type x509StoreCtx: M2Crypto.X509_Store_Context
        @param x509StoreCtx: locate the certificate to be verified and perform 
        additional verification steps as needed
        @rtype: int
        @return: controls the strategy of the further verification process. 
        - If verify_callback returns 0, the verification process is immediately 
        stopped with "verification failed" state. If SSL_VERIFY_PEER is set, 
        a verification failure alert is sent to the peer and the TLS/SSL 
        handshake is terminated. 
        - If verify_callback returns 1, the verification process is continued. 
        If verify_callback always returns 1, the TLS/SSL handshake will not be 
        terminated with respect to verification failures and the connection 
        will be established. The calling process can however retrieve the error
        code of the last verification error using SSL_get_verify_result(3) or 
        by maintaining its own error storage managed by verify_callback.
        '''
        if preVerifyOK == 0:
            # Something is wrong with the certificate don't bother proceeding
            # any further
            return preVerifyOK
        
        x509Cert = x509StoreCtx.get_current_cert()
        x509Cert.get_subject()
        x509CertChain = x509StoreCtx.get1_chain()
        for cert in x509CertChain:
            subject = cert.get_subject()
            dn = subject.as_text()
            print dn
            
        # If all is OK preVerifyOK will be 1.  Return this to the caller to
        # that it's OK to proceed
        return preVerifyOK
        
    ctx = SSL.Context()

    caDirPath = '../ndg.security.test/ndg/security/test/config/ca'
    ctx.set_verify(SSL.verify_peer|SSL.verify_fail_if_no_peer_cert, 
                   9, 
                   callback=verifyCallback)
#    ctx.set_verify(SSL.verify_peer|SSL.verify_fail_if_no_peer_cert, 1)

    ctx.load_verify_locations(capath=caDirPath)
#    ctx.load_cert(certFilePath, 
#                  keyfile=priKeyFilePath, 
#                  callback=lambda *arg, **kw: priKeyPwd)

    from M2Crypto.m2urllib2 import build_opener
    urllib2.install_opener(build_opener(ssl_context=ctx))
    
if __name__ == "__main__":
    installOpener()
    fetcher = Urllib2Fetcher()
    resp = fetcher.fetch('https://localhost/openid')
    print resp.body
