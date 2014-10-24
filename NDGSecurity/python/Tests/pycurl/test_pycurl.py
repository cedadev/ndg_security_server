import pycurl
import cStringIO
import os
#os.environ['CURL_CA_BUNDLE'] = '/home/pjkersha/Documents/BADC/Certificates/Cybertrust/cybertrustCombo.crt'
#caPath = '/usr/local/ndg/ca/ndg-test-ca.crt'
caPath = '/workspace/ndg_security_python/Tests/esg_integration/esg_trusted_certificates'
#url = 'https://ndg3beta.badc.rl.ac.uk/openid'
#url = 'https://localhost/openid'
url = 'https://pcmdi3.llnl.gov/esgcet/saml/soap/secure/attributeService.htm'
print pycurl.version_info()
for i in dir(pycurl):
    print i
    
c = pycurl.Curl()

# SSL Options
c.setopt(pycurl.SSL_VERIFYPEER, 0)
c.setopt(pycurl.SSL_VERIFYHOST, 0)
c.setopt(pycurl.CAINFO, caPath)
c.setopt(pycurl.CAPATH, caPath)

data = cStringIO.StringIO()
headerData = cStringIO.StringIO()

c.setopt(pycurl.WRITEFUNCTION, data.write)
c.setopt(pycurl.HEADERFUNCTION, headerData.write)
c.setopt(pycurl.URL, url)

try:
    c.perform()
except:
    pass
info = c.getinfo(pycurl.SSL_VERIFYRESULT)

code = c.getinfo(pycurl.RESPONSE_CODE)
print code
print headerData.getvalue()
print data.getvalue()