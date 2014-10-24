#!/usr/bin/env python
import getpass
from myproxy.client import MyProxyClient

if __name__ == "__main__":
   myproxy = MyProxyClient(hostname='myproxy.ceda.ac.uk', serverCNPrefix='')
#   myproxy = MyProxyClient(hostname='glue.badc.rl.ac.uk', serverCNPrefix='')
   cert, key = myproxy.logon('https://ceda.ac.uk/openid/Philip.Kershaw', getpass.getpass())
   open('user.crt', 'w').write(cert)
   open('user.key', 'w').write(key)
 
