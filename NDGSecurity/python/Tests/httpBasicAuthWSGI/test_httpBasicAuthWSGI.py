#!/usr/bin/env python
import urllib2
import base64
import sys

if __name__ == "__main__":
    url = 'http://localhost:40000'
    username = 'bb'
    password = 'secret'
    req = urllib2.Request(url)
    base64String = base64.encodestring('%s:%s' % (username, password))[:-1]
    authHeader =  "Basic %s" % base64String
    req.add_header("Authorization", authHeader)
    try:
        handle = urllib2.urlopen(req)
    except IOError, e:
        print("It looks like the username or password is wrong: %s" % e)
        sys.exit(1)
        
    thePage = handle.read()
    print thePage
