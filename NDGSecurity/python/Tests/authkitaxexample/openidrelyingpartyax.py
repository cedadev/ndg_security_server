#!/usr/bin/env python

"""
This code demonstrates some of the features of an AuthKit based OpenID Relying 
Party with the use of the OpenID Attribute Exchange extensions.

Start the server with:

    python openidrelyingpartyax.py
    
Then visit http://localhost:8081/ and you should see the output from the
``index()`` method which invites you to try the secured link to trigger the
OpenID Sign In process.  When the Sign In page is displayed enter an OpenID or
OpenID Provider site address.  To demonstrate the use of attribute exchange
the OpenID Provider must support their use.  This example requests some of the
more generic ones such as firstname and lastname but it can modified to suit
the attributes that a given OpenID Provider can return. 
"""
from paste import httpexceptions

class NoSuchActionError(httpexceptions.HTTPNotFound):
    pass

class OpenIDRelyingPartyAXExampleApp:
    '''OpenID Relying Party using Attribute Exchange extensions'''
    action = {
        '/': 'index',
        '/secure': 'securedPage',
        '/signedin': 'signedin',
        '/signout': 'signout'
    }
    
    def __call__(self, environ, start_response):
        method=OpenIDRelyingPartyAXExampleApp.action.get(environ['PATH_INFO'])
        if method:
            return getattr(self, method)(environ, start_response) 
        else:
            raise NoSuchActionError()

    def securedPage(self, environ, start_response):
        user = environ.get('REMOTE_USER')
        if user is not None:
            userData = environ.get('REMOTE_USER_DATA', '<empty>')
            content = ["""<html>
<head>
<title>AuthKit Example OpenID Relying Party using Attribute Exchange 
extensions</title>
</head>
<body>
<h1>OpenID Attribute Exchange Secured Page</h1>
%s
</body>
</html>""" % OpenIDRelyingPartyAXExampleApp._loginDetails(environ)]

            start_response('200 OK', [('Content-type','text/html')])
            return content
        else:
            start_response('401 Unauthorized', [('Content-type','text/html')])
            return "Authorized"

    def signout(self, environ, start_response):
        start_response('200 OK', [('Content-type','text/html')])
        return ['''<html>
<head>
<title>AuthKit Example OpenID Relying Party using Attribute Exchange 
extensions</title>
</head>
<body>
<h1>Signed Out</h1>
</body>
</html>''']

    
    def index(self, environ, start_response):
        start_response('200 OK', [('Content-type','text/html')])
        
        return ['''<html>
<head>
<title>AuthKit Example OpenID Relying Party using Attribute Exchange 
extensions</title>
</head>
<body>
<h1>OpenID Attribute Exchange Example</h1>
%s
</body>
</html>''' % OpenIDRelyingPartyAXExampleApp._loginDetails(environ)]
        
    @staticmethod
    def _loginDetails(environ):
        '''Convenience utility for displaying login status'''
        user = environ.get('REMOTE_USER')
        if user is not None:
            userData = environ.get('REMOTE_USER_DATA', '<empty>')
            userDataDict = eval(userData)
            attrs = userDataDict.get('ax', {})
            attrTbl = '<table cellspacing="1" cellpadding="3" border="0">\n'
            for k, v in attrs.iteritems():
                if k.startswith('value'):
                    attrTbl += '''  <tr>
     <td bgcolor="lightgrey">%s</td>
     <td bgcolor="lightgrey">%s</td>
  </tr>''' % (k, v)
  
            attrTbl += '</table>\n'
            if '<tr>' in attrTbl:
                attrMsg = 'with attributes:'
            else:
                attrMsg = 'with no attributes retrieved from OpenID Provider.'
            return '''<p>User signed in:</p>
<table cellspacing="1" cellpadding="3" border="0">
  <tr>
    <td bgcolor="lightgrey">%s</td>
  </tr>
</table> 
<p>%s</p>
%s
<p><a href="/signout">Sign Out</a></p>''' % (user, attrMsg, attrTbl)
        else:
            return '''<p>Access <a href="/secure">Secure page</a> to login
                   with OpenID</p>'''


if __name__ == '__main__':
    import os
    from paste.httpserver import serve
    from authkit.authenticate import middleware
    from beaker.middleware import SessionMiddleware
    
    app = OpenIDRelyingPartyAXExampleApp()
    app_conf={}
    
    # Set AX keywords by setting a type URI keyword of the form
    # openid_ax_typeuri_<attribute name>.  
    # * If no alias is set, an attribute name will automatically be allocated 
    # to the value specified.  
    # * To make the value a required parameter, set 
    # openid_ax_required_<attribute name> to True.  If not set, the parameter 
    # will be optional.
    # To set array type parameters specify a count to indicate the number of
    # elements:
    # openid_ax_count_<attribute name>=10
    #
    # or:
    # openid_ax_count_<attribute name>='unlimited'
    #
    # for unlimited array length.
    thisDir = os.path.abspath(os.path.dirname(__file__))
    openIDStoreConfigDir = os.path.join(thisDir, 'data', 'openid')
    app = middleware(app, 
        setup_method='openid, cookie',
        cookie_secret='secret string',
        cookie_signoutpath = '/signout',
        openid_store_type='file',
        openid_store_config=openIDStoreConfigDir,
        openid_session_key='authkit_openid_session_key',
        openid_session_secret='authkit_openid_session_secret',
        openid_path_signedin='/',
        openid_baseurl='http://localhost:8081',
        openid_ax_typeuri_firstname='http://openid.net/schema/namePerson/first',
        openid_ax_alias_firstname='firstname',
        openid_ax_required_firstname=True,
        openid_ax_typeuri_lastname='http://openid.net/schema/namePerson/last',
        openid_ax_required_lastname=True,
        openid_ax_alias_lastname='lastname',
        openid_ax_typeuri_email='http://openid.net/schema/contact/internet/email',
        openid_ax_required_email=True,
        openid_ax_alias_email='email',     
        openid_ax_typeuri_organization='http://openid.net/schema/company/name',
        openid_ax_alias_organization='organization',
#        openid_ax_typeuri_city='http://openid.net/schema/contact/city/home',
#        openid_ax_alias_city='city',
#        openid_ax_typeuri_state='http://openid.net/schema/contact/state/home',
#        openid_ax_alias_state='state',
#        openid_ax_typeuri_country='http://openid.net/schema/contact/country/home',
        )
    
    app = SessionMiddleware(
        app, 
        key='authkit.open_id', 
        secret='some secret')

    serve(app, host='0.0.0.0', port=8081)
