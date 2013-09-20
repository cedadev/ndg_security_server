"""NDG Security integration testing package

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "23/04/2009"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see top-level directory for LICENSE file"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"


class AuthZTestApp(object):
    """This class simulates the application to be secured by the NDG Security
    authorization middleware
    """
    method = {
        "/": 'default',
        "/test_401": "test_401",
        "/test_403": "test_403",
        "/test_securedURI": "test_securedURI",
        "/test_accessDeniedToSecuredURI": "test_accessDeniedToSecuredURI",
        "/test_logoutWithReturn2QueryArg": "test_logoutWithReturn2QueryArg"
    }
    header = """        <h1>NDG Security Authorisation Integration Tests:</h1>
        <p>These tests use require the security services application to be
        running.  See securityserviceapp.py and securityservices.ini in the 
        integration test directory.</p>
        <h2>To Run:</h2>
        <p>Try any of the links below.  When prompt for username and password,
        enter one of the sets of credentials from securityservices.ini
        openid.provider.authN.userCreds section.  The defaults are:
        </p>
        <p>pjk/testpassword</p>
        <p>another/testpassword</p>
        <p>The attributeinterface.py AttributeAuthority plugin is configured to
        grant access to 'pjk' for all URLs below apart from 
        'test_accessDeniedToSecuredURI'.  The 'another' account will be denied
        access from all URLs apart from 'test_401'</p>
"""

    def __init__(self, app, globalConfig, **localConfig):
        self.beakerSessionKeyName = globalConfig['beakerSessionKeyName']
        self.app = app
            
    def __call__(self, environ, start_response):
        
        methodName = self.method.get(environ['PATH_INFO'], '').rstrip()
        if methodName:
            action = getattr(self, methodName)
            return action(environ, start_response)
        elif environ['PATH_INFO'] == '/logout':
            return self.default(environ, start_response)
        
        elif self.app is not None:
            return self.app(environ, start_response)
        else:
            start_response('404 Not Found', [('Content-type', 'text/plain')])
            return "Authorisation integration tests: invalid URI"
            
    def default(self, environ, start_response):
        links = self.method.copy()
        del links['/']
        del links['/test_logoutWithReturn2QueryArg']
        links['/logout?ndg.security.logout.r=/test_logoutWithReturn2QueryArg'
              ] = 'test_logoutWithReturn2QueryArg'
        
        if 'username' in environ.get(self.beakerSessionKeyName, {}):
            response = """<html>
    <head/>
    <body>
        %s
        <ul>%s</ul>
        <p>You are logged in with OpenID [%s].  <a href="/logout">Logout</a></p>
    </body>
</html>
""" % (AuthZTestApp.header,
       '\n'.join(['<li><a href="%s">%s</a></li>' % (link, name) 
                  for link, name in links.items()]),
       environ[self.beakerSessionKeyName]['username'])
        
            start_response('200 OK', 
                           [('Content-type', 'text/html'),
                            ('Content-length', str(len(response)))])
        else:
            response = """<html>
    <head/>
    <body>
        %s
        <ul>%s</ul>
        <p>You are logged out.  <a href="/test_401">Login</a></p>
    </body>
</html>
""" % (AuthZTestApp.header,
       '\n'.join(['<li><a href="%s">%s</a></li>' % (link, name) 
                 for link,name in links.items()])
       )

            start_response('200 OK', 
                           [('Content-type', 'text/html'),
                            ('Content-length', str(len(response)))])
        return response

    def test_401(self, environ, start_response):
        """Trigger the Authentication middleware by returning a 401 
        Unauthorized HTTP status code from this URI"""
        username = environ[self.beakerSessionKeyName].get('username')
        if username:
            response = """<html>
        <head/>
        <body>
            <h1>Authenticated!</h1>
            <p><a href="/">Return</a> to tests<p>
            <p>You are logged in.  <a href="/logout">Logout</a></p>
        </body>
    </html>
    """
            start_response('200 OK', 
                           [('Content-type', 'text/html'),
                            ('Content-length', str(len(response)))])
        else:
            response = "This page shouldn't be displayed!"
            start_response('401 Unauthorized', 
                           [('Content-type', 'text/plain'),
                            ('Content-length', str(len(response)))])
            
        return response

    def test_403(self, environ, start_response):
        """Trigger the Authorization middleware by returning a 403 Forbidden
        HTTP status code from this URI"""
        
        username = environ[self.beakerSessionKeyName].get('username')
        if username:
            response = """<html>
    <head/>
    <body>
        <h1>Authorised!</h1>
        <p><a href="/">Return</a> to tests<p>
        <p>You are logged in with OpenID [%s].  <a href="/logout">Logout</a></p>
    </body>
</html>
""" % username

            start_response('200 OK', 
                           [('Content-type', 'text/html'),
                            ('Content-length', str(len(response)))])
        else:
            response = "This page shouldn't be displayed!"
            start_response('403 Forbidden', 
                           [('Content-type', 'text/plain'),
                            ('Content-length', str(len(response)))])

        return response

    def test_securedURI(self, environ, start_response):
        """To be secured, the Authorization middleware must have this URI in
        its policy"""
        username = environ[self.beakerSessionKeyName].get('username')
        if username is None:
            response = ("Error: User is not logged in!  Check that the "
                        "that this URI is set as secured in the authorisation "
                        "policy - request-filter.xml and policy.xml (set with "
                        "the security services configuration)")
            start_response('200 OK', 
                           [('Content-type', 'text/html'),
                            ('Content-length', str(len(response)))])
            return response
            
        response = """<html>
    <head/>
    <body>
        <h1>Authorised for path [%s]!</h1>
        <p><a href="/">Return</a> to tests<p>
        <p>You are logged in with OpenID [%s].  <a href="/logout">Logout</a></p>
    </body>
</html>
""" % (environ['PATH_INFO'], username)


        start_response('200 OK', 
                       [('Content-type', 'text/html'),
                        ('Content-length', str(len(response)))])
        return response


    def test_accessDeniedToSecuredURI(self, environ, start_response):
        """To be secured, the Authorization middleware must have this URI in
        its policy and the user must not have the required role as specified
        in the policy.  See ndg.security.test.config.attributeauthority.sitea
        for user role settings retrieved from the attribute authority"""
        response = """<html>
    <head/>
    <body>
        <h1>Authorised for path [%s]!</h1>
        <p><a href="/">Return</a> to tests<p>
        <p>You are logged in with OpenID [%s].  <a href="/logout">Logout</a></p>
    </body>
</html>
""" % (environ['PATH_INFO'], environ[self.beakerSessionKeyName]['username'])

        start_response('200 OK', 
                       [('Content-type', 'text/html'),
                        ('Content-length', str(len(response)))])
        return response

    def test_logoutWithReturn2QueryArg(self, environ, start_response):
        """Test logout setting a return to argument to explicitly set the
        URI to return to following the logout action
        """
        response = """<html>
    <head/>
    <body>
        <h1>Logged Out</h1>
        <p>Successfully redirected to specified return to URI query argument 
        ndg.security.logout.r=%s following logout.  
        <a href="/">Return to tests</a></p>
    </body>
</html>
""" % environ['PATH_INFO']

        start_response('200 OK', 
                       [('Content-type', 'text/html'),
                        ('Content-length', str(len(response)))])
        return response
    
    @classmethod
    def app_factory(cls, globalConfig, **localConfig):
        return cls(None, globalConfig, **localConfig)
    
    @classmethod
    def filter_app_factory(cls, app, globalConfig, **localConfig):
        return cls(app, globalConfig, **localConfig)