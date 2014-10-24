"""NDG Security Demonstration Rendering Interface for OpenIDProviderMiddleware

NERC DataGrid Project

Moved from ndg.security.server.wsgi.openid.provider 10/03/09
"""
__author__ = "P J Kershaw"
__date__ = "01/08/08"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"
__license__ = "BSD - see LICENSE file in top-level directory"
import logging
log = logging.getLogger(__name__)
import httplib
import cgi

from ndg.security.server.wsgi.openid.provider import RenderingInterface

quoteattr = lambda s: '"%s"' % cgi.escape(s, 1)

class DemoRenderingInterface(RenderingInterface):
    """Example rendering interface class for demonstration purposes"""
   
    def identityPage(self, environ, start_response):
        """Render the identity page.
        
        @type environ: dict
        @param environ: dictionary of environment variables
        @type start_response: callable
        @param start_response: WSGI start response function.  Should be called
        from this method to set the response code and HTTP header content
        @rtype: basestring
        @return: WSGI response
        """
        path = environ.get('PATH_INFO').rstrip('/')
        userIdentifier = path.split('/')[ - 1]
        
        link_tag = '<link rel="openid.server" href="%s">' % \
              self.urls['url_openidserver']
              
        yadis_loc_tag = '<meta http-equiv="x-xrds-location" content="%s">' % \
            (self.urls['url_yadis'] + '/' + userIdentifier)
            
        disco_tags = link_tag + yadis_loc_tag
        ident = self.base_url + path

        response = self._showPage(environ,
                                  'Identity Page',
                                  head_extras=disco_tags,
                                  msg='<p>This is the identity page for %s.'
                                      '</p>' % ident)
        
        start_response("200 OK",
                       [('Content-type', 'text/html' + self.charset),
                        ('Content-length', str(len(response)))])
        return response
    
        
    def login(self, environ, start_response,
              success_to=None, fail_to=None, msg=''):
        """Render the login form.
        
        @type environ: dict
        @param environ: dictionary of environment variables
        @type success_to: basestring
        @param success_to: URL put into hidden field telling  
        OpenIDProviderMiddleware.do_loginsubmit() where to forward to on 
        successful login
        @type fail_to: basestring
        @param fail_to: URL put into hidden field telling  
        OpenIDProviderMiddleware.do_loginsubmit() where to forward to on 
        login error
        @type msg: basestring
        @param msg: display (error) message below login form e.g. following
        previous failed login attempt.
        @rtype: basestring
        @return: WSGI response
        """
        
        if success_to is None:
            success_to = self.urls['url_mainpage']
            
        if fail_to is None:
            fail_to = self.urls['url_mainpage']
        
        form = '''\
<h2>Login</h2>
<form method="GET" action="%s">
  <input type="hidden" name="success_to" value="%s" />
  <input type="hidden" name="fail_to" value="%s" />
  <table cellspacing="0" border="0" cellpadding="5">
    <tr>
        <td>Username:</td> 
        <td><input type="text" name="username" value=""/></td>
    </tr><tr>
        <td>Password:</td>
        <td><input type="password" name="password"/></td>
    </tr><tr>
        <td colspan="2" align="right">
            <input type="submit" name="submit" value="Login"/>
            <input type="submit" name="cancel" value="Cancel"/>
        </td>
    </tr>
  </table>
</form>
%s
''' % (self.urls['url_loginsubmit'], success_to, fail_to, msg)

        response = self._showPage(environ, 'Login Page', form=form)
        start_response('200 OK',
                       [('Content-type', 'text/html' + self.charset),
                        ('Content-length', str(len(response)))])
        return response


    def mainPage(self, environ, start_response):
        """Rendering the main page.
        
        @type environ: dict
        @param environ: dictionary of environment variables
        @type start_response: callable
        @param start_response: WSGI start response function.  Should be called
        from this method to set the response code and HTTP header content
        @rtype: basestring
        @return: WSGI response
        """
        
        yadis_tag = '<meta http-equiv="x-xrds-location" content="%s">' % \
                    self.urls['url_serveryadis']
        username = environ['beaker.session'].get('username')    
        if username:
            openid_url = self.urls['url_id'] + '/' + username
            user_message = """\
            <p>You are logged in as %s. Your OpenID identity URL is
            <tt><a href=%s>%s</a></tt>. Enter that URL at an OpenID
            consumer to test this server.</p>
            """ % (username, quoteattr(openid_url), openid_url)
        else:
            user_message = "<p>You are not <a href='%s'>logged in</a>.</p>" % \
                            self.urls['url_login']

        msg = '''\
<p>OpenID server</p>

%s

<p>The URL for this server is <a href=%s><tt>%s</tt></a>.</p>
''' % (user_message, quoteattr(self.base_url), self.base_url)
        response = self._showPage(environ,
                                  'Main Page',
                                  head_extras=yadis_tag,
                                  msg=msg)
    
        start_response('200 OK',
                       [('Content-type', 'text/html' + self.charset),
                        ('Content-length', str(len(response)))])
        return response
    

    def decidePage(self, environ, start_response, oidRequest, oidResponse):
        """Show page giving the user the option to approve the return of their
        credentials to the Relying Party.  This page is also displayed for
        ID select mode if the user is already logged in at the OpenID Provider.
        This enables them to confirm the OpenID to be sent back to the 
        Relying Party
        
        @type environ: dict
        @param environ: dictionary of environment variables
        @type start_response: callable
        @param start_response: WSGI start response function.  Should be called
        from this method to set the response code and HTTP header content
        @type oidRequest: openid.server.server.CheckIDRequest
        @param oidRequest: OpenID Check ID Request object
        @type oidResponse: openid.server.server.OpenIDResponse
        @param oidResponse: OpenID response object
        @rtype: basestring
        @return: WSGI response
        """
        idURLBase = self.urls['url_id'] + '/'
        
        # XXX: This may break if there are any synonyms for idURLBase,
        # such as referring to it by IP address or a CNAME.
        
        # TODO: OpenID 2.0 Allows oidRequest.identity to be set to 
        # http://specs.openid.net/auth/2.0/identifier_select.  See,
        # http://openid.net/specs/openid-authentication-2_0.html.  This code
        # implements this overriding the behaviour of the example code on
        # which this is based.  - Check is the example code based on OpenID 1.0
        # and therefore wrong for this behaviour?
#        assert oidRequest.identity.startswith(idURLBase), \
#               repr((oidRequest.identity, idURLBase))
        userIdentifier = oidRequest.identity[len(idURLBase):]
        username = environ['beaker.session']['username']
        
        if oidRequest.idSelect(): # We are being asked to select an ID
            userIdentifier = self._authN.username2UserIdentifiers(environ,
                                                                  username)[0]
            identity = idURLBase + userIdentifier
            
            msg = '''\
            <p>A site has asked for your identity.  You may select an
            identifier by which you would like this site to know you.
            On a production site this would likely be a drop down list
            of pre-created accounts or have the facility to generate
            a random anonymous identifier.
            </p>
            '''
            fdata = {
                'pathAllow': self.urls['url_allow'],
                'identity': identity,
                'trust_root': oidRequest.trust_root,
                }
            form = '''\
<form method="POST" action="%(pathAllow)s">
<table>
  <tr><td>Identity:</td>
     <td>%(identity)s</td></tr>
  <tr><td>Trust Root:</td><td>%(trust_root)s</td></tr>
</table>
<p>Allow this authentication to proceed?</p>
<input type="checkbox" id="remember" name="remember" value="Yes"
    /><label for="remember">Remember this
    decision</label><br />
<input type="hidden" name="identity" value="%(identity)s" />
<input type="submit" name="Yes" value="Yes" />
<input type="submit" name="No" value="No" />
</form>
''' % fdata
            
        elif userIdentifier in self._authN.username2UserIdentifiers(environ,
                                                                    username):
            msg = '''\
            <p>A new site has asked to confirm your identity.  If you
            approve, the site represented by the trust root below will
            be told that you control identity URL listed below. (If
            you are using a delegated identity, the site will take
            care of reversing the delegation on its own.)</p>'''

            fdata = {
                'pathAllow': self.urls['url_allow'],
                'identity': oidRequest.identity,
                'trust_root': oidRequest.trust_root,
                }
            form = '''\
<table>
  <tr><td>Identity:</td><td>%(identity)s</td></tr>
  <tr><td>Trust Root:</td><td>%(trust_root)s</td></tr>
</table>
<p>Allow this authentication to proceed?</p>
<form method="POST" action="%(pathAllow)s">
  <input type="checkbox" id="remember" name="remember" value="Yes"
      /><label for="remember">Remember this
      decision</label><br />
  <input type="submit" name="Yes" value="Yes" />
  <input type="submit" name="No" value="No" />
</form>''' % fdata
        else:
            mdata = {
                'userIdentifier': userIdentifier,
                'username': username,
                }
            msg = '''\
            <p>A site has asked for an identity belonging to
            %(userIdentifier)s, but you are logged in as %(username)s.  To
            log in as %(userIdentifier)s and approve the login oidRequest,
            hit OK below.  The "Remember this decision" checkbox
            applies only to the trust root decision.</p>''' % mdata

            fdata = {
                'pathAllow': self.urls['url_allow'],
                'identity': oidRequest.identity,
                'trust_root': oidRequest.trust_root,
                'username': username,
                }
            form = '''\
<table>
  <tr><td>Identity:</td><td>%(identity)s</td></tr>
  <tr><td>Trust Root:</td><td>%(trust_root)s</td></tr>
</table>
<p>Allow this authentication to proceed?</p>
<form method="POST" action="%(pathAllow)s">
  <input type="checkbox" id="remember" name="remember" value="Yes"
      /><label for="remember">Remember this
      decision</label><br />
  <input type="hidden" name="login_as" value="%(username)s"/>
  <input type="submit" name="Yes" value="Yes" />
  <input type="submit" name="No" value="No" />
</form>''' % fdata

        response = self._showPage(environ, 'Approve OpenID request?',
                                  msg=msg, form=form)            
        start_response('200 OK',
                       [('Content-type', 'text/html' + self.charset),
                        ('Content-length', str(len(response)))])
        return response
    

    def _showPage(self,
                  environ,
                  title,
                  head_extras='',
                  msg=None,
                  err=None,
                  form=None):
        """Generic page rendering method.  Derived classes may ignore this.
        
        @type environ: dict
        @param environ: dictionary of environment variables
        @type title: basestring
        @param title: page title
        @type head_extras: basestring
        @param head_extras: add extra HTML header elements
        @type msg: basestring
        @param msg: optional message for page body
        @type err: basestring
        @param err: optional error message for page body
        @type form: basestring
        @param form: optional form for page body        
        @rtype: basestring
        @return: WSGI response
        """
        
        username = environ['beaker.session'].get('username')
        if username is None:
            user_link = '<a href="/login">not logged in</a>.'
        else:
            user_link = 'logged in as <a href="%s/%s">%s</a>.<br />'\
                        '<a href="%s?submit=true&'\
                        'success_to=%s">Log out</a>' % \
                        (self.urls['url_id'], username, username,
                         self.urls['url_loginsubmit'],
                         self.urls['url_login'])

        body = ''

        if err is not None:
            body += '''\
            <div class="error">
              %s
            </div>
            ''' % err

        if msg is not None:
            body += '''\
            <div class="message">
              %s
            </div>
            ''' % msg

        if form is not None:
            body += '''\
            <div class="form">
              %s
            </div>
            ''' % form

        contents = {
            'title': 'Python OpenID Provider - ' + title,
            'head_extras': head_extras,
            'body': body,
            'user_link': user_link,
            }

        response = '''<html>
  <head>
    <title>%(title)s</title>
    %(head_extras)s
  </head>
  <style type="text/css">
      h1 a:link {
          color: black;
          text-decoration: none;
      }
      h1 a:visited {
          color: black;
          text-decoration: none;
      }
      h1 a:hover {
          text-decoration: underline;
      }
      body {
        font-family: verdana,sans-serif;
        width: 50em;
        margin: 1em;
      }
      div {
        padding: .5em;
      }
      table {
        margin: none;
        padding: none;
      }
      .banner {
        padding: none 1em 1em 1em;
        width: 100%%;
      }
      .leftbanner {
        text-align: left;
      }
      .rightbanner {
        text-align: right;
        font-size: smaller;
      }
      .error {
        border: 1px solid #ff0000;
        background: #ffaaaa;
        margin: .5em;
      }
      .message {
        border: 1px solid #2233ff;
        background: #eeeeff;
        margin: .5em;
      }
      .form {
        border: 1px solid #777777;
        background: #ddddcc;
        margin: .5em;
        margin-top: 1em;
        padding-bottom: 0em;
      }
      dd {
        margin-bottom: 0.5em;
      }
  </style>
  <body>
    <table class="banner">
      <tr>
        <td class="leftbanner">
          <h1><a href="/">Python OpenID Provider</a></h1>
        </td>
        <td class="rightbanner">
          You are %(user_link)s
        </td>
      </tr>
    </table>
%(body)s
  </body>
</html>
''' % contents

        return response

    def errorPage(self, environ, start_response, msg, code=500):
        """Display error page 
        
        @type environ: dict
        @param environ: dictionary of environment variables
        @type start_response: callable
        @param start_response: WSGI start response function.  Should be called
        from this method to set the response code and HTTP header content
        @type msg: basestring
        @param msg: optional message for page body
        @rtype: basestring
        @return: WSGI response
        """
        
        response = self._showPage(environ, 'Error Processing Request', err='''\
        <p>%s</p>
        <!--

        This is a large comment.  It exists to make this page larger.
        That is unfortunately necessary because of the "smart"
        handling of pages returned with an error code in IE.

        *************************************************************
        *************************************************************
        *************************************************************
        *************************************************************
        *************************************************************
        *************************************************************
        *************************************************************
        *************************************************************
        *************************************************************
        *************************************************************
        *************************************************************
        *************************************************************
        *************************************************************
        *************************************************************
        *************************************************************
        *************************************************************
        *************************************************************
        *************************************************************
        *************************************************************
        *************************************************************
        *************************************************************
        *************************************************************
        *************************************************************

        -->
        ''' % msg)
        
        start_response('%d %s' % (code, httplib.responses[code]),
                       [('Content-type', 'text/html' + self.charset),
                        ('Content-length', str(len(response)))])
        return response
