#!/usr/local/NDG/ActivePython-2.4/bin/python

"""Example NDG Security CGI service based on SecurityCGI base class

NERC Data Grid Project

P J Kershaw 25/05/06

Copyright (C) 2009 Science and Technology Facilities Council

"""
import os
from ndg.security.SecurityCGI import *


class TestSecurityCGI(SecurityCGI):
    """CGI interface test class for NDG Security"""


    #_________________________________________________________________________
    def showLogin(self, returnURI=None, bAuthorise=False, **kwargs):
        """Display initial NDG login form"""

        if returnURI:
            returnURIfield = \
             "<input type=hidden name=\"returnURI\" value=\"%s\">" % returnURI
        else:
            returnURIfield = ''


        if bAuthorise:
            authoriseField = \
                "<input type=hidden name=\"authorise\" value=\"1\">"
        else:
            authoriseField = ""


        # Set authorisation method default
        authorisationMethodChk = {  "allowMapping":              '',
                                    "allowMappingWithPrompt" :   '',
                                    "noMapping":                 ''}

        if self._authorisationMethod is None:
            # Default to safest option for user
            authorisationMethodChk["allowMappingWithPrompt"] = ' checked'
        else:
            authorisationMethodChk[self._authorisationMethod] = ' checked'


        print """Content-type: text/html

<html>
<head>
<title>NDG Login</title>
<style type=\"text/css\">
<!--
.al {
text-align: justify
}
a{
text-decoration:none;
}
a:hover{
color:#0000FF;
}
    body { font-family: Verdana, sans-serif; font-size: 11}
    table { font-family: Verdana, sans-serif; font-size: 11}
-->
</style>
</head>
<body>
    <script language="javascript">
        <!--
            function toggleLayer(layerId)
            {
                if (document.getElementById)
                {
                    // Standard
                    var style = document.getElementById(layerId).style;
                }
                else if (document.all)
                {
                    // Old msie versions
                    var style = document.all[whichLayer].style;
                }
                else if (document.layers)
                {
                    // nn4
                    var style = document.layers[whichLayer].style;
                }
                style.visibility = style.visibility == "visible" ?
"hidden":"visible";            }
        //-->
    </script>
    <h3>NERC Data Grid Site Login (Test)<BR clear=all></h3>
    <hr>

    <form action="%s" method="POST">

    <table bgcolor=#ADD8E6 cellspacing=0 border=0 cellpadding=5>
    <tbody>
    <tr>
      <td>User Name:</td>
      <td><input type=text name="userName" value=""></td>
    </tr>
    <tr>
      <td>Password:</td>
      <td><input type=password name="passPhrase"></td>
    </tr>
    <tr>
      <td colspan="2" align="right">
        <a href="javascript:toggleLayer('advSettings');">
        Advanced Settings
        </a>
        <input type=submit value="Login">
      </td>
    </tr>
    <input type=hidden name="authenticate" value="1">
    </tbody>
    </table>
    %s
    %s
    </form>
</body>
</html>"""  % (self.scriptName, returnURIfield, authoriseField)

        print \
"""    </tbody>
    </table>
    <br>
    <div id="advSettings" style="position: relative; visibility: hidden;">
      <h4>Role Mapping for access to other trusted sites</h4>
      <p>Your account has roles or <i>privileges</i> which determine what data
you have access to.  If you access data at another NDG trusted site, these
roles can be mapped to local roles at that site to help you gain access:
      </p>
    <table bgcolor=#ADD8E6 cellspacing=0 border=0 cellpadding=5>
    <tbody>
      <tr>
        <td><input type="radio" name="authorisationMethod"
value="allowMapping"%s>
        </td>
        <td>
        Allow my roles to be mapped to local roles at other NDG trusted sites.
        </td>
      </tr>
      <tr>
        <td>
          <input type="radio" name="authorisationMethod"
value="allowMappingWithPrompt"%s>
        </td>
        <td>
            Allow my roles to be mapped, but prompt me so that I may choose
which roles to map before gaining access.
        </td>
        <tr>
        <td>
          <input type="radio" name="authorisationMethod" value="noMapping"%s>
        </td>
        <td>
          Don't allow mapping of my roles.
        </td>
        </tr>
      </tbody>
      </table>
    </div>
    </form>
</body>
</html>""" % (authorisationMethodChk['allowMapping'], \
              authorisationMethodChk['allowMappingWithPrompt'], \
              authorisationMethodChk['noMapping'])

        # end of showLogin()


    def showIdPsiteSelect(self, **kwargs):

        if not self.trustedHostInfo:
            self.getTrustedHostInfo()

        print """Content-type: text/html

<html>
<head>
    <title>Select site to retrieve credentials</title>
    <style type=\"text/css\">
    <!--
    .al {
    text-align: justify
    }
    a{
    text-decoration:none;
    }
    a:hover{
    color:#0000FF;
    }
        body { font-family: Verdana, sans-serif; font-size: 11}
        table { font-family: Verdana, sans-serif; font-size: 11}
    -->
    </style>
</head>
<body>
    <form action="%s" method="POST">
    <table bgcolor=#ADD8E6 cellspacing=0 border=0 cellpadding=5>
    <tbody>
    <tr>
      <td>
        <select name="requestURI">
          <option value="">Select your home site...""" % self.scriptName

        for hostname, info in self.trustedHostInfo.items():
            print "<option value=\"%s\">%s" % (info['loginURI'], hostname)

        print \
"""     </select>
      </td>
      <td align="right">
        <input type=submit value="Go">
      </td>
    </tr>
    </tbody>
    </table>
    </form>
</body>
</html>"""

        # end of showIdPsiteSelect()


    #_________________________________________________________________________
    def showCredsReceived(self,
	                      sessCookie,
						  pageTitle='',
						  hdrTxt='',
						  bodyTxt=''):
        """Called from receiveCredsResponse() once a cookie has been created.
        Makes a page to set the cookie and display to the user that they have
        been authenticated.  Derived class should override this method as
        required"""
        print """Content-type: text/html
%s

<html>
<head>
<title>NDG Authentication</title>
    <style type=\"text/css\">
    <!--
    .al {
    text-align: justify
    }
    a{
    text-decoration:none;
    }
    a:hover{
    color:#0000FF;
    }
        body { font-family: Verdana, sans-serif; font-size: 11}
        table { font-family: Verdana, sans-serif; font-size: 11}
    -->
    </style>
</head>
<body>
    New cookie set from credentials transfered from other domain
</body>
</html>""" % sessCookie.output()


#_____________________________________________________________________________
if __name__ == "__main__":

    smWSDL = "http://gabriel.bnsc.rl.ac.uk/sessionMgr.wsdl"
    aaWSDL = 'http://gabriel.bnsc.rl.ac.uk/attAuthority.wsdl'

    smCertFilePath = "/usr/local/NDG/conf/certs/gabriel-sm-cert.pem"
    aaCertFilePath = "/usr/local/NDG/conf/certs/gabriel-aa-cert.pem"

    clntCertFilePath = "../certs/GabrielCGI-cert.pem"
    clntPriKeyFilePath = "../certs/GabrielCGI-key.pem"

    securityCGI = TestSecurityCGI(smWSDL,
                                  aaWSDL,
								  scriptName=os.path.basename(__file__),
                                  smCertFilePath=smCertFilePath,
                                  aaCertFilePath=aaCertFilePath,
                                  clntCertFilePath=clntCertFilePath,
                                  clntPriKeyFilePath=clntPriKeyFilePath)
    securityCGI()