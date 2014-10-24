#!/usr/bin/env python

"""NDG Security CGI test program for passing cookie info between domains

NERC Data Grid Project

P J Kershaw 23/05/06

Copyright (C) 2009 Science and Technology Facilities Council

"""

from Cookie import SimpleCookie

import sys
import cgi
import os
import base64

returnURI = 'https://glue.badc.rl.ac.uk/cgi-bin/xDomainCredsTransfer.py'
__authorisationMethod = None

def main(form=None):
    if form is None:
        form = cgi.FieldStorage()


    if 'requestURI' in form:
        # Request credentials from user's home site
        requestCreds(form['requestURI'].value,
                     returnURI,
                     pageTitle='Going to user home site...',
                     delayTime=3,
                     redirectMsg=\
        'Re-directing to home site to retrieve credentials...')

    elif 'NDG-ID1' in form and 'NDG-ID2' in form:
        # Receive credentials back from home site
        receiveCredsResponse(form['NDG-ID1'].value, form['NDG-ID2'].value)

    elif 'setCookie' in form and 'returnURI' in form:
        # User has logged on at home site and a cookie is now to be set - next
        # step is processCredsRequest() below
        setCookie(returnURI=form['returnURI'].value)

    elif 'returnURI' in form:
        # Home site receives request from remote site for credentials and
        # returns them
        processCredsRequest(form['returnURI'].value,
                            pageTitle='Home Site',
                            delayTime=3,
                            redirectMsg='Processing request from remote site...')
    else:
        showIdPsiteSelect()


def requestCreds(requestURI,
                 returnURI,
                 pageTitle='',
                 delayTime=0,
                 redirectMsg=''):
    """Request credentials from user's home site"""
    output = """Content-type: text/html

<html>
<head>
<title>%s</title>
<meta http-equiv="REFRESH" content="%d; url=%s?returnURI=%s">
</head>
<body>
%s
</body>
</html>""" % (pageTitle, delayTime, requestURI, returnURI, redirectMsg)
    #sys.stderr.write(output)
    print output


def receiveCredsResponse(sessID, sessMgrURI):
    """Remote site receives returned credentials and creates a new cookie for 
    its domain"""
    setCookie(sessID, sessMgrURI)


def processCredsRequest(returnURI, **returnCredsKwArgs):
    """Receive request from remote site for credentials.  Process and return via 
    a redirect"""
    
    # Check for cookie in environment
    if 'HTTP_COOKIE' in os.environ:
        # Cookie is set - check for NDG cookie

        # Get session ID from existing cookie
        cookie = SimpleCookie(os.environ['HTTP_COOKIE'])
        if "NDG-ID1" not in cookie:
            raise Exception, 'Expecting "NDG-ID1" ID for session cookie'

        if "NDG-ID2" not in cookie:
            raise Exception, 'Expecting "NDG-ID2" ID for session cookie'

        returnCreds(returnURI,
                    cookie["NDG-ID1"].value,
                    cookie["NDG-ID2"].value,
                    **returnCredsKwArgs)
    else:
        # No cookie present - display login.  Submit must redirect back to
        # sender
        print """Content-type: text/html

"""
        showLogin(returnURI,
                  setCookie=True,
                  heading="Login",
                  htmlTag=True,
                  bodyTag=True)

def returnCreds(returnURI,
                sessID,
                sessMgrURI,
                pageTitle='',
                delayTime=0,
                redirectMsg=''):
    """User's home site returns credentials to requestor"""

    print """Content-type: text/html

<html>
<head>
<title>%s</title>
<meta http-equiv="REFRESH" content="%d; url=%s?NDG-ID1=%s&NDG-ID2=%s">
</head>
<body>
%s
</body>
</html>""" % (pageTitle, delayTime, returnURI, sessID, sessMgrURI, redirectMsg)


def setCookie(sessID=None, sessMgrURI=None, returnURI=None):
    """Make NDG cookie"""

    cookie = SimpleCookie()
    if not sessID: sessID = base64.urlsafe_b64encode(os.urandom(128))
    if not sessMgrURI: sessMgrURI = base64.urlsafe_b64encode(os.urandom(32))

    cookie['NDG-ID1'] = sessID
    cookie['NDG-ID1']['expires'] = "Tue, 13-12-2006 12:00:00 GMT"
    cookie['NDG-ID2'] = sessMgrURI
    cookie['NDG-ID2']['expires'] = "Tue, 13-12-2006 12:00:00 GMT"

    if returnURI:
        returnURIfield = """<meta http-equiv=\"REFRESH\"
        content=\"0;url=./xDomainCredsTransfer.py?returnURI=%s\">""" % returnURI
    else:
        returnURIfield = ''

    print "Content-type: text/html"
    print cookie.output() + os.linesep + os.linesep
    print """<html>
<head>
<title>Set Cookie</title>
%s
</head>

<body>
    <h1>Cookie set!</h1>
</body>
</html>""" % returnURIfield


def showLogin(returnURI=None,
              setCookie=False,
              htmlTag=False,
              heading=None,
              bodyTag=False):
    """Display initial NDG login form"""

    if htmlTag: print "<html>"

    if isinstance(heading, basestring):
        print """<head>
    <title>%s</title>
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
</head>""" % heading


    if bodyTag: print "<body>"

    if returnURI:
        returnURIfield = "<input type=hidden name=returnURI value=\"%s\">" % \
                                                                    returnURI
    else:
        returnURIfield = ''


    if setCookie:
        setCookieField = "<input type=hidden name=setCookie value=\"1\">"
    else:
        setCookieField = ''


    bAuthorise=False
    if bAuthorise:
        authoriseArg = "<input type=hidden name=authorise value=\"1\">"
    else:
        authoriseArg = ""


    # Set authorisation method default
    authorisationMethodChk = { "allowMapping":              '',
                            "allowMappingWithPrompt" :   '',
                            "noMapping":                 ''}

    if __authorisationMethod is None:
        # Default to safest option for user
        authorisationMethodChk["allowMappingWithPrompt"] = ' checked'
    else:
        authorisationMethodChk[__authorisationMethod] = ' checked'

    print \
"""<script language="javascript">
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
        style.visibility = style.visibility == "visible" ? "hidden":"visible";
    }
//-->
</script>
<h3>NERC Data Grid Site Login (Test)<BR clear=all></h3>
<hr>

<form action="./xDomainCredsTransfer.py" method="POST">

<table bgcolor=#ADD8E6 cellspacing=0 border=0 cellpadding=5>
<tbody>
<tr><td>User Name:</td> <td><input type=text name=userName value="">
</td></tr>
<tr>
    <td>Password:</td>
    <td><input type=password name=passPhrase></td>
</tr>
<tr>
    <td colspan="2" align="right">
        <a href="javascript:toggleLayer('advSettings');">Advanced Settings</a>
        <input type=submit value="Login">
    </td>
</tr>
%s
%s"""  % (returnURIfield, setCookieField)

    print \
"""</tbody></table>
<br>
<div id="advSettings" style="position: relative; visibility: hidden;">
    <h4>Role Mapping for access to other trusted sites</h4>
    <p>Your account has roles or <i>privileges</i> which determine what data you have access to.  If you access data at another NDG trusted site, these roles can be mapped to local roles at that site to help you gain access:
    </p>
    <table bgcolor=#ADD8E6 cellspacing=0 border=0 cellpadding=5>
    <tbody>
    <tr>
    <td>
        <input type="radio" name="authorisationMethod" value="allowMapping"%s>
    </td>
        <td>
            Allow my roles to be mapped to local roles at other NDG trusted sites.
        </td>
    </tr>
    <tr>
        <td>
            <input type="radio" name="authorisationMethod" value="allowMappingWithPrompt"%s>
        </td>
    <td>
        Allow my roles to be mapped, but prompt me so that I may choose which roles to map before gaining access.
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
""" % (authorisationMethodChk['allowMapping'], \
       authorisationMethodChk['allowMappingWithPrompt'], \
       authorisationMethodChk['noMapping'])

    if bodyTag: print "</body>"
    if htmlTag: print "</html>"

    # end of showLogin()


def showIdPsiteSelect(heading="NDG Home Site Select..."):

    print """Content-type: text/html

<html>
<head>
    <title>%s</title>
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
</head>""" % heading


    print "<body>"
    print \
"""<h3>NERC Data Grid Home Site Select (Test)<BR clear=all></h3>
<hr>

<form action="./xDomainCredsTransfer.py" method="POST">
<table bgcolor=#ADD8E6 cellspacing=0 border=0 cellpadding=5>
<tbody>
<tr>
  <td>
    <select name="requestURI">
      <option value="">Select your home site...
      <option value="https://glue.badc.rl.ac.uk/cgi-bin/xDomainCredsTransfer.py">BADC
      <option value="https://gabriel.bnsc.rl.ac.uk/cgi-bin/xDomainCredsTransfer.py">Gabriel
    </select>
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

if __name__ == "__main__":
    main()
