<html py:extends="'badcpage.kid'" xmlns="http://www.w3.org/1999/xhtml"
    xmlns:py="http://purl.org/kid/ns#">

    <div py:def="loginForm()">
        <form action="$g.ndg.security.server.sso.cfg.getCredentials" method="POST">
            <table cellspacing="0" border="0" cellpadding="5">
                <tr>
                    <td>Username:</td>
                    <td>
                        <input type="text" name="username" value=""/>
                    </td>
                </tr>
                <tr>
                    <td>Password:</td>
                    <td>
                        <input type="password" name="passphrase"/>
                    </td>
                </tr>
                <tr>
                    <td colspan="2" align="right">
                        <input type="submit" value="Login"/>
                    </td>
                </tr>
            </table>
        </form>
    </div>

    <div py:def="loginContent(heading='Login:')" class="badcDarkBlue">
        <h1 class="orangeOnBlue">${heading}</h1>
        <replace py:replace="loginForm()"/>
        <p>${c.xml}</p>
        <em>
            Problems logging on? Contact <a 
            href="http://badc.nerc.ac.uk/help/contact.html"
            class="orangeOnBlue">BADC support</a> for help.
        </em>
    </div>

    <head>
        <replace py:replace="pagehead()"/>
    </head>
    <body VLINK="#ffffff" ALINK="#ffffff" LINK="#ffffff">
        <div py:replace="header()"/>
        <replace py:replace="ncasLogoStrip()"/>
        <table cellspacing="0" cellpadding="0" border="0" align="top" bgcolor="#333399" width="100%">
            <tr>
                <td>
                    <replace py:replace="largeOldBADCLogo()"/>
                </td>
                <td width="100%" align="left" valign="top">
                    <replace py:replace="loginContent()"/>
                </td>
            </tr>
        </table>
        <div py:replace="footer()"/>
    </body>

</html>
