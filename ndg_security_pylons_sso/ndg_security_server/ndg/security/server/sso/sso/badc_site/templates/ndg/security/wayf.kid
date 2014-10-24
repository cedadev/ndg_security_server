<html py:extends="'login.kid'" xmlns="http://www.w3.org/1999/xhtml" xmlns:py="http://purl.org/kid/ns#">
    <head>
        <replace py:replace="pagehead()"/>
        <style>
            input.openid-identifier {
            background: url(/layout/openid-inputicon.gif) no-repeat;
            background-color: #fff;
            background-position: 0 50%;
            padding-left: 18px;
            }
        </style>
    </head>
    <body VLINK="#ffffff" ALINK="#ffffff" LINK="#ffffff">
        <div py:replace="header()"/>
        <replace py:replace="ncasLogoStrip()"/>
        <div class="badcDarkBlue" style="valign: bottom">
            <table cellspacing="0" cellpadding="0" border="0" width="100%">        
                <tr>
                    <td>
                        <replace py:replace="largeOldBADCLogo()"/>
                    </td>
                    <td width="100%" align="left" valign="top">
                        <div class="badcDarkBlue">
                            <h1 class="orangeOnBlue">Login:</h1>                       
                            <div py:replace="loginForm()"/>
                            <div py:replace="trustedSiteHeading()"/>
                            <div py:replace="trustedSitesList()"/>
                            <div py:replace="openIDSignin()"/>
                            <br/>
                            <em>
                                Problems logging on? Contact <a 
                                href="http://badc.nerc.ac.uk/help/contact.html" 
                                class="orangeOnBlue">BADC support</a> for help.
                            </em>
                            <br/>
                        </div>
                    </td>
                </tr>
            </table>
        </div>
        <div py:replace="footer()"/>
    </body>
    
    <div py:def="trustedSiteHeading()" 
        py:if="g.ndg.security.server.sso.cfg.enableOpenID or len(g.ndg.security.server.sso.state.trustedIdPs) > 0"
        class="badcDarkBlue">        
        <h3 class="orangeOnBlue">Network Login:</h3>
    </div>
    
    <div py:if="len(g.ndg.security.server.sso.state.trustedIdPs) > 0" 
        py:def="trustedSitesList()" class="badcDarkBlue">        
        <p>Using technology developed for the 
            <a href="http://ndg.nerc.ac.uk/" class="orangeOnBlue">NERC DataGrid</a> 
            you can also login via one of our trusted partner
            sites if you have an account with them:
            <?python
                # Sort alphabetically
                providerNames = g.ndg.security.server.sso.state.trustedIdPs.keys()
                providerNames.sort()
            ?>
            <ul py:for="h in providerNames">
                <li> 
                    <a class="orangeOnBlue"
                       href="${g.ndg.security.server.sso.state.trustedIdPs[h]}?r=${g.ndg.security.common.sso.state.b64encReturnToURL}">${h}</a>
                </li>
            </ul>
        </p>
    </div>
    
    <div py:if="g.ndg.security.server.sso.cfg.enableOpenID==True" 
        py:def="openIDSignin()" class="badcDarkBlue">
        <form action="$g.ndg.security.server.sso.cfg.server/verify" method="post">
            <table cellspacing="0" border="0" cellpadding="5">
                <tr>
                    <td>OpenID:</td> 
                    <td>
                        <input type="text" name="openid" value="" class='openid-identifier'/>
                    </td>
                    <td align="right">
                        <input type="submit" name="authform" value="Go"/>
                    </td>
                    <td>
                        <a href="http://openid.net/what/" 
                            target="_blank"
                            class="orangeOnBlue">
                            <small>Find out more about OpenID</small>
                        </a>
                    </td>
                </tr>
            </table>
        </form>
    </div>
</html>
