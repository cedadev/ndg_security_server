<!-- This is a bunch of named templates for use in pages -->
<html xmlns="http://www.w3.org/1999/xhtml" xmlns:py="http://purl.org/kid/ns#">
    
    <!-- HTML Header and Document header follow -->
    
    <head py:def="pagehead()" py:strip="True">
        <title py:content="c.title">title</title>
        <!--! The following includes the javascript, note that the XML
        function is needed to avoid escaping the < character -->
        ${XML(h.javascript_include_tag(builtins=True))}
        <script type="text/javascript" src="$g.ndg.security.common.sso.cfg.server/js/toggleDiv.js"/>

        <link media="all, screen" href="$g.ndg.security.common.sso.cfg.server/layout/ndg2.css" type="text/css" rel="stylesheet"/>
        <link rel="icon" type="image/ico" href="$g.ndg.security.common.sso.cfg.server/layout/favicon.jpg" />

    </head>

    <div py:def="header()">
        <div id="header"/>
        <div id="logo"><img src="$g.ndg.security.common.sso.cfg.LeftLogo" alt="$g.ndg.security.common.sso.cfg.LeftAlt" /></div>
    </div>
    
    <div py:def="PageTabs(tabv)" id="PageTabs">
        <div id="PageTabRow">
            <ul>
                <span py:for="tab in c.pageTabs">
                    <?python
                    linkto=True
                    if tab[0] == tabv: 
                        status='current'
                        linkto=False
                    else: status='hidden'
                    ?>
                    <li class="$status"><span class="pagetab">
                        ${XML(h.link_to_if(linkto,tab[0],tab[1]))}
                    </span></li> 
                 </span>
            </ul>
        </div>
        <div class="line"/>
        <div class="clear"/>
    </div>
    <py if="c.UpdatePageTabs" py:replace="PageTabs(c.current)"/>

    <!-- Page Footer follows -->
    <div py:def="footer(showLoginStatus=True)" id="Footer">
        <center><table><tbody>
            <tr>
                <td align="left" width="60%">
                    <table><tbody>
                    <tr><td><span py:replace="linkimage(g.ndg.security.common.sso.cfg.ndgLink,g.ndg.security.common.sso.cfg.ndgImage,'NDG')"/></td>
                    <td> This portal is a product of the <a href="http://ndg.nerc.ac.uk"> NERC DataGrid</a>
                    ${g.ndg.security.common.sso.cfg.disclaimer} </td>
                    </tr>
                    </tbody></table>
                </td>
                <td width="40%" align="center">
                    <div py:if="showLoginStatus" id="loginStatus">
                        <!--! now we choose one of the next two (logged in or not) -->
                        <div py:if="'ndgSec' in session"><table><tbody><tr><td> 
                        User [${session['ndgSec']['u']}] logged in at 
                        ${session['ndgSec']['org']} with roles 
                        [${len(session['ndgSec']['roles'])==1 and session['ndgSec']['roles'][0] or ', '.join(session['ndgSec']['roles'])}]</td><td>
                        &nbsp;<span py:replace="logOut()"/></td></tr></tbody></table></div>
                        <div py:if="'ndgSec' not in session">Further services maybe available if you can
                            <span py:replace="logIn()"/></div>
                    </div>
                </td>
                <td align="right"><span py:replace="linkimage(g.ndg.security.common.sso.cfg.stfcLink,g.ndg.security.common.sso.cfg.stfcImage,'Hosted by the STFC CEDA')"/></td>
            </tr>
        </tbody></table></center>
    </div>
    
    <!-- Utility Functions follow -->
    
    <!-- hyperlinked image -->
    <span py:def="linkimage(linkref,imageref,alttext)">
        <a href="$linkref"><image src="$imageref" alt="$alttext" title="$alttext"/></a>
    </span>
    
    <!-- Help Icons -->
    <span py:def="helpIcon(value)">
        <span>
            <a href="javascript:;" title="Toggle help" onclick="toggleDiv(1,'$value','shown','hidden','div'); return false;">
            <img src="$g.ndg.security.common.sso.cfg.helpIcon" alt="Toggle help" class="helpicon"/></a>      
        </span>
    </span>
    
    <!-- Login and out buttons -->    
    <span py:def="logOut()" class="logOut">
	    <?python
	    from base64 import urlsafe_b64encode
	    
	    # Base 64 encode to enable passing around in 'r' argument of query
	    # string for use with login/logout
	    g.ndg.security.common.sso.returnToURL = c.requestURL
	    g.ndg.security.common.sso.b64encReturnToURL = urlsafe_b64encode(c.requestURL)
	    ?>
        <form action="$g.ndg.security.common.sso.cfg.logoutURI">
            <input type="hidden" name="r" value="${g.ndg.security.common.sso.b64encReturnToURL}"/>
            <input type="submit" value="Logout"/>
        </form>
    </span>
    
    <span py:def="logIn()" class="logIn">
	    <?python
	    from base64 import urlsafe_b64encode
	    
	    # Base 64 encode to enable passing around in 'r' argument of query
	    # string for use with login/logout
	    g.ndg.security.common.sso.returnToURL = c.requestURL
	    g.ndg.security.common.sso.b64encReturnToURL = urlsafe_b64encode(c.requestURL)
	    ?>
        <form action="$g.ndg.security.common.sso.cfg.wayfuri">
            <input type="hidden" name="r" value="${g.ndg.security.common.sso.b64encReturnToURL}"/>
            <input type="submit" value="Login"/>
        </form>
    </span>
    
    
    
</html>
