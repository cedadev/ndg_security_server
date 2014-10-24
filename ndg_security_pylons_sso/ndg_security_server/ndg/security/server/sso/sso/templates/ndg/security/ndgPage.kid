<!-- This is a bunch of named templates for use in pages -->
<html xmlns="http://www.w3.org/1999/xhtml" xmlns:py="http://purl.org/kid/ns#">
    
    <!-- HTML Header and Document header follow -->
    
    <head py:def="pagehead()" py:strip="True">
        <title py:content="c.title">title</title>
        <!--! The following includes the javascript, note that the XML
        function is needed to avoid escaping the < character -->
        ${XML(h.javascript_include_tag(builtins=True))}
        <script type="text/javascript" src="$g.ndg.security.server.sso.cfg.server/js/toggleDiv.js"/>

        <link media="all, screen" href="$g.ndg.security.server.sso.cfg.server/layout/ndg2.css" type="text/css" rel="stylesheet"/>
        <link rel="icon" type="image/ico" href="$g.ndg.security.server.sso.cfg.server/layout/favicon.jpg" />

    </head>

    <div py:def="header()">
        <div id="header"/>
        <div id="logo"><img src="$g.ndg.security.server.sso.cfg.LeftLogo" alt="$g.ndg.security.server.sso.cfg.LeftAlt" /></div>
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
    <div py:def="footer(showLoginStatus=False)" id="Footer">
        <center><table><tbody>
            <tr>
                <td align="left" width="60%">
                    <table><tbody>
                    <tr><td><span py:replace="linkimage(g.ndg.security.server.sso.cfg.ndgLink,g.ndg.security.server.sso.cfg.ndgImage,'NDG')"/></td>
                    <td> This portal is a product of the <a href="http://ndg.nerc.ac.uk"> NERC DataGrid</a>
                    ${g.ndg.security.server.sso.cfg.disclaimer} </td>
                    </tr>
                    </tbody></table>
                </td>
                <td width="40%" align="center">
                </td>
                <td align="right"><span py:replace="linkimage(g.ndg.security.server.sso.cfg.stfcLink,g.ndg.security.server.sso.cfg.stfcImage,'Hosted by the STFC CEDA')"/></td>
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
            <img src="$g.ndg.security.server.sso.cfg.helpIcon" alt="Toggle help" class="helpicon"/></a>
      
        </span>
    </span>
    
    <!-- Login and out buttons -->    
    <span py:def="logOut()" class="logOut">
        <?python
        from base64 import urlsafe_b64encode
        
        # Base 64 encode to enable passing around in 'r' argument of query
        # string for use with login/logout
        g.ndg.security.common.sso.state.returnToURL = str(c.requestURL)
        g.ndg.security.common.sso.state.b64encReturnToURL = urlsafe_b64encode(c.requestURL)
        ?>
        <form action="$g.ndg.security.server.sso.cfg.logoutURI">
            <input type="hidden" name="r" value="${g.ndg.security.common.sso.b64encReturnToURL}"/>
            <input type="submit" value="Logout"/>
        </form>
    </span>
    
    <span py:def="logIn()" class="logIn">
        <?python
        from base64 import urlsafe_b64encode
        
        # Base 64 encode to enable passing around in 'r' argument of query
        # string for use with login/logout
        g.ndg.security.common.sso.state.returnToURL = str(c.requestURL)
        g.ndg.security.common.sso.state.b64encReturnToURL = urlsafe_b64encode(c.requestURL)
        ?>
        <form action="$g.ndg.security.server.sso.cfg.wayfuri">
            <input type="hidden" name="r" value="${g.ndg.security.common.sso.state.b64encReturnToURL}"/>
            <input type="submit" value="Login"/>
        </form>
    </span>    
</html>
