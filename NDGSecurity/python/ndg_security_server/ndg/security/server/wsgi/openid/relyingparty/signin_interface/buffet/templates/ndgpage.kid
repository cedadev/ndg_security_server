<!-- This is a bunch of named templates for use in pages -->
<html xmlns="http://www.w3.org/1999/xhtml" xmlns:py="http://purl.org/kid/ns#">
    
    <!-- HTML Header and Document header follow -->
    
    <head py:def="pagehead()" py:strip="True">
        <title py:content="c.title">title</title>
		${XML(c.headExtras)}
        <link media="all, screen" href="${c.baseURL}/layout/ndg2.css" 
            type="text/css" rel="stylesheet"/>
        <link rel="icon" type="image/ico" 
            href="${c.baseURL}/layout/favicon.jpg"/>
    </head>

    <div py:def="header()">
        <div id="header"/>
        <div id="logo"><img src="${c.leftLogo}" alt="${c.leftAlt}" /></div>
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
                    <tr>
                        <td><span py:replace="linkimage(c.ndgLink,c.ndgImage,'NDG')"/></td>
                        <td>OpenID Provider Site for <a href="http://ndg.nerc.ac.uk">NERC DataGrid</a>
                    ${c.disclaimer}</td>
                    </tr>
                    </tbody></table>
                </td>
                <td width="40%" align="center">
                    <div py:if="c.loginStatus" id="loginStatus">
                        <!--! now we choose one of the next two (logged in or not) -->
                        <div py:if="c.loggedIn" id="loggedIn">
                            <table><tbody><tr><td> 
                                Logged in as ${c.session['username']}. 
                                [<a href="$c.logOutURI">Log out</a>]
                            </td></tr></tbody></table>
                        </div>
                    </div>
                </td>
                <td align="right"><span py:replace="linkimage(c.stfcLink,c.stfcImage,'Hosted by the STFC CEDA')"/></td>
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
            <img src="${g['helpIcon']}" alt="Toggle help" class="helpicon"/></a>
      
        </span>
    </span>       
</html>
