<html xmlns="http://www.w3.org/1999/xhtml" xmlns:py="http://purl.org/kid/ns#">
    <head py:def="pagehead()" py:strip="True">
        <title>$c.title</title>
        <meta name="description" 
            content="Assisting atmospheric researchers to locate, access and interpret atmospheric data, ensuring the integrity of the atmospheric data produced by the UK's Natural Environment Research Council (NERC)."/>
        <!--  Assisting atmospheric researchers to locate, access and interpret atmospheric data, ensuring the integrity of the atmospheric data produced by the UK's Natural Environment Research Council (NERC).  -->
        <meta name="keywords" 
            content="BADC,NERC,british,atmospheric,data,atmospheric data,centre,UKMO,ECMWF,meteorological,met data,weather,archive,temperature,rain,wind,precipitation."/>
        <meta name="robots" content="all"/>
        <link rel="alternate" type="application/rss+xml"  
            href="http://badc.nerc.ac.uk/community/news/Latest_news.xml" 
            title="BADC News Channel"/>        
        <link rel="stylesheet" type="text/css" href="layout/styles/style.css"/>        
    </head>
    
    <div py:def="whiteGap()" id="whiteGap">
        <!-- white gap -->
        <table width="100%" bgcolor="#ffffff" border="0" cellpadding="0" 
            cellspacing="1">
            <tbody>
                <tr>
                    <td></td>
                </tr>
            </tbody>
        </table>
    </div>
    
    <div py:def="header()" id="header">
        <table BORDER="0" CELLSPACING="0" CELLPADDING="0"> 
            <tr height="7">
            <td width="20"></td>
            </tr> 
            <tr>
                <td><img src="layout/tabs/spacer30.gif"/></td>
                <td><img src="layout/tabs/tabs_white_under_dblue.gif"/></td>
                <td class="badcDarkBlue"><a class="menu"  href="http://badc.nerc.ac.uk/home/"><img border="0" align="middle" src="layout/logos/badc-logo-onblue-30.gif"/>Home</a></td>
                <td><img src="layout/tabs/tabs_dblue_over_lblue.gif"/></td>
                <td class="badcLightBlue"><a class="menu"  href="http://badc.nerc.ac.uk/mybadc">My&nbsp;BADC</a></td>
                <td><img src="layout/tabs/tabs_lblue_over_lblue.gif"/></td>
                <td class="badcLightBlue"><a class="menu"  href="http://badc.nerc.ac.uk/data/">Data</a></td>
                <td><img src="layout/tabs/tabs_lblue_over_lblue.gif"/></td>
                <td class="badcLightBlue"><a class="menu"  href="http://badc.nerc.ac.uk/search/">Search</a></td>
                <td><img src="layout/tabs/tabs_lblue_over_lblue.gif"/></td>
                <td class="badcLightBlue"><a class="menu"  href="http://badc.nerc.ac.uk/community/">Community</a></td>
                <td><img src="layout/tabs/tabs_lblue_over_lblue.gif"/></td>
                <td class="badcLightBlue"><a class="menu"  href="http://badc.nerc.ac.uk/help/">Help</a></td>
                <td><img src="layout/tabs/tabs_lblue_over_white.gif"/></td> 
            </tr>
        </table>
        <table width="100%" height="25" border="0" cellspacing="0"  
            cellpadding="0">
            <tr> 
                <td class="badcDarkBlue">
                    <img src="layout/tabs/topleft.jpg"/>
                </td> 
                <td class="badcDarkBlue">
                    <a class="menu" 
                        href="http://badc.nerc.ac.uk">About&nbsp;the&nbsp;BADC</a>
                </td> 
                <td class="badcDarkBlue">
                    <replace py:replace="showLoginStatus()"/>
                </td> 
                <td class="badcDarkBlue">
                    <a class="menu" 
                        href="http://badc.nerc.ac.uk/reg/user_register_info.html">
                        New&nbsp;User&nbsp;Registration</a>
                </td> 
                <td class="badcDarkBlue">
                    <a class="menu" 
                        href="http://badc.nerc.ac.uk/data/dataset_index">
                        Apply&nbsp;for&nbsp;datasets</a>
                </td> 
                <td width="10" class="badcDarkBlue" align="right">
                    <img src="layout/tabs/topright.jpg"/>
                </td> 
            </tr>
        </table>
        <div py:replace="whiteGap()"/>        
    </div>
    
    <div py:def="ncasLogoStrip()" class="badcDarkBlue">
        <table width="100%" align="top" border="0" cellpadding="0" cellspacing="0">
            <tr>
                <td width="400"></td>
                <td width="400" align="center">
                    <a href="http://www.ncas.ac.uk/">
                        <img src="layout/BADC-NCAS-logo-colour-small.jpg" 
                            alt="The new BADC logo. Click here to go to the NCAS website" 
                            align="top"/>
                    </a>
                </td>                
            </tr>
        </table>        

        <table cellspacing="0" cellpadding="0" border="0" align="bottom" width="100%">
            <tr align="left">
                <td width="400">
                </td>        
            </tr>
        </table>        
    </div>
    
    <div py:def="footer()" id="footer">
        <!-- white gap-->
        <div py:replace="whiteGap()"/>                
        
        <table width="100%" height="25" border="0" cellspacing="0"  
            cellpadding="0">
            <tr> 
                <td bgcolor="#333399" valign="bottom"><img src="layout/tabs/bottomleft.jpg"/></td> 
                <td bgcolor="#333399"><a class="menu" href="http://badc.nerc.ac.uk/">Home</a>&nbsp;&nbsp;&nbsp;</td> 
                <td bgcolor="#333399"><a class="menu" href="http://badc.nerc.ac.uk/help/contact.html">Contact</a>&nbsp;&nbsp;&nbsp;</td>
                <td bgcolor="#333399"><a class="menu" href="http://badc.nerc.ac.uk/conditions/badc_anon.html">Disclaimer</a>&nbsp;&nbsp;&nbsp;</td>
                <td bgcolor="#333399"><div class="lastm">Last Modified:<script>document.write(document.lastModified);</script></div></td>
                <td width="10" bgcolor="#333399" align="right" valign="bottom"><img src="layout/tabs/bottomright.jpg"/></td> 
            </tr>
        </table>
    </div>
    
    <div py:def="largeOldBADCLogo()" class="badcDarkBlue">
        <table cellspacing="0" cellpadding="0" border="0" height="420">
            <tr valign="bottom">
                <td>
                    <img src="layout/this_is_NOT_the_BADC_logo.jpg"
                        style="border:0; vspace:0"
                        width="400" 
                        alt="The Old BADC logo. Map of PV on the 850K isentropic surface over the southern hemisphere from the UK Met Office assimilation. 1200 UTC, 11th October 1992."/>
                </td>
            </tr>
        </table>
    </div>

    <div py:def="showLoginStatus" id="showLoginStatus">
        <a class="menu" py:if="getattr(c, 'loggedIn', False)" href="${g.ndg.security.server.sso.cfg.logoutURI}?r=${g.ndg.security.common.sso.state.b64encReturnToURL}">Log out</a>
        <b py:if="not getattr(c, 'loggedIn', False)">Login</b>
    </div>
</html>
