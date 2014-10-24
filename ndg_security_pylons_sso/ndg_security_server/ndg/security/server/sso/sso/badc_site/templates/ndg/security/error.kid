<html py:extends="'badcpage.kid'" xmlns="http://www.w3.org/1999/xhtml" xmlns:py="http://purl.org/kid/ns#">
    <head>
    <replace py:replace="pagehead()"/>
    </head>
    <body>
    <div id="entirepage">
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
                            <div py:replace="error()"/>
                        </div>
                    </td>
                </tr>
            </table>
        </div>
        <div py:replace="footer()"/>
    </div>
    </body>
    
    <div py:def="error(title='Error:')" id="error" class="badcDarkBlue">
        <h1 class="orangeOnBlue">$title</h1>
        <div py:if="c.xml">
            $c.xml
        </div>
        <div py:if="not c.xml">
            An internal error has occurred.  Please report the problem to your
            site administrator.
        </div>
        <pre py:if="c.doc is not None">
            $c.doc
        </pre>
    </div>
    
</html>