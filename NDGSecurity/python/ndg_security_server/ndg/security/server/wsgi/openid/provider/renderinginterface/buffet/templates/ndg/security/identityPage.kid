<html py:extends="'ndgPage.kid'" xmlns="http://www.w3.org/1999/xhtml" xmlns:py="http://purl.org/kid/ns#">        
    <head>
	    <replace py:replace="pagehead()"/>
    </head>
    <body>
        <div py:replace="header()"/>
        <div class="mainPageContent" style="text-indent:5px">        
            <h2>OpenID Identity Page</h2>
            <p>This is the OpenID Identity Page for user:</p>
            <p>${XML(c.xml)}</p>
        </div>
        <div py:replace="footer()"/>
    </body>
</html>