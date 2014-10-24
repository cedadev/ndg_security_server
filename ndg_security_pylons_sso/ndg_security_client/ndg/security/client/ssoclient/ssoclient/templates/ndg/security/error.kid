<html py:extends="'ndgPage.kid'" xmlns="http://www.w3.org/1999/xhtml" xmlns:py="http://purl.org/kid/ns#">
    <head>
    <replace py:replace="pagehead()"/>
    </head>
    <body>
    <div id="entirepage">
        <div py:replace="header()"/>
        <?python
        id="contents"
        if "ndgSec" in session: id="contentsRight"
        ?> 
        <div id="${id}">
            <div class="error" py:if="c.xml">
            $c.xml
            </div>
            <pre py:if="c.doc is not None">
$c.doc
            </pre>
        </div>
        <div py:replace="footer()"/>
    </div>
    </body>
</html>