<html py:extends="'ndgPage.kid'" xmlns="http://www.w3.org/1999/xhtml" xmlns:py="http://purl.org/kid/ns#">
    
    <div py:def="loginForm()" class="loginForm">
        <form action="${c.urls['url_loginsubmit']}" method="POST">
            <input type="hidden" name="success_to" value="$c.success_to" />
            <input type="hidden" name="fail_to" value="$c.fail_to" />
            <table cellspacing="0" border="0" cellpadding="5">
                <tr>
                    <td>Username:</td> 
                    <td><input type="text" name="username" value=""/></td>
                </tr><tr>
                    <td>Password:</td>
                    <td><input type="password" name="password"/></td>
                </tr><tr>
                    <td colspan="2" align="right">
                    	<input type="submit" name="submit" value="Login"/>
                    	<input type="submit" name="cancel" value="Cancel"/>
                    </td>
                </tr>
            </table>
        </form>
    </div>
    
    <head>
    <replace py:replace="pagehead()"/>
    </head>
    <body>
        <div py:replace="header()"/>
        <div class="loginContent" style="text-indent:5px">        
            <h2>Login</h2>
            <div py:replace="loginForm()"/>
            <p>${XML(c.xml)}</p>
        </div>
        <div py:replace="footer()"/>
    </body>

</html>