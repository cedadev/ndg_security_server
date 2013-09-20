<html py:extends="'ndgpage.kid'" xmlns="http://www.w3.org/1999/xhtml" xmlns:py="http://purl.org/kid/ns#">
	<div py:def="openIDSignin()" class="openIDSignin" style="text-indent:5px">
		<form action="$c.baseURL/verify" method="post">
		  <table cellspacing="0" border="0" cellpadding="5">
		    <tr>
		        <td>OpenID:</td> 
		        <td>
		        	<input type="text" name="openid" value="" class='openid-identifier' size="30"/>
		        </td>
		        <td align="right">
		        	<input type="submit" name="authform" value="Go"/>
		        </td>
		        <td>
		        	<a href="http://openid.net/what/" target="_blank"><small>What's this?</small></a>
		        </td>
		    </tr>
		  </table>
		</form>
	</div>

    <head>
  		<style>
			input.openid-identifier {
			   background: url($c.baseURL/layout/openid-inputicon.gif) no-repeat;
			   background-color: #fff;
			   background-position: 0 50%;
			   padding-left: 18px;
			}
  		</style>
    	<replace py:replace="pagehead()"/>
    </head>
    <body>
        <div py:replace="header()"/>
    	<replace py:replace="openIDSignin()"/>
        <div py:replace="footer(showLoginStatus=False)"/>
    </body>
</html>