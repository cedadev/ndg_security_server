<html py:extends="'ndgpage.kid'" xmlns="http://www.w3.org/1999/xhtml" xmlns:py="http://purl.org/kid/ns#">
	<div py:def="loginForm()" class="loginForm" style="text-indent:5px">
		<p>
			Enter your login details here or logon from another site using the 
			OpenID sign in section below:
		</p>
		<form action="$c.actionURI" method="POST">
			<input type="hidden" name="success_to" value="$c.successToURI" />
			<input type="hidden" name="fail_to" value="$c.failToURI" />
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
    	<div class="signin" style="text-indent:5px">
	    	<h2>Login</h2>
	    	<replace py:replace="loginForm()"/>
	    	<h2>Sign in from another trusted site</h2>
	    	<p>If you don't have an account with this site but you have an 
	    		<a href="http://openid.net/">OpenID</a>
	    		you can use this to sign in instead:
	    	</p>
	    	<replace py:replace="openIDSignin()"/>
	    	$c.xml
    	</div>
    	<div py:replace="footer(showLoginStatus=False)"/>
    </body>
</html>