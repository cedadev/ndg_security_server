<html py:extends="'login.kid'" xmlns="http://www.w3.org/1999/xhtml" xmlns:py="http://purl.org/kid/ns#">
	<head>
		<replace py:replace="pagehead()"/>
		<style py:if="g.ndg.security.server.sso.cfg.enableOpenID==True">
			input.openid-identifier {
			background: url($g.ndg.security.server.sso.cfg.server/layout/openid-inputicon.gif) no-repeat;
			background-color: #fff;
			background-position: 0 50%;
			padding-left: 18px;
			}
		</style>
	</head>
	<body>
		<div py:replace="header()"/>
		<div py:replace="loginContent(heading='Home Login')"/>
		<div py:replace="trustedSiteHeading()"/>
		<div py:replace="trustedSitesList()"/>
		<div py:replace="openIDSignin()"/>
		<div py:replace="footer()"/>
	</body>

	<div py:def="trustedSiteHeading()" class="trustedSiteHeading" style="text-indent:5px">        
		<h4>Trusted Site Login</h4>
	</div>
	
	<div py:if="len(g.ndg.security.server.sso.state.trustedIdPs) > 0" py:def="trustedSitesList()" class="trustedSitesList" style="text-indent:5px">        
		<p>You can also login via one of our trusted partner sites if you have an account with one of them:
			<?python
				# Sort alphabetically
				providerNames = g.ndg.security.server.sso.state.trustedIdPs.keys()
				providerNames.sort()
			?>
			<ul py:for="h in providerNames">
				<li> <a href="${g.ndg.security.server.sso.state.trustedIdPs[h]}?r=${g.ndg.security.common.sso.state.b64encReturnToURL}">${h}</a></li>
			</ul>
		</p>
	</div>
	
	<div py:if="g.ndg.security.server.sso.cfg.enableOpenID==True" py:def="openIDSignin()" class="openIDSignin" style="text-indent:5px">
		<form action="$g.ndg.security.server.sso.cfg.server/verify" method="post">
			<table cellspacing="0" border="0" cellpadding="5">
				<tr>
					<td>OpenID:</td> 
					<td>
						<input type="text" name="openid" value="" class='openid-identifier'/>
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
	
</html>
