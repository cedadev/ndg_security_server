<html py:extends="'ndgPage.kid'" xmlns="http://www.w3.org/1999/xhtml" xmlns:py="http://purl.org/kid/ns#">        
    <head>
	    <replace py:replace="pagehead()"/>
    	<script src="${g['server']}/js/wmsc.js"></script>
    	<script src="${g['server']}/js/prototype.js"></script>
    	<script src="http://www.openlayers.org/api/OpenLayers.js"></script>
    	<script src="${g['server']}/js/openlayers-x.js"/>
    	<script src="${g['server']}/js/dimensionControl.js"/>
    	<script src="${g['server']}/js/mapControl.js"/>
    </head>
    <body>
        <div py:replace="header()"/>
        <div class="decidePageContent" style="text-indent:5px">  
        	<?python
        		if c.oidRequest.idSelect():
        			identityURL = c.urls['url_id']+'/'+c.session['username']
        		else:
        			identityURL = c.oidRequest.identity
        	?>
            <h2>Login to $c.oidRequest.trust_root?</h2>
<!--         	<div class="loginHdr">Login<span py:replace="helpIcon('fts_help')"/></div>
        	<div id="fts_help" class="hidden">
        		<div class="helptxt">
        			<p>
        				Although you are logged into this site, you also need 
        				to decide whether to allow your details to be
        				returned to $c.oidRequest.trust_root so that you are 
        				logged in there too.  The details passed back include
        				the OpenID identifier given below.  The details don't
        				include you login password.
        			</p>
        		</div>
        	</div>
-->
        	<form method="POST" action="${c.urls['url_allow']}">
        		<table>
        			<tr>
        				<td>
		        			The website $c.oidRequest.trust_root has requested 
		        			your OpenID identifier:
        				</td>
        			</tr>
        			<tr>
	                 	<td>
	                 		<pre><b>$identityURL</b></pre>
	                 	</td>
	                </tr>
        			<tr>
        				<td>        					
	        				Would you like to pass your OpenID credential
	        				information back to $c.oidRequest.trust_root and 
	        				return to this site?  
        				</td>
        			</tr>
        			<tr>
        				<td align="right">
        					<input type="submit" name="Yes" value="Yes" />
        					<input type="submit" name="No" value="No" />
        				</td>
        			</tr>
        			<tr>
        				<td align="right">
        					<div py:if="c.oidRequest.trust_root not in c.session.get('approved', {})">
	        					<input type="checkbox" id="remember" name="remember" value="yes"/>
	        					<label for="remember">Remember this decision</label>
        					</div>
        				</td>
        			</tr>
        		</table>
        	</form>
        </div>
        <div py:replace="footer()"/>
    </body>
</html>