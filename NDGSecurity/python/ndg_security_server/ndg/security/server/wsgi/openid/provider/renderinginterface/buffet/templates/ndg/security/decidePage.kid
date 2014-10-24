<html py:extends="'ndgPage.kid'" xmlns="http://www.w3.org/1999/xhtml" xmlns:py="http://purl.org/kid/ns#">        
    <head>
	    <replace py:replace="pagehead()"/>
    	<!--	    
    	<script src="${c.baseURL}/js/wmsc.js"></script>
    	<script src="${c.baseURL}/js/prototype.js"></script>
    	-->
    </head>
    <body>
        <div py:replace="header()"/>
        <div class="decidePageContent" style="text-indent:5px">  
            <h2>Login to $c.oidRequest.trust_root?</h2>
        	<form method="POST" action="${c.urls['url_allow']}">
        		<table>
        			<input type="hidden" name="identity" value="$c.identityURI" />
        			<tr>
        				<td>
		        			The website $c.oidRequest.trust_root has requested 
		        			your OpenID identifier:
        				</td>
        			</tr>
        			<tr>
	                 	<td>
	                 		<pre><b>$c.identityURI</b></pre>
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
        					<input type="submit" name="ApproveRelyingParty" value="Yes" />
        					<input type="submit" name="RejectRelyingParty" value="No" />
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