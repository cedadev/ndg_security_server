'''
Created on Oct 25, 2012

@author: philipkershaw
'''
TEMPLATE = '''
<html 
 xmlns:xi="http://www.w3.org/2001/XInclude" 
 xmlns="http://www.w3.org/1999/xhtml" 
 xmlns:py="http://genshi.edgewall.org/">
    
    <body>
        <div id="main">
        <form action="/do_login" method="post">
            <table cellspacing="0" border="0" cellpadding="5" style="align: left">
                <tr align="left">
                    <td>OpenID:</td> 
                    <td align="left">
                        <input type="text" 
                            name="openid" 
                            value="" 
                            size="48"                                
                        />
                    </td>
                    <td align="right">
                        <input type="submit" name="authform" value="Go"/>                               
                    </td>
                </tr>
            </table>
        </form>
        </div>
    </body>
</html>
'''


class OpenIDRelyPartyLoginFormMiddleware(object):
    def __init__(self, app):
        self._app = app
        self.login_form_path = None
        
    @classmethod
    def filter_app_factory(cls, app, global_conf, **app_conf):
        obj = cls(app)
        obj.login_form_path = app_conf.get('login_form_path', '/login_form')
        
        return obj
        
    def __call__(self, environ, start_response):
        if environ['PATH_INFO'] == self.login_form_path:
            start_response("200 OK",
                           [('Content-length', str(len(TEMPLATE)))])
            return [TEMPLATE]
        else:
            return self._app(environ, start_response)
        