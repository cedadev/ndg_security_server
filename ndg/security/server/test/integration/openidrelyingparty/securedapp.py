class TestOpenIDRelyingPartyMiddleware(object):
    '''Test Application for the Authentication handler to protect'''
    response = "Test Authentication redirect application"
       
    def __init__(self, app_conf, **local_conf):
        self.beakerSessionKeyName = app_conf['beakerSessionKeyName']
    
    def __call__(self, environ, start_response):
        
        username = environ[self.beakerSessionKeyName].get('username')
        if username:
            response = """<html>
    <head/>
    <body>
        <p>Authenticated!</p>
        <p><a href="/logout">logout</a></p>
    </body>
</html>"""
            start_response('200 OK', 
                           [('Content-type', 'text/html'),
                            ('Content-length', str(len(response)))])
        else:
            response = "Trigger OpenID Relying Party..."
            start_response('401 Unauthorized', 
                           [('Content-type', 'text/plain'),
                            ('Content-length', str(len(response)))])
        return [response]
    
# To start run 
# $ paster serve services.ini or run this file as a script
# $ ./securedapp.py [port #]
if __name__ == '__main__':
    import sys
    import os
    from os.path import dirname, abspath
    import logging
    logging.basicConfig(level=logging.DEBUG)

    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    else:
        port = 6080
        
    cfgFilePath = os.path.join(dirname(abspath(__file__)), 'securedapp.ini')
        
    from paste.httpserver import serve
    from paste.deploy import loadapp
    from paste.script.util.logging_config import fileConfig
    
    fileConfig(cfgFilePath)
    app = loadapp('config:%s' % cfgFilePath)
    serve(app, host='0.0.0.0', port=port)