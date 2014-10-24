from authkit.authenticate import middleware, AuthKitConfigError, strip_base
from authkit.authenticate.multi import MultiHandler, status_checker

class Handler:
    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        # Implement your middleware here
        pass

def make_handler(
    app, 
    auth_conf, 
    app_conf=None,
    global_conf=None,
    prefix='authkit.method.openidprovider.', 
):
    app = MultiHandler(app)
    app.add_method('openidprovider', Handler)
    app.add_checker('openidprovider', status_checker)
    return app

