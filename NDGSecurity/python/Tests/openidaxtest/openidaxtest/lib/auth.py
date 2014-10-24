from authkit.permissions import ValidAuthKitUser
is_valid_user = ValidAuthKitUser()

from authkit.authorize.pylons_adaptors import authorized
from pylons.templating import render_mako as render

def render_signin():
    return render('signin.html')
