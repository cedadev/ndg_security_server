Test NDG Security Login and logout decorators for a Pylons application<br />
<br />
% if 'REMOTE_USER' in request.environ:
    <a href="/secured/logout">Logout</a>
% else:
    <a href="/secured/login">Login</a>
% endif

