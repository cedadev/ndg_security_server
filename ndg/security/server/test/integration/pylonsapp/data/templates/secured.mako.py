# -*- encoding:utf-8 -*-
from mako import runtime, filters, cache
UNDEFINED = runtime.UNDEFINED
__M_dict_builtin = dict
__M_locals_builtin = locals
_magic_number = 5
_modified_time = 1274174083.397857
_template_filename='/home/pjkersha/workspace/ndg_security_python/ndg_security_test/ndg/security/test/integration/pylonsapp/pylonsapp/templates/secured.mako'
_template_uri='/secured.mako'
_template_cache=cache.Cache(__name__, _modified_time)
_source_encoding='utf-8'
from webhelpers.html import escape
_exports = []


def render_body(context,**pageargs):
    context.caller_stack._push_frame()
    try:
        __M_locals = __M_dict_builtin(pageargs=pageargs)
        request = context.get('request', UNDEFINED)
        __M_writer = context.writer()
        # SOURCE LINE 1
        __M_writer(u'Test NDG Security Login and logout decorators for a Pylons application<br />\n<br />\n')
        # SOURCE LINE 3
        if 'REMOTE_USER' in request.environ:
            # SOURCE LINE 4
            __M_writer(u'    <a href="/secured/logout">Logout</a>\n')
            # SOURCE LINE 5
        else:
            # SOURCE LINE 6
            __M_writer(u'    <a href="/secured/login">Login</a>\n')
            pass
        # SOURCE LINE 8
        __M_writer(u'\n')
        return ''
    finally:
        context.caller_stack._pop_frame()


