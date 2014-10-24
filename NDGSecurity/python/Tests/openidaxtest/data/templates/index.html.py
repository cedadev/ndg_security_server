from mako import runtime, filters, cache
UNDEFINED = runtime.UNDEFINED
__M_dict_builtin = dict
__M_locals_builtin = locals
_magic_number = 5
_modified_time = 1263997653.1631539
_template_filename='/home/pjkersha/workspace/ndg_security_python/Tests/openidaxtest/openidaxtest/templates/index.html'
_template_uri='index.html'
_template_cache=cache.Cache(__name__, _modified_time)
_source_encoding='utf-8'
from webhelpers.html import escape
_exports = []


def render_body(context,**pageargs):
    context.caller_stack._push_frame()
    try:
        __M_locals = __M_dict_builtin(pageargs=pageargs)
        self = context.get('self', UNDEFINED)
        __M_writer = context.writer()
        # SOURCE LINE 1
        __M_writer(u'<div id="hd">\n    <div class="yui-gc">\n        <div class="yui-u first">\n            ')
        # SOURCE LINE 4
        __M_writer(escape(self.heading()))
        __M_writer(u'\n        </div>\n\n    </div>\n    ')
        # SOURCE LINE 8
        __M_writer(escape(self.header()))
        __M_writer(u'\n    ')
        # SOURCE LINE 9
        __M_writer(escape(self.tabs()))
        __M_writer(u'\n</div>\n')
        return ''
    finally:
        context.caller_stack._pop_frame()


