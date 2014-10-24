import pylons
from pylons.templating import Buffet
from pylons import config
import authtest.lib.helpers as h
import logging
log = logging.getLogger(__name__)

class MyBuffet(Buffet):
    def _update_names(self, ns):
        return ns

def_eng = config['buffet.template_engines'][0]
log.info("def_eng = %s" % def_eng)
buffet = MyBuffet(
    def_eng['engine'],
    template_root=def_eng['template_root'],
    **def_eng['template_options']
)

for e in config['buffet.template_engines'][1:]:
    buffet.prepare(
        e['engine'],
        template_root=e['template_root'],
        alias=e['alias'],
        **e['template_options']
    )

class State:
    pass

c = State()
c.openid = 'None'

def make_template():
    return buffet.render(
        template_name="signin",
        namespace=dict(h=h, c=State())
    ).replace("%", "%%").replace("FORM_ACTION", "%s")
