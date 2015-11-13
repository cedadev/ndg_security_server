'''
Created on 17 Jul 2015

@author: philipkershaw
'''
def keyword_parser(obj, prefix='', **kw):
    '''Parse config items delimited by dots into corresponding objects and 
    members variables
    '''
    for param_name, val in kw.items():
        if prefix:
            _param_name = param_name.rsplit(prefix)[-1]
        else:
            _param_name = param_name
            
        if '.' in _param_name:
            # Further nesting found - split and access corresponding object
            obj_name, obj_attr_name = _param_name.split('.', 1)
            child_obj = getattr(obj, obj_name)
            keyword_parser(child_obj, **{obj_attr_name: val})
        else:
            # Reached the end of nested items - set value and return
            setattr(obj, _param_name, val)
            return

