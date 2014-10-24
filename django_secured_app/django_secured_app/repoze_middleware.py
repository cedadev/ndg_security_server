from paste.httpexceptions import HTTPUnauthorized


class RepozeWhoUrlMatchFilter(object):
    '''Set 401 Unauthorized response if request matches one of a given set of 
    URL paths and repoze.who.identity session key is not set in environ'''
    REPOZE_WHO_ID_ENVIRON_KEYNAME = 'repoze.who.identity'
    URL_MATCH_LIST_OPTNAME = 'url_match_list'
    DEFAULT_PREFIX = 'repoze_url_match_filter.'
    
    def __init__(self, app):
        self._app = app
        self.urlpath_match_list = None
        
    @classmethod
    def filter_app_factory(cls, app, global_conf, prefix=DEFAULT_PREFIX, 
                           **app_conf):
        '''URL paths are whitespace delimited'''
        obj = cls(app)
        optname = prefix + cls.URL_MATCH_LIST_OPTNAME
        obj.urlpath_match_list = app_conf[optname].split()
        
        return obj
        
    def __call__(self, environ, start_response):
        '''Set HTTP 401 Unauthorized response if no repoze.who.identity key is 
        set in environ
        '''
        if (environ['PATH_INFO'] in self.urlpath_match_list and
            environ.get(self.__class__.REPOZE_WHO_ID_ENVIRON_KEYNAME) is None):
            
            return HTTPUnauthorized()(environ, start_response)
        else:
            return self._app(environ, start_response)