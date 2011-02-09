"""NDG Security server package Pylons extensions module

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "18/05/10"
__copyright__ = "(C) 2010 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
import logging
log = logging.getLogger(__name__)

import httplib

from pylons import request
from pylons.controllers.util import abort, redirect


class AuthenticationDecorators(object):
    """Login and logout decorators for Pylons controllers
    
    e.g.
    
    class MyController(BaseController):
        @PylonsExtensions.login
        def action1(self):
            return render('/loggedin.mako')
            
        @PylonsExtensions.logout
        def action2(self):
            '''Logout decorator redirects the caller to the referrer.  The
            content of this method is not invoked
            '''
    """
    USER_ENVIRON_KEYNAME = 'REMOTE_USER'
    AUTHKIT_CFG_ENVIRON_KEYNAME = 'authkit.config'
    AUTHKIT_CFG_COOKIE_SIGNOUTPATH_ENVIRON_KEYNAME = 'cookie.signoutpath'
    
    @classmethod
    def login(cls, action):
        '''Decorator to invoke login
        
        @param action: decorated controller action method
        @type action: instancemethod
        @return: wrapper function wrapping the input controller action and 
        invoking login
        @rtype: function
        '''
        def loginWrapper(obj):
            '''Wrapper to the input action invokes login middleware if no
            username key is set in environ
            
            @param obj: controller object
            @type obj: BaseController
            @return: controller action response
            @rtype: list/iterator/string
            '''
            if cls.USER_ENVIRON_KEYNAME not in request.environ:
                abort(httplib.UNAUTHORIZED)
                
            return action(obj)
    
        return loginWrapper
    
    @classmethod
    def logout(cls, action):
        '''Decorator to logout user
        
        @param action: decorated controller action method
        @type action: instancemethod
        @return: wrapper function wrapping the input controller action and 
        invoking logout
        @rtype: function
        '''
        
        def logoutWrapper(obj):
            '''Wrapper to input action invokes logout middleware.  This is 
            based on AuthKit
            
            @param obj: controller object
            @type obj: BaseController
            @return: controller action response
            @rtype: list/iterator/string
            '''
            authKitConfig = request.environ.get(cls.AUTHKIT_CFG_ENVIRON_KEYNAME,
                                                {})
            signoutPath = authKitConfig.get(
                            cls.AUTHKIT_CFG_COOKIE_SIGNOUTPATH_ENVIRON_KEYNAME)
            if signoutPath is not None:
                redirect(signoutPath)
            else:
                log.error("No AuthKit environ[%r][%r] key found.  Unable to "
                          "complete logout", cls.AUTHKIT_CFG_ENVIRON_KEYNAME,
                          cls.AUTHKIT_CFG_COOKIE_SIGNOUTPATH_ENVIRON_KEYNAME)
        
        return logoutWrapper
