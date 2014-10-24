#!/usr/bin/env perl
use strict;
package NDG::Security::Client;

use Storable qw(freeze thaw);
use Crypt::CBC;
use URI::Escape;
use CGI qw/-debug/;
use Log::Log4perl;
use AppConfig qw/:argcount/;
    

#Log::Log4perl::init($ENV{'NDGSEC_PERL_CLNT_LOGFILE'});
#my $log = Log::Log4perl->get_logger;
my $log;
my %SECURITY_ARG = ('h'=>1, 'roles'=>1, 'sid'=>1, 'org'=>1, 'u'=>1);


sub new 
{
    # Constructor
    my $class = shift;
    my $cfgFilePath = shift; 
    my $cgi = shift;

    # Create a new AppConfig object
    my $cfg = AppConfig->new();
    
    # define all the variables we will use, with defaults were necessary
    $cfg->define(
        'logCfgFilePath' => {ARGCOUNT => ARGCOUNT_ONE},
        'encryptionKey' => {ARGCOUNT => ARGCOUNT_ONE},
        'cookieName' => {ARGCOUNT => ARGCOUNT_ONE},
        'wayfURI' => {ARGCOUNT => ARGCOUNT_ONE},
        'pepCfgFilePath' => {ARGCOUNT => ARGCOUNT_ONE}
    );

    # Read configuration file
    $cfg->file($cfgFilePath);
    
    # Initialise logger
    Log::Log4perl::init($cfg->logCfgFilePath);
    $log = Log::Log4perl->get_logger;
     
    my $self = {
        "cgi"  => undef,
        "cipher" => undef,
        "cookieName" => $cfg->cookieName,
        "wayfURI" => $cfg->wayfURI,
        "b64encReturnToURL" => undef,
        "pepCfgFilePath" => $cfg->pepCfgFilePath,
    };

    bless($self, $class);

    # CGI object for convenient access to http environment
    $self->{cgi} = $cgi or CGI->new();

    # Cipher for encryption of session cookie
    $self->{cipher} = new Crypt::CBC(-key=>$cfg->encryptionKey, 
                                     -cipher=>'Blowfish', 
                                     -salt=>1);
    
    # Supply encoded form of return to URL ready to be passed to SSO Service 
    # for user login
    $self->{b64encReturnToURL} = '';
    
    return $self;
}


# Class method
sub _readCfgFile
{
    my $cfgFilePath = shift;
    
    # create a new AppConfig object
    my $config = AppConfig->new();

    # read configuration file
    $config->file($cfgFilePath);
    
    return $config
}


sub ssoHandler
{
    my $self = shift;
    
    my $virtualHostName = $self->{cgi}->virtual_host();
    my $urlPath = $self->{cgi}->url(-absolute=>1);
        
    if ($self->{cgi}->param('h'))
    {
        # 'h' argument is present in query indicating a GET call from a Single 
        # Sign On Service in response to a login
        
        # Set a cookie based on the query args supplied from the SSO Service 
        # response
        my $cookie = $self->_setSessionFromSSOResp();
        
        # Create query string with security args filtered out
        my $query = $self->_stripSecurityQueryArgs();
        
        my $returnToURL = "http://" . $virtualHostName . $urlPath . $query;
            
        $log->info("Generating redirection header for redirect to "
        		   .$returnToURL."...");

        # nph flag crashes with Apache - intended for MS IIS?
        return $self->{cgi}->redirect(-uri=>$returnToURL, -cookie=>$cookie);
    }
    elsif ($self->{cgi}->param('logout'))
    {
        # Service in response to a logout - strip logout query arg
        my $query = $self->_stripSecurityQueryArgs();

        my $returnToURL = "http://" . $virtualHostName . $urlPath . $query;
        $log->info("Generating redirection header following logout for ".
                   "redirect to ".$returnToURL."...");

        return $self->{cgi}->redirect(-uri=>$returnToURL);
    }
    elsif (! $self->_getSessionFromCookie())
    {
        $self->_makeHttpsReturnToURL();
        my $wayfURI = $self->{wayfURI}."?r=".$self->{b64encReturnToURL};
        $log->info("User not logged in - Generating redirection header for ".
        		   "WAYF: ".$wayfURI."...");
            
        return $self->{cgi}->redirect(-uri=>$wayfURI);
    }
    else
    {
        # No Call to the Single Sign On Service has been made - prepare return 
        # to URL for such a call - encode it ready to be incorporated into a 
        # login request to # the Single Sign On Service
        #
        # URL is set to https to ensure encrypted channel for SSO service -> to
        # THIS SSO client transfer
        $self->_makeHttpsReturnToURL();
        return '';
    }
}


sub _makeHttpsReturnToURL
{
    my $self = shift;
    my $virtualHostName = $self->{cgi}->virtual_host();
    my $urlPath = $self->{cgi}->url(-absolute=>1);
    
    my $returnToURL = "https://" . $virtualHostName . $urlPath;
    my $queryStr = $self->{cgi}->query_string();
    if ($queryStr)
    {
         my $returnToURL .= "?" . $queryStr;
    }
    
    $log->info("Generating return to URL with SSL transport ".
    		   $returnToURL."...");
    
    $self->{b64encReturnToURL} = pyUrlSafeB64Encode($returnToURL);
}

sub _stripSecurityQueryArgs
{
    my $self = shift;
    my %arg = $self->{cgi}->Vars;
    my $queryStr = '?';
    my $key;
    my $val;
    
    # Iterate through the keys adding to the query string only if they are 
    # non-security related and they are a genuine URL parameter
    while (($key, $val) = each %arg)
    {
        if (! $SECURITY_ARG{$key})# && $self->{cgi}->url_param($key))
        {
            $queryStr .= uri_escape($key)."=".uri_escape($val)."&";
        }
    }
    # Remove trailing '&' (or '?' if no args set)
    $queryStr = substr($queryStr, 0, -1);
    return $queryStr;
}


sub _makeCookieFromSession
{
    my $self = shift;
    my $session = shift; # ref to hash
    my $serialisedSess = freeze($session);
    
    my $encrSess = $self->{cipher}->encrypt_hex($serialisedSess);
    $log->info("Encrypted session is: ".$encrSess);
    my $cookie = $self->{cgi}->cookie(
        -name=>$self->{cookieName},
        -value=>$encrSess,
        -path=>'/',
        -expires=>'+8h'
        );

    return $cookie;
}


sub _getSessionFromCookie
{
    my $self = shift;
    
    my $cookie = $self->{cgi}->cookie($self->{cookieName}) || return undef;
    $log->debug("Cookie content is: ".$cookie);
    
    my $serialisedSess;
    eval 
    {
        $serialisedSess = $self->{cipher}->decrypt_hex($cookie)
    };
    if ($@)
    {
        die "Getting user session details: ".$@;
    }
    my $session = thaw($serialisedSess);
    my $sessionMsg;
    my $key;
    my $value;
    
    while(($key, $value) = each(%{$session}))
    {
        $sessionMsg .= "$key=$value\n";
    }
    $log->debug("Retrieved session from cookie: ".$sessionMsg);
    
    return $session;
}
 
 
# Parse query response from SSO Service and set a security session cookie
sub _setSessionFromSSOResp
{
    my $self = shift;
    
    # Process response from IdP
    my $cgi = $self->{cgi};
    my @roles = split(',', $cgi->param('roles'));
    # Separate out NDG Security session args
    my %session = (
        h => $cgi->param('h'), 
        sid => $cgi->param('sid'), 
        u => $cgi->param('u'), 
        org => $cgi->param('org'), 
        roles => \@roles); # reference - set itself messes up hash
        
    my $sessionMsg;
    my $key;
    my $value;
    while (($key, $value) = each(%session))
    {
        $sessionMsg .= "$key=$value; ";
    }
    $log->debug("Setting session: ".$sessionMsg);
    
    return $self->_makeCookieFromSession(\%session);
}


# Policy enforcement Point - provide access control decision given resource 
# constraints and user attributes
sub pep
{
    my $self = shift;
    my $resrcFilePath = shift;
    
    # Retrieve user credentials
    my $session = $self->_getSessionFromCookie();
    
    my $msg = "resource ".$resrcFilePath." for user ".$session->{u}.
    		  " with session ID = ". 
        	  $session->{sid};
    
    # Gather access constraint information for resource
    my @accessInfo = getFTPAccessFileReadPermissionsInfo($resrcFilePath);
    if ($accessInfo[0])
    {
        # Access may be granted if read permission is set to public or if the 
        # file is previously cached
        $log->info("Access granted for ".$msg.": ".$accessInfo[1]->{msg});
        return 1;
    }
    
    # Returns a hash containing (boolean, message)
    $log->debug("Calling pyPEP ...");
    my $decision = pyPEP($accessInfo[1], $session, $self->{pepCfgFilePath});
    if ($decision->{accessGranted})
    {
        $log->info("Access granted for ".$msg);
    }
    else
    {
        $log->info("Access denied to ".$msg.": ".$decision->{msg});
    }
    
    return $decision;
}

use BADC::FTPaccess;

sub getFTPAccessFileReadPermissionsInfo
{
    # Adapted from FTPaccess::read_access for use with NDG Security - changed 
    # so that all access info is returned and now username or user group info 
    # is checked.  The latter needs to be done by python code checking the 
    # user's NDG Attribute Certificate
    
    # Returns flag indicating if the user is allowed to read the directory 
    # containing 
    # the given file. Also returns hash giving information about how the result
    # was arrived at.
    my $filePath = shift;   # File or directory name to check access for
    my %info;
            
    my $ftpaccess_file=BADC::FTPaccess::find_nearest_ftpaccess_file($filePath);
    my $ftpaccess = BADC::FTPaccess->new($ftpaccess_file);
    
    $info{filePath} = $ftpaccess_file;

    # Check that we do actually have an ftpaccess file to interogate. If not 
    # then grant read access
    if (not $ftpaccess) 
    {
        $info{noobj} = 1; 
        $info{msg} = "no .ftpaccess files found";
        return (1, \%info);
    }

    #  Check for public access
    if ($ftpaccess->publicAccess("read")) 
    {
        $info{public} = 1;
        $info{msg} = "file has public read permissions";
        return (1, \%info);
    } 

    #  Check allowed groups
    my @allowGroups = $ftpaccess->allowedGroups("read");
    $info{allowedGroups} = \@allowGroups;

    #  Check any lines that contain multiple groups
    my @requiredGroups = $ftpaccess->allowedMultiGroups("read");
    $info{requiredGroups} = \@requiredGroups;
    
    #  Check if the user's username is explicitly granted access
    my @allowedUsers = $ftpaccess->allowedUsers("read");
    $info{allowedUsers} = \@allowedUsers;
    
    $info{msg} = "username and/or group information is needed to determine ".
    			 "access permissions";
    return (0, \%info);
}

use Inline Python => <<'END';
import base64
def pyUrlSafeB64Encode(str):
    return base64.urlsafe_b64encode(str)
   
import os
from logging.config import fileConfig
   
# TODO: Remove  and set from some other env var
os.environ["NDGSEC_DIR"] = "/var/www/cgi-bin/NDG/Security";
try:
    _logConfig = os.path.join(os.environ["NDGSEC_DIR"],
                              'conf',
                              'ndg-security-pep-log.cfg')
    fileConfig(_logConfig)
except KeyError:
    from warnings import warn
    warn(\
    '"NDGSEC_DIR" environment variable must be set to enable logging config',
    RuntimeWarning)
	
from ndg.security.common.authz.pep import PEP
from ndg.security.common.authz.pdp import PDPError
import logging
log = logging.getLogger(__name__)

def pyPEP(resrcHandle, userHandle, cfgFilePath):
    """Wrapper to NDG Security Python Policy Enforcement Point"""
    
    log.debug("resrcHandle = %s" % resrcHandle)
    #userHandle = dict(h=sessionMgrURI, sid=userSessionID)
    log.debug("userHandle = %s" % userHandle)

    pep = PEP(cfgFilePath=cfgFilePath)
        
    # dict is converted into a reference to a hash
    try:
        pep(resrcHandle, userHandle, None)
    except PDPError, e: 
        return {'accessGranted': 0, 'msg': str(e)}
    
    return {'accessGranted': 1, 'msg': "Access permitted"}
END

1;
__END__

 
