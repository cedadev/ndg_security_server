ndg_security_server
===================
NDG Security Server-side components package

NDG Security is the security system for the UK Natural Environment Research
Council funded NERC DataGrid.  NDG Security has been developed to 
provide users with seamless federated access to secured resources across NDG 
participating organisations whilst at the same time providing an underlying 
system which is easy to deploy around organisation's pre-existing systems. 

More recently the system has been developed in collaboration with the 
US DoE funded Earth System Grid project for the ESG Federation an infrastructure
under development in support of CMIP5 (Coupled Model Intercomparison Project 
Phase 5), a framework for a co-ordinated set of climate model experiments 
which will input into the forthcoming 5th IPCC Assessment Report.

NDG and ESG use a common access control architecture.  OpenID and MyProxy are 
used to support single sign on for browser based and HTTP rich client based 
applications respectively.  SAML is used for attribute query and authorisation
decision interfaces.  NDG Security uses a XACML based policy engine from the 
package ndg_xacml.  NDG Security has been re-engineered to use a filter based 
architecture based on WSGI enabling other Python WSGI based applications to be 
protected in a flexible manner without the need to modify application code.

Releases
--------
 * 2.4.3:
  * Enhancements to authentication redirect interface to allow customisation of
    ``ndg.security.r`` HTTP GET query argument.
 * 2.4.2:
  * fix to Attribute Exchange handling in Genshi renderer.  Renderer now 
    correctly ignores AX if no attributes were requested by the OpenID
    Relying Party.
 * 2.4.1: 
  * fix to OpenID Provider templates
  * pip package requirements file
  * fix bug in ``ndg.security.server.wsgi.openid.provider.OpenIDProviderMiddleware`` -
    reference local oid_response var instead of self member.
  * fix bug in exception handling for authentication interface include
    ``AuthNInterfaceConfigError`` type in exception handling.
 * 2.4.0:
  * update to OpenID Provider to support HTTP Basic Auth to allow easy
    authentication with non-browser based clients.  
  * Added new attribute to SAML PEP filter to allow simpler configuration of
    ignore files i.e. files that shouldn't be passed on by the PEP to the 
    authorisation filter.