/**
 * Top-level definitions of the Javascript WMS client library.
 *
 * Define a namespace for the package.
 */
WMSC = {};

WMSC.DEBUG = false;

WMSC.log = function(msg) 
{
    
    if (!WMSC.DEBUG) return;
    
    try 
    {
		/* If Firebug (and Mozilla?) */
		console.log(msg);
    }
    catch(err) 
    {	
		Debug.write(msg);
    }
}
