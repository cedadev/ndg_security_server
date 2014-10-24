/**
 * This code modified from http://www.nmcmahon.co.uk/ajax/tutorial.php
 * which was copyright 2005-2006 to Niall McMahon, although I expect
 * there is nothing in these lines of code which is not duplicated everywhere
 */
function createRequestObject() {
 
    var req;
 
    if(window.XMLHttpRequest){
       // Firefox, Safari, Opera...
       req = new XMLHttpRequest();
    } else if(window.ActiveXObject) {
       // Internet Explorer 5+
       req = new ActiveXObject("Microsoft.XMLHTTP");
    } else {
       // There is an error creating the object,
       // just as an old browser is being used.
       alert('Problem creating the XMLHttpRequest object');
    }
 
    return req;
 
 }
 
// Make the XMLHttpRequest object
var http = createRequestObject();

function sendRequestGet(act) {
 
    // Talk to a server client script for requests
    http.open('get',"webclient2.py?define="+act);
    http.onreadystatechange = handleResponse;
    http.send(null);
 
 }
function handleResponse() {

    if(http.readyState == 4 && http.status == 200){
 
       // Text returned from python script
       var response = http.responseText;

       if(response) {
          // Update ajaxTest content
          document.getElementById("ndgDefine").innerHTML = response;
       }
 
    }
 
 }
function ManageTabPanelDisplay() {

// Between the parenthesis, list the id's of the div's that 
//     will be effected when tabs are clicked. List in any 
//     order. Put the id's in single quotes (apostrophes) 
//     and separate them with a comma -- all one line.
//
// Only the following line needs to be modified for tabs ...
//
var idlist = new Array('TabHistoryFocus','TabCartFocus','TabHistoryReady','TabCartReady','HistoryContent','CartContent');

if(arguments.length < 1) { return; }
for(var i = 0; i < idlist.length; i++) {
   var block = false;
   for(var ii = 0; ii < arguments.length; ii++) {
      if(idlist[i] == arguments[ii]) {
         block = true;
         break;
         }
      }
   if(block) { document.getElementById(idlist[i]).style.display = "block"; }
   else { document.getElementById(idlist[i]).style.display = "none"; }
   }
}

/**
 * Set all checkboxes in a table to be the same state as the checkbox passed in
 * @param abox: the 'select all' checkbox - NB, the other checkboxes will be set to the same
 *				state as this one
 * @param tableID: the ID of the parent table containing the checkboxes
 */ 
function selectAll(abox, tableID) 
{
	var table = document.getElementById(tableID);
    var cboxes = table.getElementsByTagName('input');
	var l = cboxes.length;

	for (var i = 0; i < l; i++)
	{
    	var n = cboxes[i];
    	if ('checkbox' == n.type && n != abox)
    	{
			n.checked = abox.checked;
    	}
    }
}
 