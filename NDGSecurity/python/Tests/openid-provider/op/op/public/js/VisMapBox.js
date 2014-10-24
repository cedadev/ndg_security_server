/** Top-level javascript file for the IPCC DDC visualisation application.

    @author Stephen Pascoe
*/

// NB, this is currently used by visualise.kid; if this is removed (as I think it may be - having been replaced by viewItems)
// then this should also be removed
VisApp = OpenLayers.Class.create();
VisApp.prototype = {
    initialize: function(mapDivId, selectionFormId, colourbarId,
			 mapWidth, numZoomLevels) {

	this.selectionForm = $(selectionFormId);
	this.colourbarDiv = $(colourbarId);
	this.mapWidth = mapWidth;

	// This is taken from Layer.js with slight alterations.  One
	// can't override both numZoomLevels and minResolution with
	// the current OpenLayers code.  Instead calculate resolutions
	// directly.
	var maxResolution = 360.0 / mapWidth;
	var resolutions = new Array();
	for (var i=0; i < numZoomLevels; i++) {
	    resolutions.push(maxResolution / Math.pow(1.4, i));
	}

	this.map = new DDCVisMap(mapDivId, { resolutions: resolutions,
					     controls: []
					   });



	this.boxesLayer = new OpenLayers.Layer.Boxes("Sub-selection");
	this.subselControl = new SubSelectionMouseToolbar(new OpenLayers.Pixel(mapWidth-40,10),
							  'vertical', this.boxesLayer);

	this.map.events.register('moveend', this, this.updateSelectionForm);
	this.map.events.register('zoomend', this, this.updateSelectionForm);
	for (var i=0; i < this.selectionForm.elements.length; i++) {
	    this.selectionForm.elements[i].onchange = this.updateSelectionBox.bindAsEventListener(this);
	}

	this.map.addControl(new OpenLayers.Control.PanZoomBar());
	this.map.addControl(this.subselControl);
	//map.addControl(new OpenLayers.Control.Permalink($('permalink')));
	this.map.addControl(new OpenLayers.Control.MousePosition());
	//map.addControl(new OpenLayers.Control.OverviewMap());
	//this.map.addControl(new OpenLayers.Control.LayerSwitcher());

	// Setup a dummy baselayer.  This will be replaced asynchronously by this.updateVisLayer()
	this.visLayer = new OpenLayers.Layer.WMS("OpenLayers WMS",
						 "http://labs.metacarta.com/wms/vmap0",
						 {layers: 'basic',format: 'image/png'});
	this.map.addLayer(this.visLayer);

	//this.updateVisLayer();
	this.coastLayer = null;
	this._initCoast('coastline_01');


	this.map.addLayer(this.boxesLayer);
	this.map.zoomToExtent(new OpenLayers.Bounds(-180,-90,180,90));	
    },

    _initCoast: function(layerName) {
	if (this.coastLayer) {
	    if (this.coastLayer.params.LAYERS == layerName) {
		return;
	    }
	    else {
		this.map.removeLayer(this.coastLayer);
	    }
	}
	this.coastLayer = new OpenLayers.Layer.WMS("Coastline",
						   "http://labs.metacarta.com/wms/vmap0",
						   {layers: layerName, format: 'image/gif',
						    transparent: 'true'});
	this.map.addLayer(this.coastLayer);
    },


    updateVisLayer: function(wmsURL, featureId, time) {
	if (this.visLayer) {
	    this.map.removeLayer(this.visLayer);
	}
	this.visLayer = new OpenLayers.Layer.WMS("Vis layer",
						 wmsURL,
						 {format: 'img/png',
						  layers: featureId,
						  CRS: 'CRS:84',
						  version: '1.3.0',
						  style: '',
						  time: time});
	this.visLayer.setZIndex(300);
	this.map.addLayer(this.visLayer);
	// Sometimes the coast layer doesn't get drawn at initialisation.
	// This forces a redraw.
	if (this.coastLayer) {
	    this.coastLayer.moveTo(null, true);
	}
	this.loadColourbar(wmsURL, featureId, time);
    },

    loadColourbar: function(wmsURL, featureId, time) {
	console.log('Loading colourbar');
	var url = (wmsURL + '?REQUEST=GetColourbar&LAYERS=' + featureId 
		   + '&TIME=' + time
		   + '&WIDTH=' + this.mapWidth);
	var img = document.createElement('img');
	
	this.colourbarDiv.innerHTML = '<img src="' + url + '"/>';
    },
	

    updateSelectionForm: function() {
	var b = this.subselControl.getActiveBounds();
	this.selectionForm.bboxW.value = b.left.toFixed(1);
	this.selectionForm.bboxS.value = b.bottom.toFixed(1);
	this.selectionForm.bboxE.value = b.right.toFixed(1);
	this.selectionForm.bboxN.value = b.top.toFixed(1);

	// Switch to higerres coasts if needed
	var coastLayer;
	if (this.map.getZoom() > 5) {
	    coastLayer = 'coastline_02';
	}
	else {
	    coastLayer = 'coastline_01';
	}
	if (this.coastLayer && this.coastLayer.params.LAYERS != coastLayer) {
	    this._initCoast(coastLayer);
	}
    },
    updateSelectionBox: function() {
	var old_b = this.subselControl.getActiveBounds();
	var new_b = new OpenLayers.Bounds(
	    Number(this.selectionForm.bboxW.value),
	    Number(this.selectionForm.bboxS.value),
	    Number(this.selectionForm.bboxE.value),
	    Number(this.selectionForm.bboxN.value));
	
	// Validation.  negative tests required to catch NaN
	if (!(new_b.left > -180.0 && new_b.left < 180.0)) {
	    new_b.left = old_b.left;
	}
	if (!(new_b.right > -180.0 && new_b.right < 180.0)) {
	    new_b.right = old_b.right;
	}
	if (!(new_b.top > -90.0 && new_b.top < 90.0)) {
	    new_b.top = old_b.top;
	}
	if (!(new_b.bottom > -90.0 && new_b.bottom < 90.0)) {
	    new_b.bottom = old_b.bottom;
	}
	if (new_b.left > new_b.right) {
	    var t = new_b.left; new_b.left = new_b.right; new_b.right = t;
	}
	if (new_b.bottom > new_b.top) {
	    var t = new_b.bottom; new_b.bottom = new_b.top; new_b.top = t;
	}
	
	this.subselControl.setSubSel(new_b);
    }
	    
};

/** Class to control the VisApp OpenLayers widget.
    @param visApp: The VisApp object.
    @param granuleDescription: An object describing the available granules.  It should have the form:
        { <granuleId>: {<featureId>: {'name':..., 'ftype':..., 'domain': {'time': [...]}}}}

*/
VisControl = function(visApp, granuleDescription, granuleFormId, variableFormId,
		     domainFormId) {
    this.visApp = visApp;
    this.granuleDescription = granuleDescription;
    this.granuleFormId = granuleFormId;
    this.variableFormId = variableFormId;
    this.domainFormId = domainFormId;

    this.endpointAnchor = null;
};
VisControl.prototype = {
    getSelectedFeatureId: function() {
	var variableForm = $(this.variableFormId);
	for (var i=0; i<variableForm.length; i++) {
	    if (variableForm[i].checked) {
		return variableForm[i].value;
	    }
	}
    },
    getSelectedGranuleId: function() {
	var granuleForm = $(this.granuleFormId);
	for (var i=0; i<granuleForm.elements.length; i++) {
	    if (granuleForm.elements[i].name != 'dataset') {
		continue;
	    }
	    if (granuleForm.elements[i].checked) {
		return granuleForm.elements[i].value;
	    }
	}
    },
    updateVisApp: function() {
	var granuleId = this.getSelectedGranuleId();
	var featureId = this.getSelectedFeatureId();
	var domain = {'TIME': $(this.domainFormId)['time'].value};
	this.visApp.updateVisLayer(this.granuleDescription[granuleId]['wmsURI'], featureId,
				   domain['TIME']);
	if (this.endpointAnchor != null) {
	    this.endpointAnchor.href = this.visApp.visLayer.url;
	}
    },
    /** Change the domain fields in this.constraintsFormId to reflect the current variable selection */
    populateDomainOptions: function() {
	// First clear all domain options: !TODO

	// Iterate over domain fields
	var granuleId = this.getSelectedGranuleId()
	var featureId = this.getSelectedFeatureId();
	var domainForm = $(this.domainFormId);
	for (var i=0; i<domainForm.length; i++) {
	    var k = domainForm[i].name;
	    var v = this.granuleDescription[granuleId][featureId]['domain'][k];
	    for (var j=0; j<v.length; j++) {
		var e = document.createElement('option');
		e.name = k; e.value = v[j]; e.appendChild(document.createTextNode(v[j]));
		domainForm[i].appendChild(e);
	    }
	} 
    }       
    
};
