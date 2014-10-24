/** 
 *  Control to provide an OpenLayers map with default layers loaded and basic 
 *  functionality to display legend data, output figure plots and interface with
 *  dimension and layer controls.
 *  @class 
 *
 * @requires OpenLayers/Layer.js
 * @requires OpenLayers/Bounds.js
 *
 *  @author C Byrom
 */

WMSC.VisApp = OpenLayers.Class.create();
WMSC.VisApp.prototype = 
{
    /**
     * Constructor to set up object
     * @constructor
     * 
     * @param div - ID of div section to use for map control
     * @param numZoomLevels - number of zoom levels to allow in map
     * @param mapWidth - width of displayed map
     * @param showCoast - true - display coastline, otherwise not
     */
    initialize: function(div, numZoomLevels, mapWidth, showCoast) 
    {
		this.figureCounter = 1;
		this.showCoast = showCoast;

		// NB, can't override both numZoomLevels and minResolution with
		// the current OpenLayers code.  Instead calculate resolutions
		// directly.
		var maxResolution = 360.0 / mapWidth;
		var resolutions = new Array();
		for (var i=0; i < numZoomLevels; i++) 
		{
	    	resolutions.push(maxResolution / Math.pow(1.4, i));
		}

		// set up the map control
		this.map = new DDCVisMap(div, 
			{ 
	    		resolutions: resolutions,
	    		controls: []
		    }
		);
		this.boxesLayer = new OpenLayers.Layer.Boxes("Sub-selection");

		this.subselControl = new SubSelectionMouseToolbar(new OpenLayers.Pixel(mapWidth-40,10),
						   'vertical', this.boxesLayer);

		this.map.addControl(new OpenLayers.Control.PanZoomBar());
		this.map.addControl(this.subselControl);
		this.map.addControl(new OpenLayers.Control.MousePosition());

		// Setup the map - initially with the basic openlayers map + coastline + boxes
		this.updateVisLayer();

		this.maxExtent = new OpenLayers.Bounds(-180,-90,180,90);
		this.map.zoomToExtent(this.maxExtent);	

		// Enter selection mode
		this.subselControl.switchModeTo('zoombox');
    },
    
    /**
     * Specify a dimension control to use with the map
     * @param dimControl - a suitable dimension control
     * - this must include an attribute, wmsParams and a method
     * getSelection retuning an OpenLayers.Bounds object
     */
    addDimensionControl: function(dimControl)
    {
    	this.dimControl = dimControl;
		this.dimControl.events.register('changeSelection', this, this.updateSelectionBox);
		this.dimControl.events.register('changeWMS', this, this.updateVisLayer);
		this.dimControl.events.register('clearSelection', this, this.resetMapCoords);
    	
		this.map.events.register('moveend', this, this.updateDimensionControl);
		this.map.events.register('zoomend', this, this.updateDimensionControl);
    },
    
    
    /**
     * Specify a layer control to use with the map
     * @param layerControl - a suitable layer control
     */
    addLayerControl: function(layerControl)
    {
		layerControl.events.register('changeSelection', this, this.updateSelectionBox);
		layerControl.events.register('changeWMS', this, this.updateVisLayer);
    },
    
    // Cleaning up is important for IE.
    destroy: function() 
    {
    	if (this.dimControl)
    		this.dimControl.destroy();

		if (this.layerControl)
			this.layerControl.destroy();
		this.subselControl.destroy();
    },

	/**
	 * Set up coast layer using the specified layer name
	 */
    _initCoast: function(layerName) 
    {
		// check if coast layer is loaded or if a different coast layer has been specified; reload, if so
    	if (!this.coastLayer || this.coastLayer.params.LAYERS != layerName) 
    	{
			this.coastLayer = new OpenLayers.Layer.WMS("Coastline",
					   "http://labs.metacarta.com/wms/vmap0",
					   {layers: layerName, format: 'image/gif',
					    transparent: 'true'});
    	}
		this.map.addLayer(this.coastLayer);
    },

	/**
	 * Determine whether any layers have been added to the layerlist; if so, add these one by one
	 * to the map
	 * NB, the layers are initially removed to ensure they are not duplicated
	 */
    updateVisLayer: function() 
    {
    	// firstly, remove any existing layers
    	j = this.map.getNumLayers();
		for (var i = 0; i < j; i++)
		{
	    	this.map.removeLayer(this.map.layers[0]);
		}

    	// Setup an initial baselayer - NB, without this, the transparent layers will not display
    	if (!this.visLayer)
    	{
	    	this.visLayer = new OpenLayers.Layer.WMS("OpenLayers WMS",
			     "http://labs.metacarta.com/wms/vmap0",
			     {layers: 'basic',format: 'image/png'});
			
			// add extra parameters, if specified by layer control
			this._mergeDimParams(this.visLayer);
       	}
		this.map.addLayer(this.visLayer);
		
		// retrieve the elements of the layer list and add these to the map
		layerList = document.getElementById("layerlist");

		for (var i = 0; layerList && i < layerList.childNodes.length; i++)
		{
			child = layerList.childNodes[i];
			// ignore any hidden list values
			if (child.className == "hiddenList")
				continue;
			
			if (child.nodeName == "LI")
			{
				// extract the required info and load the map
				// NB, these values are set in the layerControl._updateLeafLayer() method
				// NB, for transparancy to be fully supported, the format must be gif
				// - png is only partially supported and jpg not at all
				endpoint = child.getAttribute("wmcURL");
				title = child.getAttribute("title");
				layerName = child.getAttribute("layerName");
					
		    	mapLayer = new OpenLayers.Layer.WMS(
			    			title,
	    					endpoint,
						     {format: 'image/gif',
						      version: '1.3.0', 
						      CRS: 'CRS:84',
						      layers: layerName,
					    	  transparent: 'true'
						     });
				// add extra parameters, if specified by layer control
				this._mergeDimParams(mapLayer);
       			this.map.addLayer(mapLayer);
			}
		}
			
		// add the coast outline, if required
    	if (this.showCoast)
    		this._initCoast('coastline_01');

		// add layer to represent the subselection box on the layer		
		this.map.addLayer(this.boxesLayer);
		
		// if there is legend data available, display this under the map
		this.loadLegend();
    },
    
    /**
     * If a dimension control has been specified, check if this has any
     * additional params to use when setting up the map layer; add
     * these, if so
     */
    _mergeDimParams: function(mapLayer)
    {
    	if (this.dimControl && this.dimControl.wmsParams)
    	{
			mapLayer.mergeNewParams(this.dimControl.wmsParams);
    	}
		mapLayer.setZIndex(300);
    },	

	/**
	 * Reset the map to display the full global bounds - and update
	 * the coordinate selections to reflect this
	 */
    resetMapCoords: function() 
    {
		this.subselControl.deactivateSubsel();
		this.map.zoomToExtent(this.maxExtent);
		this.updateDimensionControl();
    },

	/**
	 * Check if a legend element is available; if so, check
	 * if the topmost layer isn't a default one; if so, attempt
	 * to load and display legend data for this layer
	 */
    loadLegend: function() 
    {
    	var legend = $('legend');
    	if (!legend)
    		return;
    		
		var setLegend = function (xhr) 
		{
	    	$('legend').innerHTML = '';
			var legendHTML = xhr.responseXML.documentElement.innerHTML;
			if (legendHTML)
		    	$('legend').innerHTML = legendHTML;
		};

		var failure = function (xhr) 
		{
	    	alert('Error: could not load legend data for the last selected layer.');
		};

		// set the legend to be the topmost layer that has been picked
		// NB, there are initially three layers - for the subselection box, coastline and base map
		// - so ignore legend if only three layers
		var layerNo = this.map.layers.length;
		if (layerNo < 4)
		{
	    	legend.innerHTML = '';
			return;
		}
			
		var topLayer = this.map.layers[layerNo - 3];
		
		if (topLayer.url == null) 
		{
	    	legend.innerHTML = '';
		}
		else 
		{
	    	var url = topLayer.getFullRequestString({
				REQUEST: 'GetLegend',
				FORMAT: 'text/html'
	    	});

			var params = {REQUEST: 'GetLegend',
					  ENDPOINT: url};
	    	
	    	new Ajax.Request('', 
				{parameters: params,
	    		method: "get",
		    	onSuccess: setLegend.bindAsEventListener(this),
		    	onFailure: failure.bindAsEventListener(this)
				});
		}
    },
    
	/**
	 * Make a figure of the displayed data
	 * NB, this is not currently properly implemented
	 * and is just replicated from the ipcc dcip codebase
	 * @param typeInput - colour of output figure
	 * @param formatSelect - format of output figure
	 */
    makeFigure: function(typeInput, formatSelect) 
    {
		var clim = this.visLayer;
		//var caption = 'IPCC Data Distribution Centre: www.ipcc-data.org\n' + this.layerControl.getStateDescription().join('.\n');
		for (var i=0; i<typeInput.length; i++) 
		{
	    	if (typeInput[i].checked) 
	    	{
				var figType = typeInput[i].value;
				break;
	    	}
		}

		var url = clim.getFullRequestString({
            	REQUEST: 'GetFigure',
				BBOX: this.subselControl.getActiveBounds().toBBOX(),
				CAPTION: caption,
				TYPE: figType,
	            FORMAT: formatSelect.value
			});
		if (formatSelect.value == 'application/postscript') 
		{
	    	location.href = url;
		}
		else 
		{
	    	window.open(url, 'figure_'+this.figureCounter, 'toolbars=no,location=no,directories=no,menubar=no');
	    	this.figureCounter++;
		}
    },
    
    
    /**
     * If an area has been selected on the map to zoom, update
     * the dimension selection control to reflect this change
     */
    updateDimensionControl: function() 
    {
		var b = this.subselControl.getActiveBounds();
		if (this.dimControl)
			this.dimControl.setSelection(b, noCascade=true);

		// Switch to higerres coasts if needed
		var coastLayer = 'coastline_01';
		if (this.map.getZoom() > 5)
		    coastLayer = 'coastline_02';
	
		if (this.showCoast && this.coastLayer.params.LAYERS != coastLayer) 
		{
	    	this._initCoast(coastLayer);
		}
    },

	/**
	 * Update the selection box displayed on the map
	 * - taking the values from the input coord control
	 */
    updateSelectionBox: function() 
    {
		var old_b = this.subselControl.getActiveBounds();
		var new_b = this.dimControl.getSelection();
	
		// Validation.  negative tests required to catch NaN
		if (!(new_b.left > -180.0 && new_b.left < 180.0)) 
		{
	    	new_b.left = old_b.left;
		}
		if (!(new_b.right > -180.0 && new_b.right < 180.0)) 
		{
	    	new_b.right = old_b.right;
		}
		if (!(new_b.top > -90.0 && new_b.top < 90.0)) 
		{
	    	new_b.top = old_b.top;
		}
		if (!(new_b.bottom > -90.0 && new_b.bottom < 90.0)) 
		{
	    	new_b.bottom = old_b.bottom;
		}
		if (new_b.left > new_b.right) 
		{
	    	var t = new_b.left; 
	    	new_b.left = new_b.right; 
	    	new_b.right = t;
		}
		if (new_b.bottom > new_b.top) 
		{
	    	var t = new_b.bottom; 
	    	new_b.bottom = new_b.top; 
	    	new_b.top = t;
		}
	
		this.subselControl.setSubSel(new_b);
    }
    
};

