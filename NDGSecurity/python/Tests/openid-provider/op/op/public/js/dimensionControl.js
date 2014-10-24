/**
 * Control to display the map coordinate inputs + update these and respond to inputs
 * @class
 *
 * @requires OpenLayers/Events.js
 * @requires OpenLayers/Bounds.js
 *
 * @author C Byrom
 */

WMSC.DimControl = OpenLayers.Class.create();
WMSC.DimControl.prototype = 
{
    EVENT_TYPES: ['changeWMS','changeSelection','clearSelection'],
    GLOBAL_BOUNDS: new OpenLayers.Bounds(-180.0,-90.0,180.0,90.0),

    // The WMS domain and layer parameters of the current selection
    wmsParams: null,
    
	clearButtonID: 'WMSC_clear',
	formID: 'coordsForm',
	dimFormID: 'WMSC_dimDiv',
    controlMarkup:'<div id="WMSC_sel" class="WMSC_domain">'+
	  '<form id="coordsForm"><table>'+
	  '  <tr><td colspan="2"'+
          '          align="center">'+
          '    <input type="text" name="bboxN" size="4" value="90"/><br/>N'+
          '  </td></tr>'+
	  '  <tr>'+
	  '   <td><input type="text" name="bboxW" size="4" value="-180"/> W</td>'+
	  '   <td>E <input type="text" name="bboxE" size="4" value="180"/></td>'+
	  '  </tr>'+
	  '  <tr><td colspan="2" align="center">S<br/>'+
          '    <input type="text" name="bboxS" size="4" value="-90"/>'+
          '  </td></tr>'+
	  '</table>'+
	  '<input id="WMSC_clear" type="button" value="Reset selection"/>'+
	  '</form></div>'+
	  '<div id="WMSC_dimDiv" class="WMSC_domain"><form id="WMSC_dimForm"></form></div>',

	// dimensions of currently selected layer
	currentDims: null,
	
	/**
	 * Constructor to create dimensionControl object
	 *
	 * @param domainDivID - ID of div element to use for domain control
	 * @param formID - ID of form which features the coordinate selection control
	 * @controlMarkup - HTML defining the coordinate selection control; NB, if this
	 *	is not set, a default markup is used
	 */
    initialize: function(domainDivID, formID, controlMarkup) 
    {
    	this.domainDivID = domainDivID;
    	if (formID)
    		this.formID = formID;
		if (controlMarkup)
			this.controlMarkup = controlMarkup;
		this.events = new OpenLayers.Events(this, this.selectionForm,
					    this.EVENT_TYPES);
		this.wmsParams = {};

		// store of the selected dimensions; not used currently, but useful if we're producing output data
		this._selectedDims = {};
		
    	this._initDomainDiv();
    },

	/**
	 * Clean up object
     * - important for IE.
     */
    destroy: function() 
    {
		this.events.destroy();
    },

    /**
     * Listener to trigger a change selection event
     */
    _selectionListener: function() 
    {
		this.events.triggerEvent('changeSelection');
    },
    
    /**
     * Set the div with the coord data up 
     * - including specifying event listeners and handlers
     */
    _initDomainDiv: function() 
    {
    	var domainDiv = $(this.domainDivID); 
		domainDiv.innerHTML = this.controlMarkup;

		// NB, not all controls may have a clear button
		var clearButton = $(this.clearButtonID);
		if (clearButton)
			clearButton.onclick = this._clearSelection.bindAsEventListener(this);
			
		var listener = this._selectionListener.bindAsEventListener(this);

		this.selectionForm = $(this.formID);

		for (var i=0; i < this.selectionForm.elements.length; i++) 
		{
		    this.selectionForm.elements[i].onchange = listener;
		}
	
		this.setSelection(this.GLOBAL_BOUNDS);
    },
    
    
    /**
     * Reset displayed coords to full global bounds
     */
    _clearSelection: function() 
    {
		this.events.triggerEvent('clearSelection');
    },
    
    /*
     * Retrieve selected coord data
     */
    getSelection: function() 
    {
		return new OpenLayers.Bounds(this.selectionForm.bboxW.value,
				     this.selectionForm.bboxS.value,
				     this.selectionForm.bboxE.value,
				     this.selectionForm.bboxN.value);
    },
		
	/**
	 * Update displayed coordinate selection - mapping to the
	 * bounding box displayed in the map layer
	 * NB, data is validated, to flip negative area selections, before being set
	 *
	 * @param bbox - openlayers bounds object
	 * @param noCascade - if false trigger a changeSelection event 
	 */
    setSelection: function(bbox, noCascade) 
    {
		var old_b = this.getSelection();

		// Validation.  negative tests required to catch NaN
		if (!(bbox.left >= -180.0 && bbox.left < 180.0))
		    bbox.left = old_b.left;

		if (!(bbox.right > -180.0 && bbox.right <= 180.0))
		    bbox.right = old_b.right;
	
		if (!(bbox.top > -90.0 && bbox.top <= 90.0))
		    bbox.top = old_b.top;
	
		if (!(bbox.bottom >= -90.0 && bbox.bottom < 90.0))
		    bbox.bottom = old_b.bottom;
	
		if (bbox.left > bbox.right) 
		{
	    	var t = bbox.left; 
	    	bbox.left = bbox.right; 
	    	bbox.right = t;
		}
	
		if (bbox.bottom > bbox.top) 
		{
	    	var t = bbox.bottom; 
	    	bbox.bottom = bbox.top; 
	    	bbox.top = t;
		}
		
		this.selectionForm.bboxW.value = bbox.left.toFixed(1);
		this.selectionForm.bboxS.value = bbox.bottom.toFixed(1);
		this.selectionForm.bboxE.value = bbox.right.toFixed(1);
		this.selectionForm.bboxN.value = bbox.top.toFixed(1);

		if (noCascade != true) {
	    	this.events.triggerEvent('changeSelection');
		}
    },


	/**
  	 * Update the selections div with dimensions relevant to the
 	 * currently selected layer
 	 *
 	 * @param dims - OpenLayers.Bounds object with current bounds
 	 */
    updateDomainDiv: function(dims) 
    {
    	this.currentDims = dims;
		var dimId, dimText, div, i;

		$(this.dimFormID).innerHTML = '';
		for (id in dims) 
		{
	    	div = document.createElement('div');
	    	div.innerHTML = '<b>'+dims[id].getName()+'</b> '
	    	select = document.createElement('select');
	    	select.name = id;
	    	extent = dims[id].getExtent();

		    this.wmsParams[id] = extent[0];
		    this._selectedDims[id] = this.getDimensionText(dims[id], extent[0]);
	    
	    	for (i=0; i<extent.length; i++) 
	    	{
				option = document.createElement('option');
				option.innerHTML = this.getDimensionText(dims[id], extent[i]);
				// Required for IE6
				option.value = extent[i];
				select.appendChild(option);
	    	}

	    	Event.observe(select, 'change', this._selectDimValue.bindAsEventListener(this));
	    	div.appendChild(select);
	    	$(this.dimFormID).appendChild(div);
		}
    },
  
    /**
     * Respond to a selection of dimension - by adding this data to the selected parameters
     * and updating the displayed maps
     *
     * @param evt
     */
    _selectDimValue: function(evt) 
    {
		var select = Event.element(evt);
		var value = select.options[select.selectedIndex].value;
		var tst = this.dims;

		this._selectedDims[select.name] = this.getDimensionText(this.currentDims[select.name], value);
		this.wmsParams[select.name] = value;

		this.events.triggerEvent('changeWMS');
    },
    
    getDimensionText: function(dim, value) {
	return value;
    }
    
};

