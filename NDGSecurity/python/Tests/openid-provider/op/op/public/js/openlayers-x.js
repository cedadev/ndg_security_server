/** Extensions to OpenLayers to fine-tune the user interface
    
    @author Stephen Pascoe
*/

SubSelectionMouseToolbar = OpenLayers.Class.create();
SubSelectionMouseToolbar.prototype =
    OpenLayers.Class.inherit(OpenLayers.Control.MouseToolbar, {
	initialize: function(position, direction, boxesLayer) {
	    OpenLayers.Control.MouseToolbar.prototype.initialize.apply(this,
								       [position, direction]);
	    /* Add the sub-selection box to the boxes layer */
	    this.boxesLayer = boxesLayer;
	    this._initSubsel();
	},
	zoomBoxEnd: function(evt) {

	    if (this.mouseDragStart) {
		var start = this.map.getLonLatFromViewPortPx( this.mouseDragStart ); 
		var end = this.map.getLonLatFromViewPortPx( evt.xy );
		var top = Math.max(start.lat, end.lat);
		var bottom = Math.min(start.lat, end.lat);
		var left = Math.min(start.lon, end.lon);
		var right = Math.max(start.lon, end.lon);

		this.activateSubsel(new OpenLayers.Bounds(left, bottom, right, top));
	    }
	    OpenLayers.Control.MouseToolbar.prototype.zoomBoxEnd.apply(this, [evt]);
	},


	setSubSel: function(bounds) {
	    this.activateSubsel(bounds);
	    this.map.zoomToExtent(bounds);
	},

	activateSubsel: function(bounds) {
	    this.subselBox.bounds = bounds;
	    this.subselBox.display(true);
	    this.isSubselActive = true;
	    /* Force a redraw */
	    this.boxesLayer.moveTo(null, true);
	},
	deactivateSubsel: function() {
	    this.subselBox.display(false);
	    this.isSubselActive = false;
	},
	/*
	 * Ideally I'd like to implement these event overrides with the Event mechanism but
	 * I can't figure out how to do it.
	 */
	defaultMouseUp: function(evt) {
	    OpenLayers.Control.MouseToolbar.prototype.defaultMouseUp.apply(this, [evt]);
	    /* Check the subselection hasn't been panned out of the viewport */
	    //if (this.mode == "pan") {
	    this.checkSubselVisibility(this.map.getExtent());
	    //}
	    
	},
	defaultWheelUp: function(evt) {
	    OpenLayers.Control.MouseToolbar.prototype.defaultWheelUp.apply(this, [evt]);
	    this.checkSubselVisibility(this.map.getExtent());
	},
	
	/** Get either the subselection or the complete viewport bounds  */
	getActiveBounds: function() {
	    if (this.isSubselActive) {
		return this.subselBox.bounds;
	    }
	    else {
		return this.map.getExtent();
	    }
	},

	_initSubsel: function() {
	    var subsel = new OpenLayers.Bounds(-180,-90, 180, 90);
	    this.subselBox = new OpenLayers.Marker.Box(subsel);
	    this.subselBox.div.style.borderStyle = 'dashed';
	    this.subselBox.display(false);
	    this.boxesLayer.addMarker(this.subselBox);
	    this.isSubselActive = false;
	},
	/** Check the subselection is within bounds and deactivate if not. */
	checkSubselVisibility: function(bounds) {
	    if (!this.isSubselActive) { return; }

	    var sbounds = this.subselBox.bounds;
	    if ((bounds.left > sbounds.left) ||
		(bounds.right < sbounds.right) ||
		(bounds.bottom > sbounds.bottom) ||
		(bounds.top < sbounds.top)) {
		this.deactivateSubsel();
	    }
	}

    });




DDCVisMap = OpenLayers.Class.create();
DDCVisMap.prototype = OpenLayers.Class.inherit(OpenLayers.Map, {
    setCenter: function(center, zoom, dragging) {

        if (center == null) {
            center = this.getCenter();
        }                
        if (zoom == null) {
            zoom = this.getZoom();
        }

	var resolution = this.baseLayer.resolutions[zoom];
	var size = this.getSize();
	var w_deg = size.w * resolution;
	var h_deg = size.h * resolution;
        
	var bounds = new OpenLayers.Bounds(center.lon - w_deg / 2,
					   center.lat - h_deg / 2,
					   center.lon + w_deg / 2,
					   center.lat + h_deg / 2);

	if (bounds.left < -180.0) {
	    center.lon = center.lon + (-180.0 - bounds.left);
	}
	else if (bounds.right > 180.0) {
	    center.lon = center.lon - (bounds.right - 180.0);
	}

	if (bounds.bottom < -90.0) {
	    center.lat = center.lat + (-90.0 - bounds.bottom);
	}
	else if (bounds.top > 90.0) {
	    center.lat = center.lat - (bounds.top - 90.0);
	}

	OpenLayers.Map.prototype.setCenter.apply(this, [center, zoom, dragging]);
    }
});
