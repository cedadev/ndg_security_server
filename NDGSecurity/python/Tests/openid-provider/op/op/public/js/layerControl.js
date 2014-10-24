/** 
 * Control to handle the layer selections when dealing with WMC docs
 * @class
 *
 * @requires OpenLayers/Events.js
 * @requres YAHOO.widget
 * 
 * @author C Byrom
 */
WMSC.VisAppLayers = OpenLayers.Class.create();
WMSC.VisAppLayers.prototype = {
    EVENT_TYPES: ['changeWMS', 'changeSelection'],

    // The id of an element in which to render the layer selection tree
    treeDiv: null,
    // The id of an element in which to render the field selection list
    layerDiv: null,

    // OpenLayers Events object managing EVENT_TYPES
    events: null,
    
    // The number of layers currently displayed
    layerNo: 0,
    
    // The maximum number of layers to display at once; NB, this needs to equal the 
    // number of drag and drop controls created in dragAndDrop.js
    MAX_LAYER_NO: 10,
    
    /**
     * Constructor to initialise layer control
     * @constructor
     *
     * @param treeDiv - ID of div element in which to place the tree view control
     * @param layerDiv - ID of div element in which to place the layers drag and drop control
     * @param coordControl - coordinate control to use with layerControl
     * 	NB, this control must include a method, updateDomainDiv(OpenLayers.Bounds)
     */
    initialize: function(treeDiv, layerDiv, coordControl) 
    {
		WMSC.log("Initialising Control");
		this.treeDiv = treeDiv;
		this.layerDiv = layerDiv;
		this.coordControl = coordControl;

		this.events = new OpenLayers.Events(this, $(this.treeDiv),
					    this.EVENT_TYPES);

		this._selectedTreeNode = null;
		this._selectedLayer = null;
		this._selectedLayerElement = null;
		this._selectedDims = {};

		this.tree = new YAHOO.widget.TreeView($(this.treeDiv));
		this.tree.subscribe('labelClick', this._selectTreeNode.bindAsEventListener(this));
		
		// Restrict behaviour of tree so that the selected node is always
		// on the open branch.
		this.tree.subscribe('expand', function(node) 
		{
	    	this._selectTreeNode(node);
	    	return true;
		}.bindAsEventListener(this));
    },
    
    /**
     * Cleaning up is important for IE.
     */
    destroy: function() 
    {
		this.events.destroy();
		this.tree.unsubscribe();
    },

    /**
     * Add a WMS doc to the treeview
     * NB, this is not fully tested as the current implementation
     * only uses WMC docs
     * @param wmsEndpoint - endpoint of WMS service
     * @param context - context param - to use in GetCapabilities call
     * @param depth - depth of layer - to use in GetCapabilities call
     */
    addWMS: function(wmsEndpoint, context, depth) 
    {
		var treeNode = new YAHOO.widget.MenuNode(
	             {endpoint: wmsEndpoint,
			      label: "...loading"}, 
			     this.tree.getRoot(), false);
			     
		var f = function(xhr) 
		{
	    	var cap = new WMSC.Capabilities(xhr.responseXML.documentElement);
	    	var tree = this._addLayerTree(
	    		cap.getRootLayer(), 
	    		treeNode.data, 
	    		this.tree.getRoot(), 
	    		treeNode);
	    		
	    	this.tree.draw();
		};

		var params = {REQUEST: 'GetCapabilities'};
		if (context) params.CONTEXT = context;
		if (depth) params.DEPTH = depth;

		// invoke the GetCapabilities call asynchronously via AJAX
		new Ajax.Request(wmsEndpoint, 
			{parameters: params,
	    	method: "get",
	    	onSuccess: f.bindAsEventListener(this)
			});
    },
    
    /**
     * Add listeners to the delete icons on the tree view nodes
     * NB, these are lost each time the tree redraws itself, hence the
     * need to constantly refresh this list
     */
    addListeners: function()
    {
    	for (var i = 0; i <= this.tree.getRoot().children.length; i++)
    	{
    		// get index of child
    		var index = this.tree.getRoot().children[i].index;
	    	var delIcon = document.getElementById("delIcon_" + index);
	    	if (delIcon != null)
	    	{
		    	delIcon.onclick = this._removeNode.bindAsEventListener(this);
		    }
    	}
    },

    /**
     * Add a WMC document to the tree view
     * @param wmsEndpoint - endpoint to retrieve the WMC doc from - NB, this is typically the localhost
     */
    addWebMapContext: function(wmcEndpoint) 
    {
		var treeNode = new YAHOO.widget.TextNode(
	             {wmcEndpoint: wmcEndpoint}, 
			     this.tree.getRoot(), false);
		treeNode.label = this._createNodeLabel("...loading", treeNode.index);
					     
		var bindDataToTree = function(xhr) 
		{
	    	var wmc = new WMSC.WebMapContext(xhr.responseXML.documentElement);
	    	var tree = this._addWMCTree(wmc, 
	    		treeNode.data, 
	    		this.tree.getRoot(), 
	    		treeNode);

	    	this.tree.draw();
	    	
	    	// Add listener to delete icon to allow node to be removed
	    	this.addListeners();
		};

		var params = {REQUEST: 'GetWebMapContext',
					  ENDPOINT: wmcEndpoint};

		// invoke the GetWebMapContext call asynchronously via AJAX
		new Ajax.Request('', 
			{parameters: params,
	    	 method: "get",
	    	 onSuccess: bindDataToTree.bindAsEventListener(this)
			});
    },
    
    
    /**
     * Add WMS sub-layers to tree view as a new tree node
     *
     * @param layer - WMS sublayer to add
     * @param nodeData - additional data to associate with tree node
     * @param parentNode - parent node in treeview
     * @param treeNode - treenode to use; if this is null, a new node is added
     */
    _addLayerTree: function(layer, nodeData, parentNode, treeNode) 
    {
		nodeData.label = layer.getTitle();
		nodeData.layer = layer.getName();
		nodeData.abstract = layer.getAbstract();
		nodeData.layerData = layer;

		var subLayers = layer.getSubLayers();

		// When initialising a top-level node it will 
		// already exist (showing loading indicator).
		// In this case replace data, otherwise create a new node.
		if (treeNode == null) 
		{
	    	var treeNode = new YAHOO.widget.MenuNode(
	    		nodeData, parentNode, false);
		}
		else 
		{
	    	treeNode.data = nodeData;
	    	treeNode.label = nodeData.label;
		}
		
		for (var i=0; i<subLayers.length; i++) 
		{
	    	this._addLayerTree(subLayers[i], 
	    		{endpoint: nodeData.endpoint},
			    treeNode);
		}
		return treeNode;
    },
    
    
    /**
     * Add WMC sub-layers to tree view as a new tree node
     *
     * @param layer - WMS sublayer to add
     * @param nodeData - additional data to associate with tree node
     * @param parentNode - parent node in treeview
     * @param treeNode - treenode to use; if this is null, a new node is added
     */
    _addWMCTree: function(wmc, nodeData, parentNode, treeNode) 
    {
		nodeData.label = wmc.getTitle();
		nodeData.layer = wmc.getTitle();
		nodeData.abstract = wmc.getTitle();

		var subLayers = wmc.getSubLayers();

		// When initialising a top-level node it will 
		// already exist (showing loading indicator).
		// In this case replace data, otherwise create a new node.
		if (treeNode == null) 
		{
	    	var treeNode = new YAHOO.widget.MenuNode(
	    		nodeData, parentNode, false);
		}
		else 
		{
	    	treeNode.data = nodeData;
	    	// NB, add listener later on since the delete is not currently available in the DOM
	    	treeNode.label = this._createNodeLabel(nodeData.label, treeNode.index);
		}
		
		for (var i=0; i<subLayers.length; i++) 
		{
	    	this._addLayerTree(
	    		subLayers[i], 
	    		{endpoint: nodeData.endpoint,
	    		wmcEndpoint: subLayers[i].getEndpoint()},
			    treeNode);
		}
		return treeNode;
    },
    
    /**
     * Add a label to a tree node - with a delete icon appended
     * 
     * @param nodeLabel - text content of label
     * @param nodeIndex - index in tree of label - used to identify the delete event
     */
    _createNodeLabel: function(nodeLabel, nodeIndex)
    {
    	return '<table><tr><td class="nodeTitle">' + 
	    		nodeLabel + '</td><td class="delIcon">' +
	    		'<img id="delIcon_' + nodeIndex + '" src="js/img/close.gif" /></td></tr></table>';
    },
     
    /**    
     * Respond to the user clicking on the delete icon for node - by removing this node
     *
     * @param evt
     */
    _removeNode: function(evt)
    {
		var delIcon = Event.element(evt);

		// get the node name from the icon ID
		nodeIndex = delIcon.id.substring(delIcon.id.indexOf("_") + 1, delIcon.id.length);		    
    	
    	node = this.tree.getNodeByIndex(nodeIndex);
		var params = {removeItem: node.data.wmcEndpoint};
    	this.tree.removeNode(node)
    	// need to redraw to show this change 
    	this.tree.draw();
    	
    	var updateView = function(xhr) 
		{
			// add listeners again to the delete icons; these are lost when the tree redraws
	    	this.addListeners();
		}
    	
    	new Ajax.Request('removeViewItem', 
			{
				parameters: params,
	    	 	method: "get",
				onSuccess: updateView.bindAsEventListener(this)			
			});
    },
				
	/**
	 * Respond to a tree node being selected
	 * - by highlighting this node and, if the node is
	 * a layer, by adding it to the selected layer div
	 */
    _selectTreeNode: function(node) 
    {
		var i, layer;
		var treeLayer = node.data.layer;
		var leafDiv;
		var node1;

		node1 = this._selectedTreeNode;
		while (node1 != null) 
		{
	    	if (node1.labelElId) 
	    	{
				$(node1.labelElId).className = this._selectedTreeNode.labelStyle;
				node1 = node1.parent;
	    	}
	    	else 
	    	{
				node1 = null;
	    	}
		}

		this._selectedTreeNode = node;
		node1 = this._selectedTreeNode;
		while (node1 != null) 
		{
	    	if (node1.labelElId) 
	    	{
				$(node1.labelElId).className = 'WMSC_selectedField';
				node1 = node1.parent;
	    	}
	    	else 
	    	{
				node1 = null;
	    	}
		}

		// If this node is a leaf, display the different layers available
		// NB, need to treat differently depending on whether we're dealing
		// with a GetCapabilities or a GetWebMapContext call
		if (node.children.length == 0) 
		{
			// check this isn't the 'loading...' leaf; escape if it is
			if (node.label.indexOf("...loading") > -1)
				return;

	    	// add the selected layer to the layers panel
	    	this._updateLeafLayer();
	    	
	    	// set the selected layer
	    	this._selectedLayer = node;
			
			// update the selections control to match the selected layer
			this.coordControl.updateDomainDiv(this._selectedLayer.data.layerData.getDimensions());

			// now refresh the displayed map layers - this is done in the BaseMap.updateVisLayer fn
	    	this.events.triggerEvent('changeWMS');
		}
    },
    
    /**
     * Respond to the user clicking on the delete icon for layer - by removing this layer
     *
     * @param evt
     */
    _removeLayer: function(evt)
    {
		var delIcon = Event.element(evt);

		// get the layer number from the icon ID
		layerIndex = delIcon.id.substring(delIcon.id.indexOf("_") + 1, delIcon.id.length);		    
    	
    	layer = document.getElementById("li_" + layerIndex);

		// hide this layer by changing the style - NB, if the layer is removed, the 
		// associated drag+drop functionality will stop working if the list item is recreated
    	layer.className = "hiddenList";
    	layer.innerHTML = '';
    	
    	// reduce the layer counter
    	this.layerNo--;

	    this._updateLeafLayerMessage();

    	// and reload the maps
    	this.events.triggerEvent('changeWMS');
    },
    
    /**
     * Adjust message displayed in the leaf layer panel according to the current context
     */ 
    _updateLeafLayerMessage: function()
    {
		message = document.getElementById("layerMessage");
		messageText = '';

		if (this.layerNo > 1)
	    {
	    	messageText = 'Adjust display order of layers by dragging and dropping them.  \
	    		NB, layers are overlaid from top to bottom.';
	    }
	    else if (this.layerNo == 0)
	    {
	    	messageText = 'Expand a dataset and select a layer to view';
	    }
	    message.innerHTML = messageText;
    },

    /**
     * Update what layers are displayed in the layer panel and add appropriate event listeners
     * to their associated delete icons
     *
     * @param xhr - XmlHttpRequest object returned by Ajax call
     */
    _updateLeafLayer: function(xhr) 
    {	    
    	var node = this._selectedTreeNode;
	    // check this layer isn't already present and visible
		layers = document.getElementById("layerlist");
		for (var i = 0; i < layerList.childNodes.length; i++)
		{
			child = layerList.childNodes[i];
			if (child.className == "hiddenList")
				continue;
				
			if (child.nodeName == "LI")
			{
				title = child.getAttribute("title");
				if (title == node.data.label)
					return;
			}
		}	    

    	// check what node was selected; if this was a webmapcontext one
    	// load this info, if not, load the capabilities
	    this.layerNo++;
	    if (this.layerNo > this.MAX_LAYER_NO)
	    {
	    	alert('Can only select 10 layers at once; please delete an existing layer and try again.');
	    	this.layerNo--;
	    	return;
	    }
	    
	    this._updateLeafLayerMessage();
				
		// Populate the leafLayer div
		// - check if there are any existing, unused lists first
		layer = this._getFirstHiddenListElement();
		
		listItemNumber = this.layerNo;
		if (layer == null)
		{
		    layer = document.createElement('li');
	    	layer.id = "li_" + this.layerNo;
		}
		else
		{
			// get the listItemNumber - to ensure the delete button matches
			listItemNumber = layer.id.substring(layer.id.indexOf("_") + 1, layer.id.length);
		}
	    layer.className = "list";
	    layer.setAttribute("title", node.data.label);
	    layer.setAttribute("layerName", node.data.layer);
	    layer.setAttribute("wmcURL", node.data.wmcEndpoint);
		layer.innerHTML = 
			'<table><tr><td class="layerTitle">' + node.data.label +
	    	'</td><td class="delIcon"><img id="del_' + listItemNumber + '" src="js/img/close.gif" />' +
	    	'</td></tr></table>';
	    
		layers.appendChild(layer);
	    
	    // Add listener to delete icon to allow layer to be removed
	    deleteIcon = document.getElementById("del_" + listItemNumber);
	    deleteIcon.onclick = this._removeLayer.bindAsEventListener(this);
    },
    
    /**
     * Iterate over the list elements and return the first hidden one - or return null if none found
     */
    _getFirstHiddenListElement: function()
    {
    	for (var i = 1; i <= this.MAX_LAYER_NO; i++)
    	{
    		layer = document.getElementById('li_' + i);
    		if (layer == null)
    			continue;
    		if (layer.className == "hiddenList")
    			return layer;
    	}
    	return null;
    },

    /** 
     * A hook to change the display of Dimension items.
     *   Override this in subclasses to implement 
     */
    getDimensionText: function(dim, value) 
    {
		return value;
    }
}

    