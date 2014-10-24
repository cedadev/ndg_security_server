/**
 * Various objects for wrappering capabilities and web map context documents
 * - borrowed from the DCIP code to use in the view functionality for WMC and granules data
 * C Byrom
 */

// For resolving XML Namespaces in XPath expressions
WMSC.nsMap = {
    wms: 'http://www.opengis.net/wms',
    xlink: 'http://www.w3.org/1999/xlink'
};

/* A poor man's XPath */
WMSC._searchElement = function(node, element) 
{
    var i, node2, children;

    children = node.childNodes;
    for (i=0; i<children.length; i++) 
    {
		node2 = children[i];
		if (node2.nodeName == element) 
			return node2;
    }
    return null;
};
WMSC.traverseWMSDom = function(node, elements) {
    var i;

    for (i=0; i<elements.length; i++) {
	node = WMSC._searchElement(node, elements[i]);
	if (node == null) return null;
    }
    return node;
};


/**
 * Class to wrapper a GetCapabilities document and expose
 * useful properties easily
 */
WMSC.Capabilities = function(domElement) {
    this.dom = domElement;
};
WMSC.Capabilities.prototype = {
    evaluate: function(expr, node) {

	if (node == null) {
	    node = this.dom;
	}
	return WMSC.evalXPath(expr, node);
    },

    getTitle: function() {
	var el = WMSC.traverseWMSDom(this.dom, ['Service', 'Title']);
	if (el.textContent) {
	    return el.textContent;
	}
	else {
	    return el.text;
	}
    },
    getAbstract: function() {
	var el = WMSC.traverseWMSDom(this.dom, ['Service', 'Abstract']);
	if (el.textContent) {
	    return el.textContent;
	}
	else {
	    return el.text;
	}
    },
    getRootLayer: function() {
	var rootLayer = WMSC.traverseWMSDom(this.dom, ['Capability', 'Layer']);
	if (rootLayer == null) return null;
	return new WMSC.Layer(rootLayer);
    },
    getEndpoint: function() {
	var or = WMSC.traverseWMSDom(this.dom, ['Service', 'OnlineResource']);
	if (or == null) return null;
	var attr = or.getAttribute('href');
	if (!attr) {
	    attr = or.getAttribute('xlink:href');
	}
	return attr;
    }
};

/**
 * Class to wrapper a WMC Layer document and expose
 * useful properties easily
 */
WMSC.Layer = function(node) {
    this.node = node;
};
WMSC.Layer.prototype = {
    getName: function() {
	var node = WMSC.traverseWMSDom(this.node, ['Name']);
	if (node == null) return null;
	if (node.textContent) {
	    return node.textContent;
	}
	else {
	    return node.text;
	}
    },
    getTitle: function() {
	var el = WMSC.traverseWMSDom(this.node, ['Title']);
	if (el.textContent) {
	    return el.textContent;
	}
	else {
	    return el.text;
	}
    },
    getAbstract: function() {
	var el = WMSC.traverseWMSDom(this.node, ['Abstract']);
	// NB, WMC layers may not have abstracts
	if (!el)
		return "";
		
	if (el.textContent) {
	    return el.textContent;
	}
	else {
	    return el.text;
	}
    },
    getDimensions: function() 
    {
		var i;
		var dimObj;
		var dims = {};
		var dimEls = this.node.getElementsByTagName('Dimension');
		for (i=0; i<dimEls.length; i++) 
		{
	    	dimObj = new WMSC.Dimension(dimEls[i]);
		    dims[dimObj.getName()] = dimObj;
		}

		return dims;
    },

    getSubLayers: function() {
	var i, children, n;
	var layers = [];

	children = this.node.childNodes;
	for (i=0; i<children.length; i++) {
	    n = children[i];
	    if (n.nodeName == 'Layer') {
		layers[layers.length] = new WMSC.Layer(n);
	    }
	}
	return layers;
    },
    
    // if layer is part of a web map context, it should have
    // an endpoint defined
    getEndpoint: function() 
    {
		var or = WMSC.traverseWMSDom(this.node, 
			['Server', 'OnlineResource']);
		if (or == null) 
			return null;
	
		var attr = or.getAttribute('href');
		if (!attr)
		    attr = or.getAttribute('xlink:href');
		return attr;
    }
};


/**
 * Class to wrapper a WMC Layers dimension document and expose
 * useful properties easily
 */
WMSC.Dimension = function(node) {
    this.node = node;
};
WMSC.Dimension.prototype = {
    getName: function() {
	var attr = this.node.attributes.getNamedItem('name');
	return attr.value;
    },
    getUnits: function() {
	var attr = this.node.attributes.getNamedItem('units');
	return attr.value;
    },
    getExtent: function() {
	if (this.node.textContent) {
	    return this.node.textContent.split(',');
	}
	else {
	    return this.node.text.split(',');
	}
    }
};


/**
 * Class to wrapper a WebMapContext document and expose
 * useful properties easily
 * @author C Byrom
 */
WMSC.WebMapContext = function(domElement) 
{
    this.dom = domElement;
};
WMSC.WebMapContext.prototype = 
{
	/**
	 * Evaluate an XPATH expression on a specified dom node
	 * @param expr: XPATH expression to use
	 * @param node: node to evaluate expr on
	 */
    evaluate: function(expr, node) 
    {
		if (node == null) 
	    	node = this.dom;

		return WMSC.evalXPath(expr, node);
    },

	/**
	 * Retrieve the general title of the WMC doc
	 * @return WMC Title string
	 */
    getTitle: function() 
    {
		var el = WMSC.traverseWMSDom(this.dom, ['General', 'Title']);
		if (el.textContent) 
	    	return el.textContent;
		else
		    return el.text;
    },
    
	/**
	 * Retrieve the sublayers of the WMC doc
	 * @return array of WMCS.Layer objects
	 */
    getSubLayers: function()
    {
        var layerList = WMSC._searchElement(this.dom, 'LayerList');
         
		var children = layerList.childNodes;
		var layers = [];
		for (var i=0; i<children.length; i++) 
		{
			if (children[i].nodeName == 'Layer')
				layers[layers.length] = new WMSC.Layer(children[i]);
	    }
		return layers;
    } 
};
