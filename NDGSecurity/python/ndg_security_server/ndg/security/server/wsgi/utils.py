"""NDG Security WSGI utilities

MashMyData Project
"""
__author__ = "P J Kershaw"
__date__ = "21/08/11"
__copyright__ = "(C) 2011 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"
import logging
log = logging.getLogger(__name__)


class FileObjResponseIterator(object):
    """Helper class creates iterable WSGI response based on a given block size
    """
    DEFAULT_BLK_SIZE = 1024
    BYTE_RANGE_PREFIX = 'bytes='
    BYTE_RANGE_SEP = '-'
    CONTENT_RANGE_FIELDNAME = 'Content-range'
    CONTENT_RANGE_FORMAT_STR = "bytes %d-%d/%d"
    INVALID_CONTENT_RANGE_FORMAT_STR = "bytes */%d"
    
    __slots__ = (
        'file_obj',
        'file_size',
        '__block_size',
        'read_lengths',
        'content_length',
        'content_range',
        'content_range_hdr',
        'closed_method'
    )
    
    
    class IteratorError(Exception):
        """Base exception type for exceptions raised from 
        FileObjResponseIterator class instances"""
    
    
    class InvalidRangeRequest(IteratorError):
        """Raise for an invalid byte range requested"""
        def __init__(self, *arg, **kw):
            FileObjResponseIterator.IteratorError.__init__(self, *arg, **kw)
            if len(arg) > 1:
                self.content_range_hdr = arg[1]
            else:
                self.content_range_hdr = None
                
        
    class InvalidRangeRequestSyntax(IteratorError):
        """Raise for invalid range request syntax"""
    
       
    def __init__(self, file_obj, file_size=-1, request_range=None, 
                 block_size=DEFAULT_BLK_SIZE):
        '''Open a file and set the blocks for reading, any input range set and
        the response size
        '''
        self.file_obj = file_obj
        self.file_size = file_size

        # Find method of determining whether the file object is closed.
        if hasattr(file_obj, 'closed'):
            # Standard file interface has optional 'closed' attribute.
            self.closed_method = lambda : self.file_obj.closed
        elif hasattr(file_obj, 'isclosed'):
            # httplib.HTTPResponse has a non-standard 'isclosed' method.
            self.closed_method = self.file_obj.isclosed
        elif hasattr(file_obj, 'fp'):
            # urllib.addbase and derived classes returned by urllib and urllib2:
            self.closed_method = lambda : self.fp is None
        else:
            self.closed_method = None

        # the length of the content to return - this will be different to the
        # file size if the client a byte range header field setting
        self.content_length = 0
        
        # None unless a valid input range was given
        self.content_range = None
        
        # Formatted for HTTP content range header field
        self.content_range_hdr = None

        # This will call the relevant set property method
        self.block_size = block_size
        
        # Array of blocks lengths for iterator to use to read the file
        self.read_lengths = []
        
        if request_range is not None:
            
            # Prepare a content range header in case the range specified is
            # invalid
            content_range_hdr = (self.__class__.CONTENT_RANGE_FIELDNAME,
                               self.__class__.INVALID_CONTENT_RANGE_FORMAT_STR %
                               self.file_size)
                                
            try:
                # Remove 'bytes=' prefix
                rangeVals = request_range.split(
                                        self.__class__.BYTE_RANGE_PREFIX)[-1]
                                        
                # Convert into integers taking into account that a value may be
                # absent
                startStr, endStr = rangeVals.split(
                                                self.__class__.BYTE_RANGE_SEP)
                start = int(startStr or 0)
                end = int(endStr or self.file_size - 1)
            except ValueError:
                raise self.__class__.InvalidRangeRequestSyntax('Invalid format '
                    'for request range %r' % request_range)
            
            # Verify range bounds
            if start > end:
                raise self.__class__.InvalidRangeRequest('Range start index %r '
                    'is greater than the end index %r' % 
                    (start, end), content_range_hdr)
            elif start < 0:
                raise self.__class__.InvalidRangeRequest('Range start index %r '
                                                         'is less than zero' % 
                                                         start,
                                                         content_range_hdr) 
            elif end >= self.file_size:
                # This is not an error - 
                # http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.35.1
                log.warning('Range end index %r is greater than the length %r '
                            'of the requested resource - reseting to %r',
                            end, self.file_size, self.file_size - 1)
                end = self.file_size - 1
                
            # Set the total content length to return
            self.content_length = end + 1 - start 
            self.content_range = (start, end)
            self.content_range_hdr = (
                self.__class__.CONTENT_RANGE_FIELDNAME, 
                self.__class__.CONTENT_RANGE_FORMAT_STR % 
                                        (self.content_range + (self.file_size,))
            )
            try:
                self.file_obj.seek(start)
            except AttributeError:
                # File seek method is optional.
                pass
        else:            
            # Set the total content length to return
            self.content_length = self.file_size
                  
        nReads = self.content_length / self.block_size
        lastReadLen = self.content_length % self.block_size
        self.read_lengths = [self.block_size] * nReads
        if lastReadLen > 0:
            nReads += 1
            self.read_lengths.append(lastReadLen)
        
    def __iter__(self):
        '''Read the file object a block at a time'''
        
        # Leave read_lengths attribute intact
        read_lengths = self.read_lengths[:]
        while (self.content_length < 0) or (len(read_lengths) > 0):
            if self.content_length < 0:
                if self.closed_method():
                    return
                amt = self.block_size
            else:
                amt = read_lengths.pop()
            output = self.file_obj.read(amt)
            if not output:
                self.close()
            yield output

    def close(self):
        """Closes the file object.
        """
        self.file_obj.close()

    @property
    def block_size(self):
        """block size for reading the file in the iterator and returning a 
        response
        """
        return self.__block_size
    
    @block_size.setter
    def block_size(self, value):
        """block size for reading the file in the iterator and returning a 
        response
        """
        self.__block_size = int(value)
        if self.__block_size < 0:
            raise ValueError('Expecting positive integer value for block size '
                             'attribute')
