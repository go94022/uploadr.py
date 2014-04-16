Uploadr.py
==========

Uploadr.py is a simple Python script for uploading your photos to Flickr. Unlike
many GUI applications out there, it lends itself to automation; and because it's
free and open source, you can just change it if you don't like it.

Modified 4/2013 to make Win32 only (watch for filesystem changes in target folder)! 
Now support local file deletion on successful upload, logging by file hash, some 
other minor changes.


Authentication
--------------

To use this application, you need to obtain your own Flickr API key and secret
key. You can apply for keys `on the Flickr website
<http://www.flickr.com/services/api/keys/apply/>`_.

Keys and other settings go in a settings.yml file--rename settings.yml.default
and modify as needed.


License
-------

Uploadr.py consists of code by Cameron Mallory, Martin Kleppmann, Aaron Swartz, 
Andy Hebrank and others. See ``COPYRIGHT`` for details.
