#!/usr/bin/env python

"""
   uploadr.py

   Upload images placed within a directory to your Flickr account.

   Requires:
       xmltramp http://www.aaronsw.com/2002/xmltramp/
       flickr account http://flickr.com

   Inspired by:
        http://micampe.it/things/flickruploadr

   Usage:

   The best way to use this is to just fire this up in the background and forget about it.
   If you find you have CPU/Process limits, then setup a cron job.

   %nohup python uploadr.py -d &

   cron entry (runs at the top of every hour )
   0  *  *   *   * /full/path/to/uploadr.py > /dev/null 2>&1

   September 2005
   Cameron Mallory   cmallory/berserk.org

   This code has been updated to use the new Auth API from flickr.

   You may use this code however you see fit in any form whatsoever.


"""

import argparse
import hashlib
import mimetools
import mimetypes
import os
import shelve
import string
import sys
import time
import urllib2
import webbrowser
import xmltramp
import ConfigParser

#
##
##  Items you will want to change
##

#
# Location to scan for new images
#
#IMAGE_DIR = "images/"

#
#
#
UPLOADR_DIR = os.path.dirname(__file__)
#
#   Flickr settings
#
FLICKR = {"title": "",
        "description": "",
        "tags": "auto-upload uploadr",
        "is_public": "0",
        "is_friend": "0",
        "is_family": "0" }
#
#   How often to check for new images to upload (in seconds)
#
SLEEP_TIME = 1 * 60
#
#   Only with --drip-feed option:
#     How often to wait between uploading individual images (in seconds)
#
DRIP_TIME = 1 * 60
#
#   File we keep the history of uploaded images in (for uploading purposes)
#
HISTORY_FILE = os.path.join(UPLOADR_DIR, "uploadr.history")

#
#
#
LOG_FILE = os.path.join(UPLOADR_DIR, "uploaded.log")

##
##  You shouldn't need to modify anything below here
##
config = ConfigParser.RawConfigParser()
config.read('settings.cfg')
FLICKR["api_key"] = config.get('flickr', 'api_key')
FLICKR["secret"] = config.get('flickr', 'secret')

class APIConstants:
    """ APIConstants class
    """

    base = "http://flickr.com/services/"
    rest   = base + "rest/"
    auth   = base + "auth/"
    upload = base + "upload/"

    token = "auth_token"
    secret = "secret"
    key = "api_key"
    sig = "api_sig"
    frob = "frob"
    perms = "perms"
    method = "method"

    def __init__( self ):
       """ Constructor
       """
       pass

api = APIConstants()

class Uploadr:
    """ Uploadr class
    """

    token = None
    IMAGE_DIR = ""
    TOKEN_DIR = os.getcwd()
    perms = ""
    TOKEN_FILE = os.path.join(UPLOADR_DIR, ".flickrToken")
    log = open(LOG_FILE,"ab")

    def __init__( self ):
        """ Constructor
        """
        self.token = self.getCachedToken()
        self.IMAGE_DIR = args.path.rstrip('/')

    def signCall( self, data):
        """
        Signs args via md5 per http://www.flickr.com/services/api/auth.spec.html (Section 8)
        """
        keys = data.keys()
        keys.sort()
        foo = ""
        for a in keys:
            foo += (a + data[a])

        f = FLICKR[ api.secret ] + api.key + FLICKR[ api.key ] + foo
        #f = api.key + FLICKR[ api.key ] + foo
        return hashlib.md5( f ).hexdigest()

    def urlGen( self , base,data, sig ):
        """ urlGen
        """
        foo = base + "?"
        for d in data:
            foo += d + "=" + data[d] + "&"
        return foo + api.key + "=" + FLICKR[ api.key ] + "&" + api.sig + "=" + sig


    def authenticate( self ):
        """ Authenticate user so we can upload images
        """

        print("Getting new token")
        self.getFrob()
        self.getAuthKey()
        self.getToken()
        self.cacheToken()

    def getFrob( self ):
        """
        flickr.auth.getFrob

        Returns a frob to be used during authentication. This method call must be
        signed.

        This method does not require authentication.
        Arguments

        api.key (Required)
        Your API application key. See here for more details.
        """

        d = {
            api.method  : "flickr.auth.getFrob"
            }
        sig = self.signCall( d )
        url = self.urlGen( api.rest, d, sig )
        try:
            response = self.getResponse( url )
            if ( self.isGood( response ) ):
                FLICKR[ api.frob ] = str(response.frob)
            else:
                self.reportError( response )
        except:
            print("Error getting frob:" + str( sys.exc_info() ))

    def getAuthKey( self ):
        """
        Checks to see if the user has authenticated this application
        """
        d =  {
            api.frob : FLICKR[ api.frob ],
            api.perms : "write"
            }
        sig = self.signCall( d )
        url = self.urlGen( api.auth, d, sig )
        ans = ""
        try:
            webbrowser.open( url )
            ans = raw_input("Have you authenticated this application? (Y/N): ")
        except:
            print(str(sys.exc_info()))
        if ( ans.lower() == "n" ):
            print("You need to allow this program to access your Flickr site.")
            print("A web browser should pop open with instructions.")
            print("After you have allowed access restart uploadr.py")
            sys.exit()

    def getToken( self ):
        """
        http://www.flickr.com/services/api/flickr.auth.getToken.html

        flickr.auth.getToken

        Returns the auth token for the given frob, if one has been attached. This method call must be signed.
        Authentication

        This method does not require authentication.
        Arguments

        NTC: We need to store the token in a file so we can get it and then check it insted of
        getting a new on all the time.

        api.key (Required)
           Your API application key. See here for more details.
        frob (Required)
           The frob to check.
        """

        d = {
            api.method : "flickr.auth.getToken",
            api.frob : str(FLICKR[ api.frob ])
        }
        sig = self.signCall( d )
        url = self.urlGen( api.rest, d, sig )
        try:
            res = self.getResponse( url )
            if ( self.isGood( res ) ):
                self.token = str(res.auth.token)
                self.perms = str(res.auth.perms)
                self.cacheToken()
            else :
                self.reportError( res )
        except:
            print(str(sys.exc_info()))

    def getCachedToken( self ):
        """
        Attempts to get the flickr token from disk.
       """
        if ( os.path.exists( self.TOKEN_FILE )):
            return open( self.TOKEN_FILE ).read()
        else :
            return None



    def cacheToken( self ):
        """ cacheToken
        """

        try:
            open( self.TOKEN_FILE , "w").write( str(self.token) )
        except:
            print("Issue writing token to local cache ", str(sys.exc_info()))

    def checkToken( self ):
        """
        flickr.auth.checkToken

        Returns the credentials attached to an authentication token.
        Authentication

        This method does not require authentication.
        Arguments

        api.key (Required)
            Your API application key. See here for more details.
        auth_token (Required)
            The authentication token to check.
        """

        if ( self.token == None ):
            return False
        else :
            d = {
                api.token  :  str(self.token) ,
                api.method :  "flickr.auth.checkToken"
            }
            sig = self.signCall( d )
            url = self.urlGen( api.rest, d, sig )
            try:
                res = self.getResponse( url )
                if ( self.isGood( res ) ):
                    self.token = res.auth.token
                    self.perms = res.auth.perms
                    return True
                else :
                    self.reportError( res )
            except:
                print(str(sys.exc_info()))
            return False

    def createPhotoset(self,photoids):
        """
        flickr.photosets.create

        Create a new photoset for the calling user.Authentication

        Arguments

        api_key (Required)
        Your API application key.

        title (Required)
        A title for the photoset.

        description (Optional)
        A description of the photoset. May contain limited html.

        primary_photo_id (Required)
        The id of the photo to represent this set. The photo must belong to the calling user.This method requires authentication with 'write' permission.
        """ 
        photosetID = ""
        d = {
                    api.method  : "flickr.photosets.create",
                    "title"         :  str(FLICKR["photoset_title"]),
                    "primary_photo_id" : str(photoids[0]),
                    api.token       : str(self.token)
                }
        sig = self.signCall( d )
        #d['title'] = urllib2.quote(str(FLICKR["photoset_title"]).replace(" ","+"),safe="+") # Need to do this, otherwise signature errors occur
        d['title'] = str(FLICKR["photoset_title"]).replace(" ","+") # Need to do this, otherwise signature errors occur
        url = self.urlGen( api.rest, d, sig )
        try:
            res = self.getResponse( url )
            if(self.isGood(res)) :
                photosetID = str(res.photoset('id'))
                if(not args.silent) : print "Created Photoset"+" "+photosetID
                if(args.log) : self.log.write(photosetID+","+str(FLICKR["photoset_title"])+"\n")
            else :
                print "Could not create photoset, "+ str(res.err('msg'))
                self.reportError( res )
        except:
            print("Error creating photoset:" + str( sys.exc_info() ))
        if(photosetID != "" and len(photoids)>1):
            for ids in photoids[1:] :
                d = {
                        api.method  : "flickr.photosets.addPhoto",
                        "photo_id"         : ids,
                        "photoset_id" : photosetID,
                        api.token       : str(self.token)
                    }
                sig = self.signCall( d )
                url = self.urlGen( api.rest, d, sig )
                try:
                    res = self.getResponse( url )
                    if(not self.isGood(res)) :
                        self.reportError( res )
                except:
                    print("Error creating photoset:" + str( sys.exc_info() ))




    def upload( self ):
        """ upload
        """

        newImages = self.grabNewImages()
        if ( not self.checkToken() ):
            self.authenticate()
        self.uploaded = shelve.open( HISTORY_FILE )
        for i, image_directory in enumerate( newImages ):
            photoids=[]
            FLICKR["photoset_title"] = image_directory[0]
            for image,title in image_directory[1]:
                tag=" "+image_directory[0]+" "+title
                success,photoid = self.uploadImageWithMetadata( image,title,tag )
                if(success) :
                    photoids.append(str(photoid))
                if args.drip_feed and success:# and i != len( newImages )-1:
                    if(not args.silent) : print("Waiting " + str(DRIP_TIME) + " seconds before next upload")
                    time.sleep( DRIP_TIME )
            if(len(photoids)>0) : self.createPhotoset(photoids)
        self.uploaded.close()
        self.log.close()

    def grabNewImages( self ):
        """ grabNewImages
        """

        list_of_images=[]
        foo = os.walk( self.IMAGE_DIR )
        for data in foo:
            images = []
            (dirpath, dirnames, filenames) = data
            if(len(filenames)>0):
                for f in filenames :
                    ext = f.lower().split(".")[-1]
                    fname = f.rsplit(".",1)[0]
                    if ( ext == "jpg" or ext == "jpeg" or ext == "gif" or ext == "png" ):
                        images.append( (os.path.normpath( dirpath + "/" + f ),fname) )
                if(len(images)>0):
                    list_of_images.append((dirpath.rsplit('/',2)[-1],images))
                if(args.norecursion):
                    break
        return list_of_images


    def uploadImage( self, image ):
        """ uploadImage
        """

        success = False
        photoid=""
        if ( not self.uploaded.has_key( image ) ):
            if(not args.silent) : print("Uploading " + image + "...")
            try:
                photo = ('photo', image, open(image,'rb').read())
                #if args.title: # Replace
                #    FLICKR["title"] = args.title
                #if args.description: # Replace
                #    FLICKR["description"] = args.description
                #if args.tags: # Append
                #    FLICKR["tags"] += " " + args.tags + " "
                d = {
                    api.token       : str(self.token),
                    api.perms       : str(self.perms),
                    "title"         : str( FLICKR["title"] ),
                    "description"   : str( FLICKR["description"] ),
                    "tags"          : str( FLICKR["tags"] ),
                    "is_public"     : str( FLICKR["is_public"] ),
                    "is_friend"     : str( FLICKR["is_friend"] ),
                    "is_family"     : str( FLICKR["is_family"] )
                }
                sig = self.signCall( d )
                d[ api.sig ] = sig
                d[ api.key ] = FLICKR[ api.key ]
                url = self.build_request(api.upload, d, (photo,))
                xml = urllib2.urlopen( url ).read()
                res = xmltramp.parse(xml)
                if ( self.isGood( res ) ):
                    if(not args.silent) : print("Success.")
                    photoid=res.photoid
                    self.logUpload( res.photoid, image )
                    if(args.log) :
                        self.log.write(str(photoid)+","+str(image)+"\n")
                        self.log.flush()
                    success = True
                else :
                    print("Problem:")
                    self.reportError( res )
                    if(args.log) : 
                        self.log.write("error,"+str(image)+"\n")
                        self.log.flush()
            except:
                print(str(sys.exc_info()))
                if(args.log) : 
                        self.log.write("error,"+str(image)+","+str(sys.exc_info())+"\n")
                        self.log.flush()
        return success,photoid

    def uploadImageWithMetadata(self,image,title,tag):
        """
        Call uploadImage(self,image) and set the title and tag for batch uploads 
        """

        FLICKR["title"] = title
        FLICKR["tags"] = tag
        success,photoid= self.uploadImage(image)
        return success,photoid


    def logUpload( self, photoID, imageName ):
        """ logUpload
        """

        photoID = str( photoID )
        imageName = str( imageName )
        self.uploaded[ imageName ] = photoID
        self.uploaded[ photoID ] = imageName

    def build_request(self, theurl, fields, files, txheaders=None):
        """
        build_request/encode_multipart_formdata code is from www.voidspace.org.uk/atlantibots/pythonutils.html

        Given the fields to set and the files to encode it returns a fully formed urllib2.Request object.
        You can optionally pass in additional headers to encode into the opject. (Content-type and Content-length will be overridden if they are set).
        fields is a sequence of (name, value) elements for regular form fields - or a dictionary.
        files is a sequence of (name, filename, value) elements for data to be uploaded as files.
        """

        content_type, body = self.encode_multipart_formdata(fields, files)
        if not txheaders: txheaders = {}
        txheaders['Content-type'] = content_type
        txheaders['Content-length'] = str(len(body))

        return urllib2.Request(theurl, body, txheaders)

    def encode_multipart_formdata(self,fields, files, BOUNDARY = '-----'+mimetools.choose_boundary()+'-----'):
        """ Encodes fields and files for uploading.
        fields is a sequence of (name, value) elements for regular form fields - or a dictionary.
        files is a sequence of (name, filename, value) elements for data to be uploaded as files.
        Return (content_type, body) ready for urllib2.Request instance
        You can optionally pass in a boundary string to use or we'll let mimetools provide one.
        """

        CRLF = '\r\n'
        L = []
        if isinstance(fields, dict):
            fields = fields.items()
        for (key, value) in fields:
            L.append('--' + BOUNDARY)
            L.append('Content-Disposition: form-data; name="%s"' % key)
            L.append('')
            L.append(value)
        for (key, filename, value) in files:
            filetype = mimetypes.guess_type(filename)[0] or 'application/octet-stream'
            L.append('--' + BOUNDARY)
            L.append('Content-Disposition: form-data; name="%s"; filename="%s"' % (key, filename))
            L.append('Content-Type: %s' % filetype)
            L.append('')
            L.append(value)
        L.append('--' + BOUNDARY + '--')
        L.append('')
        body = CRLF.join(L)
        content_type = 'multipart/form-data; boundary=%s' % BOUNDARY        # XXX what if no files are encoded
        return content_type, body


    def isGood( self, res ):
        """ isGood
        """

        if ( not res == "" and res('stat') == "ok" ):
            return True
        else :
            return False


    def reportError( self, res ):
        """ reportError
        """

        try:
            print("Error: " + str( res.err('code') + " " + res.err('msg') ))
        except:
            print("Error: " + str( res ))

    def getResponse( self, url ):
        """
        Send the url and get a response.  Let errors float up
        """

        xml = urllib2.urlopen( url ).read()
        return xmltramp.parse( xml )


    def run( self ):
        """ run
        """

        while ( True ):
            self.upload()
            print("Last check: " + str( time.asctime(time.localtime())))
            time.sleep( SLEEP_TIME )

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Upload images to Flickr.')
    parser.add_argument('-d', '--daemon', action='store_true',
        help='Run forever as a daemon')
    parser.add_argument('-i', '--title',       action='store',
        help='Title for uploaded images')
    parser.add_argument('-e', '--description', action='store',
        help='Description for uploaded images')
    parser.add_argument('-t', '--tags',        action='store',
        help='Space-separated tags for uploaded images')
    parser.add_argument('-r', '--drip-feed',   action='store_true',
        help='Wait a bit between uploading individual images')
    parser.add_argument('-s', '--silent', action='store_true',
        help='Suppress all output except errors')
    parser.add_argument('-l','--log',action='store_true',
        help='Enable logging to text file')
    parser.add_argument('-1','--norecursion',action='store_true',
        help="Upload only files in current directory, don't go deeper")
    parser.add_argument('--public',action='store_true',
        help="Make this batch of uploads visible to everyone")
    parser.add_argument('--friend',action='store_true',
        help="Make this batch of uploads visible to friends")
    parser.add_argument('--family',action='store_true',
        help="Make this batch of uploads visible to family")
    parser.add_argument('path',help="Path to the file")
    args = parser.parse_args()

    if args.public:
        FLICKR["is_public"] = "1"
        FLICKR["is_family"] = "1"
        FLICKR["is_friend"] = "1"
    if args.friend:
        FLICKR["is_friend"] = "1"
    if args.family:
        FLICKR["is_family"] = "1"


    flick = Uploadr()

    if args.daemon:
        flick.run()
    else:
        flick.upload()
