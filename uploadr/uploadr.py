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

   *** August 2013, by alisanta
    took code from Barry Dobyns (https://github.com/bdobyns/uploadr.py) to make more arguments available in command line
    add argument to allow upload of resized images 

    include a repo from Ben Leslei (https://github.com/bennoleslie/pexif) to copy EXIF information to resized image
   *** 
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
from optparse import OptionParser
import Image
import tempfile
from pexif import pexif


#
##
##  Items you will want to change
##

#
# Location to scan for new images, this can be override from parameter
#
IMAGE_DIR = "/Users/alist/Pictures/flickr"
#
#   Flickr settings
#
FLICKR = {"title": "",
        "description": "",
        "tags": "auto-upload",
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
#   File we keep the history of uploaded images in.
#
#HISTORY_FILE = os.path.join(IMAGE_DIR, "uploadr.history")
HISTORY_FILE = os.path.join(os.path.expanduser("~"), ".uploadr.history")

##
##  You shouldn't need to modify anything below here
##
FLICKR["api_key"] = os.environ['FLICKR_UPLOADR_PY_API_KEY']
FLICKR["secret"] = os.environ['FLICKR_UPLOADR_PY_SECRET']

class APIConstants:
    """ APIConstants class
    """

    base = "http://api.flickr.com/services/" #"http://flickr.com/services/"
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
    perms = ""
    #TOKEN_FILE = os.path.join(IMAGE_DIR, ".flickrToken")
    TOKEN_FILE = os.path.join(os.path.expanduser("~"), ".flickrToken")

    def __init__( self ):
        """ Constructor
        """
        self.token = self.getCachedToken()



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


    def upload( self ):
        """ upload
        """

        newImages = self.grabNewImages()
        if ( not self.checkToken() ):
            self.authenticate()
        self.uploaded = shelve.open( HISTORY_FILE )
        setId=""
        for i, image in enumerate( newImages ):
            id = self.uploadImage( image )

            # add photo to set
            
            if (options.sets!=""):
                if setId=="": 
                    setId = options.sets
                if not(self.addPhotoToSet( setId, id )):
                    setId = self.createSet( id )
                    self.addPhotoToSet( setId, id )

            if options.drip_feed and success and i != len( newImages )-1:
                print("Waiting " + str(DRIP_TIME) + " seconds before next upload")
                time.sleep( DRIP_TIME )
        self.uploaded.close()

    def grabNewImages( self ):
        """ grabNewImages
        """

        images = []
        foo = os.walk( IMAGE_DIR )
        for data in foo:
            (dirpath, dirnames, filenames) = data
            for f in filenames :
                ext = f.lower().split(".")[-1]
                if ( ext == "jpg" or ext == "gif" or ext == "png" ):
                    images.append( os.path.normpath( dirpath + "/" + f ) )
        images.sort()
        return images


    def uploadImage( self, image ):
        """ uploadImage
        """

        success = False
        if ( not self.uploaded.has_key( image ) ):
            print("Uploading " + image + "...")
            try:
                if hasattr(options, 'image_pixel_size'):
                    resized_image = self.resize_image(image)

                if resized_image=="":
                    photo = ('photo', image, open(image,'rb').read())
                else:
                    photo = ('photo', image, open(resized_image,'rb').read())
                    
                
                
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
                    print("Success.")
                    self.logUpload( res.photoid, image )
                    success = res.photoid
                    if len(FLICKR["lat"]) and len(FLICKR["lon"]):
                        d = { 
                            api.token : str(self.token),
                            "method" : str("flickr.photos.geo.setLocation"),
                            "photo_id" : str(res.photoid),
                            'lat': str(FLICKR['lat']),
                            'lon': str(FLICKR['lon'])
                            }
                        sig = self.signCall( d )
                        d[ api.sig ] = sig
                        d[ api.key ] = FLICKR[ api.key ]         
                        url = self.build_request(api.rest, d, () )
                        xml = urllib2.urlopen( url ).read()
                        res = xmltramp.parse(xml)
                        if ( self.isGood( res ) ):
                            print "Patched Location", d['lat'], d['lon']
                        else:
                            print "FAILED Location", d['lat'], d['lon']
                            self.reportError( res )


                else :
                    print("Problem:")
                    self.reportError( res )

                # remove temp resized image
                if resized_image!="":
                    self.kill_resize_image(resized_image)

            except:
                print(str(sys.exc_info()))
        return success #photoid if successful

    def createSet( self, photoid ):
            print "Creating set ", SET_TITLE , "...",
            d = { 
                api.method : "flickr.photosets.create",
                api.token   : str(self.token),
                "title"      : str( SET_TITLE ),
                "primary_photo_id" : str(photoid)
            }
            sig = self.signCall( d )
            d[ api.sig ] = sig
            d[ api.key ] = FLICKR[ api.key ]        
            url = self.urlGen( api.rest, d, sig )
            try:
                res = self.getResponse( url )
                if ( self.isGood( res ) ):
                    print "successful."
                    return res.photoset("id")
                else :
                    self.reportError( res )
            except:
                print str( sys.exc_info() )

    def addPhotoToSet( self, setid, photoid ):
        # from https://github.com/stinju/uploadr.py/
        
        d = { 
            api.method : "flickr.photosets.addPhoto",
            api.token   : str(self.token),
            "photoset_id"      : str(setid),
            "photo_id" : str(photoid)
        }
        sig = self.signCall( d )
        d[ api.sig ] = sig
        d[ api.key ] = FLICKR[ api.key ]        
        url = self.urlGen( api.rest, d, sig )
        try:
            res = self.getResponse( url )

            
            if ( self.isGood( res ) ):
                print "successful add to set."
            elif str(res.err('code'))=="1":
                return False # error 1: Photoset not found
            else :
                self.reportError( res )
        except:
            print str( sys.exc_info() )
        return True

    def resize_image ( self, image):
        """ resizeimage accoding to specified size in arguments
            return empty if resize is cancelled
        """
        img = Image.open(image)
        cancel=0
        if img.size[0]>img.size[1]:
            if float(img.size[0])<=float(options.image_pixel_size):
                cancel=1
            else:
                ratio=float(img.size[0])/float(img.size[1])
                vsize=int(float(options.image_pixel_size))
                hsize=int(float(options.image_pixel_size)/float(ratio))
        else:
            if float(img.size[1])<=float(options.image_pixel_size):
                cancel=1
            else:
                ratio=float(img.size[1])/float(img.size[0])
                hsize=int(float(options.image_pixel_size))
                vsize=int(float(options.image_pixel_size)/float(ratio))
        
        if cancel==0:
            img2 = img.resize((vsize,hsize), Image.ANTIALIAS)
            resized = os.path.normpath(  tempfile.gettempdir() +"/tmpres"+(os.path.split(image))[1] ) 
            img2.save(resized, quality=95)
            
            # now copy EXIF information
            self.copy_exif(image, resized)

        else:
            resized=""
        return resized

    def copy_exif (self, sourcefile, targetfile):
        """ copy important EXIF to resized file. 
            Refer to pexif code for acceptable tags.
            For my own purpose, I just need some tags copied: Camera, Model, Original Date, and GPS if available
        """
        a=["Make", "Model", "Software","DateTime", "FileModifyDate", "Orientation"]
        b=["DateTimeOriginal"]
        img = pexif.JpegFile.fromFile(sourcefile)
        p=img.exif.primary
        q=p.ExtendedEXIF
        img_dst = pexif.JpegFile.fromFile(targetfile)
        primary_dst = img_dst.exif.primary

        # copy primary tags
        for x in a:
            if hasattr(p, x):
                primary_dst[x]=p[x]
        
        # extended EXIF tags
        for x in b:
            if hasattr(q, x):
                primary_dst.ExtendedEXIF[x] = q[x]
        
        # GPS Info
        try:
            gps_loc = img.get_geo()
            img_dst.set_geo(gps_loc[0], gps_loc[1])
        except img.NoSection:
            pass
        try:
            img_dst.writeFile(targetfile)
        except:
            print ("Unable to write file "+targetfile)
        

    def kill_resize_image(self, resized_image):
        """ remove temporary resized image after upload
        """
        if (os.path.exists(resized_image)):
            try:
                os.remove(resized_image)
            except:
                print("Error removing temp "+resized_image)



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
    #parser = argparse.ArgumentParser(description='Upload images to Flickr.')
    #parser.add_argument('-d', '--daemon', action='store_true',
    #    help='Run forever as a daemon')
    #parser.add_argument('-i', '--title',       action='store',
    #    help='Title for uploaded images')
    #parser.add_argument('-e', '--description', action='store',
    #    help='Description for uploaded images')
    #parser.add_argument('-t', '--tags',        action='store',
    #    help='Space-separated tags for uploaded images')
    #parser.add_argument('-r', '--drip-feed',   action='store_true',
    #    help='Wait a bit between uploading individual images')
    #args = parser.parse_args()
    usage= "usage: %prog [options] dir_to_upload"
    version="%prog 0.2"
    parser = OptionParser(usage=usage, version=version)
    parser.add_option("-d", "--daemon", action="store_true",  dest="daemon", default=False, help="Run forever as a daemon")
    parser.add_option("-e", "--desc",   action="store", dest="desc",   default="", help="Description of files to upload")
    parser.add_option("-t", "--tags",   action="store", dest="tags",   default="", help="Tags to flag uploaded photos with")
    parser.add_option("-i", "--title",  action="store", dest="title",   default="",    help="Title to give uploaded photos")
    parser.add_option("-u", "--public", action="store_const", const=1, dest="public", default=1,     help="Mark the upload public")
    parser.add_option("-n", "--notpublic", action="store_const", const=0, dest="public", default=0,               help="Mark the upload hidden (not public)")
    parser.add_option("-f", "--friend", action="store_const", const=1, dest="friends", default=0,    help="Mark the upload for friends only")
    parser.add_option("-a", "--family", action="store_const", const=1, dest="family", default=0,     help="Mark the upload for Family only")
    parser.add_option("-x", "--lon", action="store", dest="lat", default="", help="latitude geo-location")
    parser.add_option("-y", "--lat", action="store", dest="lon", default="", help="longitude geo-location")
    parser.add_option("-r", "--drip-feed", action='store_true', default="", help='Wait a bit between uploading individual images')
    parser.add_option("-p", "--pixel", action="store", type="string", dest="image_pixel_size", help="Uploaded image pixel size (800,1280,1600,2048)")
    parser.add_option("-s", "--sets", action="store", type="string", dest="sets", default="", help="Add photo to specified set title")
    parser.add_option("-o", "--setdirname", action='store_true', default="", help='Use directory name as Set name')

    (options,args) = parser.parse_args()

    if hasattr(options, 'title'):
        FLICKR["title"] = options.title
    if hasattr(options, "desc"):
        FLICKR["desc"] = options.desc
    if hasattr(options, 'tags'):
        FLICKR["tags"] = options.tags
    if hasattr(options, 'lat'):
        FLICKR["lat"] = options.lat
    if hasattr(options, 'lon'):
        FLICKR["lon"] = options.lon
    if hasattr(options, 'notpublic'):
        FLICKR["is_public"] = options.public
    if hasattr(options, 'friend'):
        FLICKR["is_friend"] = options.friends    
    if hasattr(options, 'family'):
        print (options.family)
        FLICKR["is_family"] = options.family
    if hasattr(options, 'sets'):
        if options.sets!="":
            SET_TITLE = options.sets
       


    flick = Uploadr()

    if len(args):
        IMAGE_DIR = args[0];



    print "Reading images from "+IMAGE_DIR   
    if ( options.daemon == True ) :
        flick.run()
    else:
        flick.upload()
    
