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
import urllib
import webbrowser
import xmltramp
import ConfigParser
from optparse import OptionParser
import Image
import tempfile
from pexif import pexif
import timeit  # want to calculate resize processing time



import win32ui
import win32con
import win32file
import win32event

# location of script
SCRIPT_DIR = os.path.dirname(os.path.realpath(sys.argv[0]))

# read settings yaml
import yaml
with open(os.path.join(SCRIPT_DIR, "settings.yml")) as f:
    settings = yaml.safe_load(f)
IMAGE_DIR = settings["image_dir"]
FLICKR = settings["flickr"]
DRIP_TIME = settings["drip_time"]

#
# Location to scan for new images, this can be override from parameter
#
IMAGE_DIR = "images/"
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
HISTORY_FILE = os.path.join(IMAGE_DIR, "uploadr.history")

LOG_FILE = os.path.join(IMAGE_DIR, "uploaded.log")

##
##  You shouldn't need to modify anything below here
##
config = ConfigParser.RawConfigParser()
config.read('settings.cfg')
FLICKR["api_key"] = config.get('flickr', 'api_key')
FLICKR["secret"] = config.get('flickr', 'secret')
FLICKR["api_key"] = os.environ['FLICKR_UPLOADR_PY_API_KEY']
FLICKR["secret"] = os.environ['FLICKR_UPLOADR_PY_SECRET']

class APIConstants:
    """ APIConstants class
    """

    base = "https://api.flickr.com/services/"
    base_upload = "https://up.flickr.com/services/"  # refer to https://code.flickr.net/2014/04/30/flickr-api-going-ssl-only-on-june-27th-2014/
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
    TOKEN_FILE = os.path.join(SCRIPT_DIR, ".flickrToken")
    log = open(LOG_FILE,"ab")

    def __init__( self ):
        """ Constructor
        """
        self.token = self.getCachedToken()
        self.IMAGE_DIR = args.path.rstrip('/')
        if args.search_dups:
            self.isDuplicate = self.isFlickrDuplicate
        else:
            self.isDuplicate = lambda image: self.uploaded.has_key(image)


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
            foo += d + "=" + urllib.quote_plus( data[d] ) + "&"
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

        if options.listset:
            self.listPhotoset()
            return

        
        newImages = self.grabNewImages()
        if ( not self.checkToken() ):
            self.authenticate()
        self.uploaded = shelve.open( HISTORY_FILE )

        if (options.sets!=""):
            setId = self.findPhotoset(options.sets)

        for i, image in enumerate( newImages ):
            picid = self.uploadImage( image )

            # add photo to set
            
            if (options.sets!=""):
                if setId=="": 
                    setId = self.createSet( picid )
                else:
                    self.addPhotoToSet( setId, picid )
            #
            #if (options.sets!=""):
            #    if (setId==""):
            #        # set not found, create new set
            #        self.addPhotoToSet( setId, picid )
            #    self.addPhotoToSet( setId, picid )    
            #"""

            if options.drip_feed and success and i != len( newImages )-1:
                print("Waiting " + str(DRIP_TIME) + " seconds before next upload")
                time.sleep( DRIP_TIME )
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
        if not self.isDuplicate(image):
        if ( not self.uploaded.has_key( image ) ):
            if(not args.silent) : print("Uploading " + image + "...")
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
                    if(not args.silent) : print("Success.")
                    photoid=res.photoid
                    self.logUpload( res.photoid, image )
                    if(args.log) :
                        self.log.write(str(photoid)+","+str(image)+"\n")
                        self.log.flush()
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
                    if(args.log) : 
                        self.log.write("error,"+str(image)+"\n")
                        self.log.flush()
                # remove temp resized image
                if resized_image!="":
                    self.kill_resize_image(resized_image)

            except KeyboardInterrupt:
                sys.exit(1)
            except urllib2.HTTPError as e:
                print e.code
                print e.read()
            except:
                print(str(sys.exc_info()))
                if(args.log) : 
                        self.log.write("error,"+str(image)+","+str(sys.exc_info())+"\n")
                        self.log.flush()
        else:
            print("Duplicate, skip upload " + image )
        return success #photoid if successful

    def uploadImageWithMetadata(self,image,title,tag):
        """
        Call uploadImage(self,image) and set the title and tag for batch uploads 
        """

        FLICKR["title"] = title
        FLICKR["tags"] = tag
        success,photoid= self.uploadImage(image)
        return success,photoid

    def createSet( self, photoid ):
            sys.stdout.write( "Creating set "+ SET_TITLE + "... using photoid "+ str(photoid))
            d = { 
                api.method : "flickr.photosets.create",
                api.token   : str(self.token),
                api.perms : "write",
                "title"      : SET_TITLE,
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

    def findPhotoset ( self, setname):
        """ retrieve all photosets from flickr, and find setID 
        """
        d = { 
            api.method : "flickr.photosets.getList",
            api.token   : str(self.token)
        }
        sig = self.signCall( d )
        d[ api.sig ] = sig
        d[ api.key ] = FLICKR[ api.key ]        
        url = self.urlGen( api.rest, d, sig )
        result = ""
        try:
            res = self.getResponse( url )
            allsets=[]
            for the_set in res[0]:
                dic=(str(the_set('id')), str(the_set.title), str(the_set('date_create')))
                allsets.append(dic)

            for x in allsets:
                if (x[1]==setname):
                    result = x[0]

        except:
            print str( sys.exc_info() )

        return result

    def listPhotoset ( self):
        """ retrieve all photosets from flickr, print as output
        """
        d = { 
            api.method : "flickr.photosets.getList",
            api.token   : str(self.token)
        }
        sig = self.signCall( d )
        d[ api.sig ] = sig
        d[ api.key ] = FLICKR[ api.key ]        
        url = self.urlGen( api.rest, d, sig )
        
        try:
            res = self.getResponse( url )
            allsets=[]
            for the_set in res[0]:
                dic=( str(the_set.title),str(the_set('id')), str(the_set('date_create')))
                allsets.append(dic)
                
            a = sorted(allsets, key=lambda a_entry: a_entry[0]) 
            for x in a:
                print (x[0] +" - "+ x[1])

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
                #print "successful add to set."
                pass
            elif str(res.err('code'))=="1":
                return False # error 1: Photoset not found
            else :
                self.reportError( res )
                return False
        except:
            print str( sys.exc_info() )
            return False
        return True

    def resize_image ( self, image):
        """ resizeimage accoding to specified size in arguments
            return empty if resize is cancelled
        """
        tic = timeit.default_timer()
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
        toc = timeit.default_timer()
        # print ("resize time %s " % (toc-tic))
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
        except:
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



    def removeImage( self, image ):
        """ delete a local image (presumably on successful upload)
        """
        if os.path.isfile(image):
            self.logger.info("Deleting local copy of " + image)
            return os.remove(image)
        return False

    def hashImage ( self, image ):
        """ given a filename, hash the file contents
        """
        # from http://www.pythoncentral.io/hashing-files-with-python/
        BLOCKSIZE = 65536
        hasher = hashlib.md5()
        with open( image, 'rb' ) as fin:
            buf = fin.read(BLOCKSIZE)
            while len(buf) > 0:
                hasher.update(buf)
                buf = fin.read(BLOCKSIZE)
        return(hasher.hexdigest())


    def logUpload( self, photoID, fileHash ):
        """ log the upload
    def logUpload( self, photoID, imageName ):
        """ logUpload
        """

        photoID = str( photoID )
        fileHash = str( fileHash )

        self.uploaded[ fileHash ] = photoID
        imageName = str( imageName )
        self.uploaded[ imageName ] = photoID
        self.uploaded[ photoID ] = imageName
        self.uploaded.sync()
        self.uploaded[ photoID ] =  fileHash

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

    def isFlickrDuplicate(self, image):
        """
        flickr.photos.search

        Searches the flickr service for an existing title.
        """
        if ( self.token == None ):
            return False
        else :
            d = {
                api.token  :  str(self.token) ,
                api.method :  "flickr.photos.search",
            }
            search = os.path.basename(image).split('.')[0]
            # Define search text
            d['text'] = urllib.quote_plus(search)
            # Only search user's own photos
            d['user_id'] = 'me'

            sig = self.signCall( d )
            url = self.urlGen( api.rest, d, sig )
            try:
                xml = urllib2.urlopen( url ).read()
                print xml
                # The returned XML contains the original name if found
                if xml.find(search) == -1:
                    return False
                else:
                    print "Duplicate: ", search
                    return True
            except:
                print(str(sys.exc_info()))
            return False

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
    #args = parser.parse_args()
    usage= "usage: %prog [options] dir_to_upload"
    parser.add_argument('-x', '--delete', action='store_true',
        help='Delete local images after uploading')
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
    parser.add_option("-s", "--sets", action="store", type="string", dest="sets", default="", help="Create set and ddd photo to specified set title")
    parser.add_option("-l", "--listset", action="store_true", default="", help="Print List of Photoset, ** No Upload process **")
    
    #parser.add_option("-o", "--setdirname", action='store_true', default="", help='Use directory name as Set name')

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
    print "Image folder set to "+IMAGE_DIR   

    if args.daemon:
        flick.run()
    else:
        flick.upload()
