#!/usr/bin/python3

# Written by Michael J. Evans <mjevans1983@gmail.com> on 2016-01-21 --well after-- work

# License choices offered without further conditions: LGPLv3+ or MIT (must reference source, similar to stack overflow sites from 2016 forward)

# Backblaze b2 wants sha1 sums; I want other secure hashes like SHA512 and maybe md5 for older record comparison; created at the same time.

# Python 3.4.2 reports hashlib.algorithms_guaranteed = {'sha224', 'sha384', 'sha1', 'sha512', 'md5', 'sha256'}

CONFIG_FILE = '.pyb2push'

import json
import digestparallel
import os
import sys
import datetime
import base64
import requests


class b2:
    s = None
    buckets = None
    session = None
    # dict: accountId, apiUrl, authorizationToken, downloadUrl

    def __init__(self):
        self.s = requests.Session()
        self.buckets = {}
        self.largeFileChunk = 4 * 1024 * 1024
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as f:
                cfg = json.load(f)
                self.b2id       = cfg['b2id']
                self.b2key      = cfg['b2key']
        elif os.path.exists(os.path.join('~/', CONFIG_FILE)):
            with open(os.path.join('~/', CONFIG_FILE), 'r') as f:
                cfg = json.load(f)
                self.b2id       = cfg['b2id']
                self.b2key      = cfg['b2key']
        else:
            self.b2id = None
            self.b2key = None

    # These staticmethods are promoted to class methods in case derived classes use class state (E.G. a database connection)

    def lookupBucket(self, bucket):
        fname = os.path.join('buckets', '{}.json'.format(bucket))
        if os.path.exists(fname):
            return json.load(open(fname, 'r'))
        return None

    def storeBucket(self, bucket_obj):
        with open(os.path.join('buckets', '{}.json'.format(
                        bucket_obj['bucketName'])), 'w') as f:
            json.dump(bucket_obj, f, indent=0, sort_keys=True)

    def removeBucket(self, bucket_obj):
        try:
            os.unlink(os.path.join('buckets', '{}.json'.format(bucket_obj['bucketName']))
        except (Exception, ) as e:
            pass

    def lookupFile(self, path, attr):
        fname = '{}.json'.format(path)
        if os.path.exists(fname):
            # FIXME: MAYBE: For the default 'on disk' implementation the attributes are presently ignored
            return json.load(open(fname, 'r'))
        return None

    def storeFile(self, path, attr, info):
        info.update(attr)
        with open('{}.json'.format(path),
                    'w') as f:
            json.dump(info, f, indent=0, sort_keys=True)

    def removeFileNameId(self, fileName, fileId):
        try:
            os.unlink('{}.json'.format(fileName))
        except (Exception, ) as e:
            pass

    # an interface for bulk operations in other storage methods
    def storeBuckets(self, buckets):
        for bucket in buckets:
            self.storeBucket(bucket)

    def storeFiles(self, files)
        for path, attr, info in files:
            self.storeFile(path, attr, info)






    # b2_authorize_account
    def authorizeAccount(self, _id = None, _key = None):
        if _id is None: _id = self.b2id
        if _key is None: _key = self.b2key
        auth = requests.auth.HTTPBasicAuth(_id, _key)
        r = self.s.get('https://api.backblaze.com/b2api/v1/b2_authorize_account', verify=True, auth=auth)
        if 200 == r.status_code:
            self.session = json.loads(r.text)
            self.s.headers.update({'Authorization': self.session['authorizationToken']})
        else:
            raise PermissionError("Unable to login to Backblaze B2: Status {}\n{}\n\n".format(r.status_code, r.text))
        return self.session

    # b2_create_bucket [A-Za-z0-9_-]{1,50}  # b2GetOrCreateBucket
    def createBucket(self, bucket):
        _bucket = None
        if bucket in self.buckets:
            return self.buckets[bucket]
        else:
            _bucket = self.lookupBucket(bucket)

        if _bucket is None:
            req = {
                'accountId':  self.session['accountId'],
                'bucketName': bucket,
                'bucketType': 'allPrivate'
                }
            r = self.s.post(self.session['apiUrl'] + '/b2api/v1/b2_create_bucket', verify=True, data = json.dumps(req))
            if 200 == r.status_code:
                _bucket = json.loads(r.text)
            else:
                robj = json.loads(r.text)
                if robj['code'] == 'duplicate_bucket_name':
                    print(  "WARNING: Duplicate bucket creation attempted, is our database complete?\n"
                            "WARNING: Forcing enumeration of buckets.", file=sys.stderr)
                    self.listBuckets()
                    if bucket in self.buckets:
                        return self.buckets[bucket]
                raise RuntimeError("Bucket Create Failure: Status {}\n{}\n\n".format(r.status_code, r.text))

        self.storeBucket(_bucket)
        self.buckets[_bucket['bucketName']] = _bucket
        return _bucket

    # b2_list_buckets # b2GetBuckets
    def listBuckets(self):
        r = self.post(self.session['apiUrl'] + '/b2api/v1/b2_list_buckets', verify=True, data = json.dumps({'accountId': self.session['accountId']}))
        if 200 == r.status_code:
            self.storeBuckets(json.loads(r.text)['buckets'])
        else:
            raise RuntimeError("(get)Bucket List Failure: Status {}\n{}\n\n".format(r.status_code, r.text))

    # If known, delete a bucket locally and remotely, returning the information object on success, returning None on the bucket not being known.
    # b2_delete_bucket # b2DeleteBucketIfKnown
    def deleteBucket(self, bname):
        if bname in self.buckets:
            _bucket = self.buckets[bucket]
        else:
            _bucket = self.lookupBucket(bname)
        if _bucket is None:
            return None

        req = {
            'accountId':  self.session['accountId'],
            'bucketId': _bucket['bucketId']
            }
        r = self.s.post(self.session['apiUrl'] + '/b2api/v1/b2_delete_bucket', verify=True, data = json.dumps(req))
        if 200 == r.status_code:
            self.removeBucket(_bucket)
            if bname in self.buckets:
                del self.buckets[bname]
            return _bucket
        else:
            robj = json.loads(r.text)
            raise RuntimeError("Bucket Delete Failure: Status {}\n{}\n\n".format(r.status_code, r.text))

    # b2_delete_file_version # b2DeleteFileVersion 
    def deleteFileVersion(self, fileName, fileId):
        req = {
            'accountId':  self.session['accountId'],
            'fileName': fileName,
            'fileId': fileId
        }
        r = self.s.post(self.session['apiUrl'] + '/b2api/v1/b2_delete_file_version', verify=True, data = json.dumps(req))
        if 200 == r.status_code:
            ref = json.loads(r.text)
            self.removeFileNameId(ref['fileName'], ref['fileId'])
            return ref
        else:
            robj = json.loads(r.text)
            raise RuntimeError("Bucket Delete Failure: Status {}\n{}\n\n".format(r.status_code, r.text))


    # b2_get_upload_url # b2GetUploadURL
    def getUploadURL(self, bucket):
        if isinstance(bucket, str):
            bucket = self.createBucket(bucket)

        req = { 'bucketId': bucket['bucketId'] }
        r = self.s.post(self.session['apiUrl'] + '/b2api/v1/b2_get_upload_url', verify=True, data = json.dumps(req))
        if 200 == r.status_code:
            return json.loads(r.text)
        else:
            raise RuntimeError("Get Upload URL Failure: Status {}\n{}\n\n".format(r.status_code, r.text))

    # b2_upload_file # b2UploadIfNew
    def uploadFile(self, bucket, path):
        info = digestparallel.digest(path, sha1each = self.largeFileChunk)
        stats = os.stat(path)
        info['size'] = stats.st_size
        info['mtimens'] = stats.st_mtime_ns
        info['ctimens'] = stats.st_ctime_ns

        if stats.st_size > self.largeFileChunk:
            bfile = self.startLargeFile(bucket, path, info)
            # You were here
        else:
            # Use classic single file method
            _file = self.lookupFile(path, info)
            if _file is None:
                bfile = self.getUploadURL(bucket)
                headers = {
                    'Authorization': bfile['authorizationToken'],
                    'X-Bz-File-Name': path, # ??? https://www.backblaze.com/b2/docs/string_encoding.html ??? Python should work by default?
                    'Content-Type': 'b2/x-auto',
                    'Contnet-Length': info['size'],  # 'requests' MIGHT update this... but we already have it and that was /might/
                    'X-Bz-Content-Sha1': info['sha1'],
                    'X-Bz-Info-src_last_modified_millis': int(info['mtimens'] / 1000.0),
                    'X-Bz-Info-md5': info['md5'],
                    'X-Bz-Info-sha256': info['sha256'],
                    'X-Bz-Info-sha512': info['sha512']
                }
                ups = requests.Session()
                ups.headers.update(headers)
                with open(path, 'rb') as f:
                    r = ups.post(bfile['uploadUrl'], data=f, )
                    if 200 == r.status_code:
                        self.storeFile(path, json.loads(r.text), info)
                        info.update(json.loads(r.text))
                        return info
                    else:
                        raise RuntimeError("Upload Failure for {}: Status {}\n{}\n\n".format(path, r.status_code, r.text))

    # b2_start_large_file
    def startLargeFile(self, bucket, path):
        self.uploadFile(bucket, path)

    # b2_start_large_file
    def startLargeFile(self, bucket, path, info):
        if isinstance(bucket, str):
            bucket = self.createBucket(bucket)

        req = { 'bucketId': bucket['bucketId'],
                'fileName': path,
                'Content-Type': 'b2/x-auto',
                'fileInfo': {
                    'src_last_modified_millis': int(info['mtimens'] / 1000.0),
                    'md5': info['md5'],
                    'sha256': info['sha256'],
                    'sha512': info['sha512']
                    }
                }
        r = self.s.post(self.session['apiUrl'] + '/b2api/v1/b2_start_large_file', verify=True, data = json.dumps(req))
        if 200 == r.status_code:
            return json.loads(r.text)
        else:
            raise RuntimeError("Get Upload URL Failure: Status {}\n{}\n\n".format(r.status_code, r.text))


    # b2_get_upload_part_url


    # b2_upload_part


    # b2_cancel_large_file


    # b2_finish_large_file





"""
https://api.backblaze.com/b2api/v1/ with LargeFile (current as of 2016-07)

b2 API wrappers will methods named in camelCase (medial capitals)

*b2_authorize_account
b2_cancel_large_file
*b2_create_bucket
*b2_delete_bucket
*b2_delete_file_version
b2_download_file_by_id
b2_download_file_by_name
b2_finish_large_file
b2_get_file_info
b2_get_upload_part_url
*b2_get_upload_url
b2_hide_file
*b2_list_buckets
b2_list_file_names
b2_list_file_versions
b2_list_parts
b2_list_unfinished_large_files
b2_start_large_file
b2_update_bucket
*b2_upload_file
b2_upload_part

https://www.backblaze.com/b2/docs/b2_list_file_names.html  Cap of 1000 files, and lists per /bucket/

https://www.backblaze.com/b2/docs/large_files.html

Large files must be at least 100MB (100MB+1byte), have a part limit of 5-billion-bytes, and a max size of 10TB (they mean billion bytes).

Parts start at 1 (Q: 0 is the whole file?)

The sha1 checksum of each segment must be specified for that segment, an sha1 of the whole file is optional (recommended).


"""
