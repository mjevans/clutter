#!/usr/bin/python3

# Written by Michael J. Evans <mjevans1983@gmail.com> on 2016-01-21 --well after-- work

# License choices offered without further conditions: LGPLv3+ or MIT (must reference source, similar to stack overflow sites from 2016 forward)

# Backblaze b2 wants sha1 sums; I want other secure hashes like SHA512 and maybe md5 for older record comparison; created at the same time.

# Python 3.4.2 reports hashlib.algorithms_guaranteed = {'sha224', 'sha384', 'sha1', 'sha512', 'md5', 'sha256'}

IO_BUFFER_SIZE = 65536

#CONFIG_FILE = '.pyb2push'

B2_AUTH_ID      = ''
B2_AUTH_KEY     = ''

import json
import hashlib
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

    @staticmethod
    def hashFile(sfile):
        try:
            with open(sfile, 'rb') as bfile:
                hl_md5      = hashlib.md5()
                hl_sha1     = hashlib.sha1()
                hl_sha256   = hashlib.sha256()
                hl_sha512   = hashlib.sha512()

                while True:
                    buf = bfile.read(IO_BUFFER_SIZE)
                    if buf:
                        hl_md5.update(buf)
                        hl_sha1.update(buf)
                        hl_sha256.update(buf)
                        hl_sha512.update(buf)
                    else:
                        break

                return {'md5':    hl_md5.hexdigest(),
                        'sha1':   hl_sha1.hexdigest(),
                        'sha256': hl_sha256.hexdigest(),
                        'sha512': hl_sha512.hexdigest()}

        except (Exception,) as e:
            raise e

    # These staticmethods are promoted to class methods in case derived classes use class state (E.G. a database connection)

    #@staticmethod
    def lookupBucket(self, bucket):
        fname = os.path.join('buckets', '{}.json'.format(bucket))
        if os.path.exists(fname):
            return json.load(open(fname, 'r'))
        return None

    #@staticmethod
    def storeBucket(self, bucket_obj):
        with open(os.path.join('buckets', '{}.json'.format(
                        bucket_obj['bucketName'])), 'w') as f:
            json.dump(bucket_obj, f, indent=0, sort_keys=True)

    #@staticmethod
    def lookupFile(self, path, attr):
        fname = '{}.json'.format(path)
        if os.path.exists(fname):  # FIXME: MAYBE: For the default 'on disk' implementation the attributes are presently ignored
            return json.load(open(fname, 'r'))
        return None

    #@staticmethod
    def storeFile(self, path, attr, info):
        info.update(attr)
        with open('{}.json'.format(path),
                    'w') as f:
            json.dump(info, f, indent=0, sort_keys=True)

    # b2_authorize_account
    def b2Auth(self, _id = B2_AUTH_ID, _key = B2_AUTH_KEY):
        auth = requests.auth.HTTPBasicAuth(_id, _key)
        r = self.s.get('https://api.backblaze.com/b2api/v1/b2_authorize_account', verify=True, auth=auth)
        if 200 == r.status_code:
            self.session = json.loads(r.text)
            self.s.headers.update({'Authorization': self.session['authorizationToken']})
        else:
            raise PermissionError("Unable to login to Backblaze B2: Status {}\n{}\n\n".format(r.status_code, r.text))
        return self.session

    # b2_create_bucket [A-Za-z0-9_-]{1,50}
    def b2GetOrCreateBucket(self, bucket):
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
                    self.b2GetBuckets()
                    if bucket in self.buckets:
                        return self.buckets[bucket]
                raise RuntimeError("Bucket Create Failure: Status {}\n{}\n\n".format(r.status_code, r.text))

        self.storeBucket(_bucket)
        self.buckets[_bucket['bucketName']] = _bucket
        return _bucket

    def b2GetBuckets(self):
        r = self.post(self.session['apiUrl'] + '/b2api/v1/b2_list_buckets', verify=True, data = json.dumps({'accountId': self.session['accountId']}))
        if 200 == r.status_code:
            for _bucket in json.loads(r.text)['buckets']:
                self.storeBucket(_bucket)
        else:
            raise RuntimeError("(get)Bucket List Failure: Status {}\n{}\n\n".format(r.status_code, r.text))

    #def b2GetFiles(self):  https://www.backblaze.com/b2/docs/b2_list_file_names.html  Cap of 1000 files, and lists per /bucket/

    # b2_get_upload_url
    def b2GetUploadURL(self, bucket):
        if isinstance(bucket, str):
            bucket = self.b2GetOrCreateBucket(bucket)

        req = { 'bucketId': bucket['bucketId'] }
        r = self.s.post(self.session['apiUrl'] + '/b2api/v1/b2_get_upload_url', verify=True, data = json.dumps(req))
        if 200 == r.status_code:
            return json.loads(r.text)
        else:
            raise RuntimeError("Get Upload URL Failure: Status {}\n{}\n\n".format(r.status_code, r.text))

    # b2_upload_file
    def b2UploadIfNew(self, bucket, path):
        info = self.hashFile(path)
        stats = os.stat(path)
        info['size'] = stats.st_size
        info['mtimens'] = stats.st_mtime_ns
        info['ctimens'] = stats.st_ctime_ns

        _file = self.lookupFile(path, info)
        if _file is None:
            bucket = self.b2GetUploadURL(bucket)
            headers = {
                'Authorization': bucket['authorizationToken'],
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
                r = ups.post(bucket['uploadUrl'], data=f, )
                if 200 == r.status_code:
                    self.storeFile(path, json.loads(r.text), info)
                    info.update(json.loads(r.text))
                    return info
                else:
                    raise RuntimeError("Upload Failure for {}: Status {}\n{}\n\n".format(path, r.status_code, r.text))
