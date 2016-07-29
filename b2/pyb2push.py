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
import time
import datetime


class RangeLimiter(object):
            def __init__(self, path, offset, limit, notify = 100 * 1024 * 1024, verbose = 0, growingFileRace = False):
                self.fh = open(path, 'rb', buffering=1*1024*1024) # Try reading ahead in case the underlying device has issues.
                self.fh.seek(offset, 0)
                self.offset = offset
                #self.fh = os.open(path, os.O_RDONLY|os.O_NONBLOCK)
                #self.fh.lseek(self.fh, offset, os.SEEK_SET)
                self.sent = 0
                self.progress = 1
                self.path = path
                self.notify = notify
                self.verbose = verbose
                if True == growingFileRace:
                    self.limit = limit
                else:
                    self.limit = min(limit, os.fstat(self.fh.fileno()).st_size - offset)
            def __exit__():
                if self.fh is not None:
                    os.close(self.fh)

            def __len__(self):
                # super_len() will probe for supporting len(RangeLimiter()) (find st_size)
                # https://github.com/kennethreitz/requests/blob/master/requests/utils.py
                return self.limit

            def read(self, amount=-1): # Emulate RawIOBase
                if self.limit == self.sent:
                    return b''
                elif self.sent > self.limit:
                    raise IndexError()
                else:
                    if -1 == amount:
                        amount = self.limit - self.sent
                    else:
                        amount = min(amount, self.limit - self.sent)
                    #buf = os.read(self.fh, amount)
                    t0 = time.perf_counter()
                    buf = self.fh.read(amount)
                    t1 = time.perf_counter()
                    if buf:
                        self.sent += len(buf)
                    if self.verbose > 0 and self.progress != self.sent // self.notify:
                        self.progress = self.sent // self.notify
                        if self.verbose > 2:
                            sys.stderr.write("\x1b[2J\x1b[H") # ANSI escape sequences: clear screen and move cursor
                        print("INFO: {} local read {:.3f} ( {} / {} ) + {} {}".format(
                                datetime.datetime.now().strftime("%Y%m%d-%H%M%S.%f"),
                                float(self.sent) / float(self.limit),
                                self.sent,
                                self.limit,
                                self.offset,
                                self.path), file=sys.stderr)
                        sys.stderr.flush()
                    if t1 - t0 > 1 or 0 == len(buf):
                        print("WARNING: current read ({} @ {}) {} seconds for {} bytes!".format(amount, self.sent, t1 - t0, len(buf)), file=sys.stderr)
                        sys.stderr.flush()
                    return buf


class b2:
    session = None
    # dict: accountId, apiUrl, authorizationToken, downloadUrl

    def __init__(self, authorizeNow = True, **overrides):
        # defaults
        self.b2id = None
        self.b2key = None
        self.authUrl = 'https://api.backblaze.com/b2api/v1/b2_authorize_account'
        self.bucketDir = os.path.join(os.getcwd(), 'buckets')
        self.largeFileChunk = 1 * 1024 * 1024 * 1024 # 512 * 1024 * 1024 # 4 * 1024 * 1024 * 1024
        self.minFileChunk =  100000000 # default B2 minimum; may be superceeded by b2_authorize_account
        self.maxFileChunk = 5000000000 # default B2 maximum; may be superceeded by b2_authorize_account
        self.retryDefault = 8 # seconds, default for start of exponential backoff.
        self.timeout = 35
        self.triesDefault = 5
        self.verbose = 3

        # resources
        self.s = requests.Session()
        self.buckets = {}

        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, 'r') as f:
                    print("Loaded b2id and b2key from local {}".format(CONFIG_FILE), file=sys.stderr)
                    cfg = json.load(f)
                    for k, v in crg.iter():
                        if k in self.__dict__:
                            setattr(self, k, v)
            elif os.path.exists(os.path.join(os.path.expanduser('~'), CONFIG_FILE)):
                with open(os.path.join(os.path.expanduser('~'), CONFIG_FILE), 'r') as f:
                    print("Loaded b2id and b2key from local ~/{}".format(CONFIG_FILE), file=sys.stderr)
                    cfg = json.load(f)
                    for k, v in crg.iter():
                        if k in self.__dict__:
                            setattr(self, k, v)
            else:
                print("b2 authorization not provided", file=sys.stderr)
        except (KeyError,) as e:
            print("b2 auth load failed {}".format(e), file=sys.stderr)


        for k, v in overrides.iter():
            setattr(self, k, v)


        if (self.bucketDir is not None and not os.path.isdir(self.bucketDir)):
            os.makedirs(self.bucketDir)


        if authorizeNow:
            self.session = self.authorizeAccount()


    # These were staticmethods but are now class methods in case derived classes use class state (E.G. a database connection)

    def lookupBucket(self, bucket):
        fname = os.path.join(self.bucketDir, '{}.json'.format(bucket))
        if os.path.exists(fname):
            if self.verbose >= 2:
                print("lookupBucket: exists {}".format(fname), file=sys.stderr)
            return json.load(open(fname, 'r'))
        if self.verbose >= 2:
            print("lookupBucket: miss {}".format(fname), file=sys.stderr)
        return None

    def storeBucket(self, bucket_obj):
        if self.verbose >= 2:
            print("storeBucket: {}".format(bucket_obj['bucketName']), file=sys.stderr)
        with open(os.path.join(self.bucketDir, '{}.json'.format(
                        bucket_obj['bucketName'])), 'w') as f:
            json.dump(bucket_obj, f, indent=0, sort_keys=True)

    def removeBucket(self, bucket_obj):
        if self.verbose >= 2:
            print("removeBucket: {}".format(bucket_obj['bucketName']), file=sys.stderr)
        try:
            os.unlink(os.path.join(self.bucketDir, '{}.json'.format(bucket_obj['bucketName'])))
        except (Exception, ) as e:
            pass

    def lookupFile(self, path, attr = None):
        fname = '{}.json'.format(path)
        if os.path.exists(fname):
            # FIXME: MAYBE: For the default 'on disk' implementation the attributes are presently not compared FIXME?
            if self.verbose >= 2:
                print("lookupFile: exists {}.json".format(path), file=sys.stderr)
            return json.load(open(fname, 'r'))
        if self.verbose >= 2:
            print("lookupFile: miss {}.json".format(path), file=sys.stderr)
        return None

    def storeFile(self, path, attr, info):
        if self.verbose >= 2:
            print("storeFile: {}.json".format(path), file=sys.stderr)
        info.update(attr)
        with open('{}.json'.format(path),
                    'w') as f:
            json.dump(info, f, indent=0, sort_keys=True)

    def removeFileNameId(self, fileName, fileId):
        if self.verbose >= 2:
            print("removeFileNameId: {}.json".format(fileName), file=sys.stderr)
        try:
            os.unlink('{}.json'.format(fileName))
        except (Exception, ) as e:
            pass

    # an interface for bulk operations in other storage methods
    def storeBuckets(self, buckets):
        for bucket in buckets:
            self.storeBucket(bucket)

    def storeFiles(self, files):
        for path, attr, info in files:
            self.storeFile(path, attr, info)

    def postAsJSON(self, path, data):
        jdata = json.dumps(data)
        if self.verbose >= 1:
            print("postAsJSON :: {}\n".format(jdata), file=sys.stderr)
        self.postB2(self.session['apiUrl'] + path, jdata, timeout = 35)

    # On BlockingIOError abort operational state; optional: retry from base state
    def postB2(self, postUrl, data, timeout = None, tries = 5, retryDefault = None):
        if timeout is None:
            timeout = self.timeout
        if tries is None:
            tries = self.triesDefault
        if retryDefault is None:
            retry = self.retryDefault
        else:
            retry = retryDefault

        while tries > 0:
            tries -= 1
            if self.verbose >= 1:
                print("{} :: {} tries remain:: {}\n".format(path, tries, datetime.datetime.now().strftime("%Y%m%d-%H%M%S.%f")), file=sys.stderr)
            try:
                r = self.s.post(self.session['apiUrl'] + path, verify=True, data=data, timeout=timeout)
                if self.verbose >= 1:
                    print("{} :: result :: {}\n\n{}\n".format(path, r.text, r.headers), file=sys.stderr)
                    sys.stderr.flush()

                if 200 == r.status_code:
                    return json.loads(r.text)

                if 'Retry-After' in r.headers:
                    retry = float(r.headers['Retry-After'])
                else:
                    retry *= 2

                if 401 == r.status_code:
                    time.sleep(retry)
                    self.authorizeAccount() # do not handle PermissionError
                elif 403 == r.status_code:
                    raise RuntimeError("CRITICAL: User review required: {} : {}".format(r.status_code, r.text))
                elif 429 == r.status_code:
                    print("BB 429 Too Many Requests, sleeping for {} seconds".format(retry), file=sys.stderr)
                    sys.stderr.flush()
                    sleep(retry)
                elif (400 <= r.status_code and r.status_code <= 499):
                    if path.find("_upload_"):
                        raise BlockingIOError()
                    else:
                        robj = json.loads(r.text)
                        if robj['code'] == 'duplicate_bucket_name':
                            print(  "WARNING: Duplicate bucket creation attempted, is our database complete?\n"
                                    "WARNING: Forcing enumeration of buckets.", file=sys.stderr)
                            self.listBuckets()
                            raise BlockingIOError()
                elif (500 <= r.status_code and r.status_code <= 599):
                    print("POST INFO {}: holding for 900 seconds ({} tries remain)\n\tStatus {}: {}\n\n".format(
                        path, tries, r.status_code, r.text), file=sys.stderr)
                    sys.stderr.flush()
                    time.sleep(900)
                    self.authorizeAccount() # do not handle PermissionError
                    if 503 == r.status_code:
                        raise BlockingIOError()
                else:
                    raise RuntimeError("POST ERROR {}:\nStatus {}\n{}\n\n".format(path, r.status_code, r.text))
            except (ConnectionError, requests.exceptions.RequestException, requests.exceptions.Timeout) as e:
                print("POST INFO {} ConnectionError holding for {} seconds ({} tries remain)\t:: {}\n\n".format(
                        path, retry, tries, e), file=sys.stderr)
                sys.stderr.flush()
                time.sleep(retry)
                ## self.authorizeAccount() # do not handle PermissionError

	    raise BlockingIOError() # Out of attempts.





    # b2_authorize_account
    def authorizeAccount(self, _id = None, _key = None):
        if _id is None: _id = self.b2id
        if _key is None: _key = self.b2key
        tries = 3
        while tries > 0:
            tries -= 1
            if self.verbose >= 1:
                print("\n\nb2_authorize_account :: {} tries remain\n".format(tries), file=sys.stderr)
            try:
                auth = requests.auth.HTTPBasicAuth(_id, _key)
                r = self.s.get(self.authUrl, verify=True, auth=auth, timeout=self.timeout)
                if self.verbose >= 1:
                    print("{}\n\n".format(r.text), file=sys.stderr)
                    sys.stderr.flush()
                if 200 == r.status_code:
                    self.session = json.loads(r.text)
                    self.s.headers.update({'Authorization': self.session['authorizationToken']})
                    if 'minimumPartSize' in self.session:
                        self.minFileChunk = int(self.session['minimumPartSize'])
                    break
                elif 401 == r.status_code:
                    raise PermissionError("Unable to login to Backblaze B2: Status {}\n{}\n\n".format(r.status_code, r.text))
            except (ConnectionError, ConnectionResetError, requests.exceptions.RequestException, requests.exceptions.Timeout) as e:
                pass
            print("AUTH INFO sleeping for 300 seconds ({} tries remain): {}: {}".format(tries, r.status_code, r.text))
            time.sleep(300)
        return self.session

    # b2_create_bucket [A-Za-z0-9_-]{1,50}  # b2GetOrCreateBucket
    def createBucket(self, bucket):
        _bucket = None
        if bucket in self.buckets:
            if self.verbose >= 1:
                print("createBucket: cached: {}".format(bucket), file=sys.stderr)
            return self.buckets[bucket]
        else:
            _bucket = self.lookupBucket(bucket)

        if _bucket is None:
            if self.verbose >= 1:
                print("createBucket: create: {}".format(bucket), file=sys.stderr)
            req = {
                'accountId':  self.session['accountId'],
                'bucketName': bucket,
                'bucketType': 'allPrivate'
                }
            _bucket = self.postAsJSON('/b2api/v1/b2_create_bucket', req)
            self.storeBucket(_bucket)
            self.buckets[_bucket['bucketName']] = _bucket
        else:
            if self.verbose >= 1:
                print("createBucket: lookup: {}".format(bucket), file=sys.stderr)

        return _bucket

    # b2_list_buckets # b2GetBuckets
    def listBuckets(self):
        self.storeBuckets(
            self.postAsJSON(
                '/b2api/v1/b2_list_buckets',
                {'accountId': self.session['accountId']}
                )['buckets']
            )

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

        self.postAsJSON('/b2api/v1/b2_delete_bucket', req)

        self.removeBucket(_bucket)
        if bname in self.buckets:
            del self.buckets[bname]

        return _bucket

    # b2_delete_file_version # b2DeleteFileVersion
    def deleteFileVersion(self, fileName, fileId):
        req = {
            'fileName': fileName,
            'fileId': fileId
        }
        try:
            ref = self.postAsJSON('/b2api/v1/b2_delete_file_version', req)
        except (BlockingIOError,) as e:
            if "file_not_present" != ref["code"]:
                raise e
        self.removeFileNameId(ref['fileName'], ref['fileId'])
        return ref


    # b2_get_upload_url # b2GetUploadURL
    def getUploadURL(self, bucket):
        if isinstance(bucket, str):
            bucket = self.createBucket(bucket)

        req = { 'bucketId': bucket['bucketId'] }
        return self.postAsJSON('/b2api/v1/b2_get_upload_url', req)

    # b2_upload_file # b2UploadIfNew
    def uploadFile(self, bucket, path, info = None):
        _file = self.lookupFile(path,None)
        stats = os.stat(path)
        if _file is None:
            if   (stats.st_size % self.largeFileChunk >= self.minFileChunk and
                  stats.st_size < self.largeFileChunk * 10000):
                fileChunk = self.largeFileChunk
            elif stats.st_size / self.largeFileChunk < 10000:
                fileChunk = self.largeFileChunk
            else:
                fileChunk = self.maxFileChunk

            info = digestparallel.digest(path, sha1each = fileChunk)
            info['fileChunk'] = fileChunk
        else:
            info = _file
        info['size'] = stats.st_size
        info['mtimens'] = stats.st_mtime_ns
        info['ctimens'] = stats.st_ctime_ns

        if stats.st_size > info['fileChunk']:
            if self.verbose >= 1:
                print("uploadFile: Large {}/{}".format(bucket, path), file=sys.stderr)
            if "largeFileState" not in info:
                bfile = self.startLargeFile(bucket, path, info)
                info["largeFileObj"] = bfile
                info["largeFileState"] = "Started"
                info["fileId"] = bfile["fileId"]
                self.storeFile(path, bfile, info)
                if self.verbose >= 2:
                    print("Started: {}/{} as {}".format(bucket, path, info["fileId"]),file=sys.stderr)
            elif "Complete" == info["largeFileState"]:
                if self.verbose >= 1:
                    print("File appears to be complete: {}/{} as {}".format(bucket, path, info["fileId"]), file=sys.stderr)
                return None
            else:
                bfile = info["largeFileObj"]
                if self.verbose >= 2:
                    print("Attempting to resume: {}/{} as {}".format(bucket, path, info["fileId"]), file=sys.stderr)
            skiplist = []
            if "uploaded" not in info:
                info["uploaded"] = []
            else:
                for oo in info["uploaded"]:
                    skiplist.append(oo["contentSha1"])
            pfile = self.getUploadPartURL(info["fileId"])
            for s_part, s_sha1 in enumerate(info["sha1each"]):
                if s_sha1 in skiplist:
                    print("Skipping previously uploaded section {} :: {}".format(s_part, s_sha1), file=sys.stderr)
                    continue
                tries = 3
                while tries > 0:
                    tries -= 1
                    if self.verbose >= 1:
                        print("uploadPart: {} tries remain: {} of Large {}/{}".format(tries, s_part, bucket, path), file=sys.stderr)
                        sys.stderr.flush()
                    try:
                        info["uploaded"].append(
                            self.uploadPart(path, info, s_part, s_sha1, pfile = pfile)
                        )
                        skiplist.append(s_sha1)
                        info["largeFileState"] = str(len(skiplist))
                        self.storeFile(path, bfile, info)
                        break
                    except (BlockingIOError,) as e:
                        pfile = self.getUploadPartURL(info["fileId"])
                else:
                    raise RuntimeError("ERROR: Tries exceeded while uploading large file part.")
            bfile = self.finishLargeFile(bfile["fileId"], info["sha1each"])
            info["largeFileState"] = "Complete"
            return self.storeFile(path, bfile, info)

        else:
            # Use classic single file method
            if _file:
                return None
            tries = 3
            while tries > 0:
                tries -= 1
                try:
                    bfile = self.getUploadURL(bucket)
                    headers = {
                        'Authorization': bfile['authorizationToken'],
                        'X-Bz-File-Name': path.replace(os.sep, '/'), # ??? https://www.backblaze.com/b2/docs/string_encoding.html ??? Python should work by default?
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
                        try:
                            if self.verbose >= 1:
                                print("uploadFile: Normal {} :: {}/{}".format(datetime.datetime.now().strftime("%Y%m%d-%H%M%S.%f"), bucket, path), file=sys.stderr)
                                sys.stderr.flush()
                            r = ups.post(bfile["uploadUrl"], verify=True, data = f, timeout=None)
                            if self.verbose >= 2:
                                print("uploadFile: Normal {} :: {}/{} -> {}".format(datetime.datetime.now().strftime("%Y%m%d-%H%M%S.%f"), bucket, path, r.text), file=sys.stderr)
                            if 200 == r.status_code:
                                bfile = json.loads(r.text)
                                if info['sha1'] != bfile["contentSha1"]:
                                    raise BlockingIOError()
                                self.storeFile(path, bfile, info)
                                return bfile
                            elif 401 == r.status_code:
                                time.sleep(15)
                                self.authorizeAccount() # do not handle PermissionError
                            elif 403 == r.status_code:
                                raise RuntimeError("CRITICAL: User review required: {} : {}".format(r.status_code, r.text))
                            elif (400 <= r.status_code and r.status_code <= 499):
                                raise BlockingIOError()
                            elif (500 <= r.status_code and r.status_code <= 599):
                                print("POST INFO {}: holding for 60 seconds ({} tries remain)\n\tStatus {}: {}\n\n".format(
                                    path, tries, r.status_code, r.text), file=sys.stderr)
                                time.sleep(60)
                                self.authorizeAccount() # do not handle PermissionError
                                raise BlockingIOError()
                            else:
                                raise RuntimeError("POST ERROR {}:\nStatus {}\n{}\n\n".format(path, r.status_code, r.text))
                        except (ConnectionError, ConnectionResetError, requests.exceptions.RequestException, requests.exceptions.Timeout) as e:
                            print("POST INFO {} ConnectionError holding for 60 seconds ({} tries remain)\t:: {}\n\n".format(
                                    path, tries, e), file=sys.stderr)
                            time.sleep(60)
                            self.authorizeAccount() # do not handle PermissionError
                            raise BlockingIOError()
                except (BlockingIOError,) as e:
                    pass


    # b2_start_large_file
    def startLargeFile(self, bucket, path, info):
        if isinstance(bucket, str):
            bucket = self.createBucket(bucket)

        req = { 'bucketId': bucket['bucketId'],
                'fileName': path.replace(os.sep, '/'),
                'contentType': 'b2/x-auto',
                'fileInfo': {
                    'src_last_modified_millis': str(int(info['mtimens'] / 1000.0)),
                    'md5': info['md5'],
                    'large_file_sha1': info['sha1'],
                    'sha256': info['sha256'],
                    'sha512': info['sha512']
                    }
                }
        return self.postAsJSON('/b2api/v1/b2_start_large_file', req)


    # b2_get_upload_part_url
    def getUploadPartURL(self, fileID):
        return self.postAsJSON('/b2api/v1/b2_get_upload_part_url', {"fileId": fileID})


    # b2_upload_part
    def uploadPart(self, path, info, s_part, s_sha1, pfile = None):
        if pfile is None:
            pfile = self.getUploadPartURL(info["fileId"])
        headers = {
            'Authorization': pfile['authorizationToken'],
            'X-Bz-Part-Number': s_part + 1,
            'Contnet-Length': \
                self.largeFileChunk \
                if s_part + 1 < len(info["sha1each"]) else \
                info["size"] % self.largeFileChunk,
            'X-Bz-Content-Sha1': s_sha1
            }
        ups = requests.Session()
        ups.headers.update(headers)
        f = RangeLimiter(path,
                            s_part * info['fileChunk'],
                            info['fileChunk'],
                            notify = 20 * 1024 * 1024,
                            verbose = 1)
        try:
            if self.verbose >= 1:
                print("uploadPart: {} :: {}".format(datetime.datetime.now().strftime("%Y%m%d-%H%M%S.%f"), path), file=sys.stderr)
                sys.stderr.flush()
            r = ups.post(pfile["uploadUrl"], verify=True, data = f, timeout=None)
            if self.verbose >= 2:
                print("uploadPart: {} :: {} -> {}".format(datetime.datetime.now().strftime("%Y%m%d-%H%M%S.%f"), path, r.text), file=sys.stderr)
            robj = json.loads(r.text)
            if 200 == r.status_code:
                if s_sha1 != robj["contentSha1"]:
                    raise BlockingIOError()
                return robj
            elif 401 == r.status_code:
                time.sleep(15)
                self.authorizeAccount() # do not handle PermissionError
            elif 403 == r.status_code:
                raise RuntimeError("CRITICAL: User review required: {} : {}".format(r.status_code, r.text))
            elif (400 <= r.status_code and r.status_code <= 499):
                raise BlockingIOError()
            elif (500 <= r.status_code and r.status_code <= 599):
                print("POST INFO {}: holding for 60 seconds\n\tStatus {}: {}\n\n".format(
                    path, r.status_code, r.text), file=sys.stderr)
                time.sleep(60)
                self.authorizeAccount() # do not handle PermissionError
                raise BlockingIOError()
            else:
                raise RuntimeError("POST ERROR {}:\nStatus {}\n{}\n\n".format(path, r.status_code, r.text))
        except (ConnectionError, ConnectionResetError, requests.exceptions.RequestException, requests.exceptions.Timeout) as e:
            print("POST INFO {} ConnectionError holding for 60 seconds\t:: {}\n\n".format(
                    path, e), file=sys.stderr)
            time.sleep(60)
            self.authorizeAccount() # do not handle PermissionError
            raise BlockingIOError()



    # b2_cancel_large_file
    def cancelLargeFile(self, fileID):
        return self.postAsJSON('/b2api/v1/b2_cancel_large_file', { "fileId": fileID})

    # b2_finish_large_file
    def finishLargeFile(self, fileID, sha1each):
        return self.postAsJSON('/b2api/v1/b2_finish_large_file',
                                { "fileId": fileID, "partSha1Array": sha1each})

def simpleExample(bucket_files):
    bb = b2()
    cwd = os.getcwd()
    if len(bucket_files) > 0:
        #pass
        #print("Attempting to authorizeAccount", file=sys.stderr)
        bb.authorizeAccount()
    #bb.cancelLargeFile("")
    for apath in bucket_files:
        bucket, rpath = os.path.relpath(apath, start=cwd).split(os.sep, 1)
        os.chdir(bucket)
        if os.path.exists(rpath):
            print("{} :: {}".format(bucket, rpath), file=sys.stderr)
            bb.uploadFile(bucket, rpath)
        os.chdir(cwd)

if __name__ == "__main__":
    simpleExample(sys.argv[1:])



"""
https://api.backblaze.com/b2api/v1/ with LargeFile (current as of 2016-07)

b2 API wrappers will methods named in camelCase (medial capitals)

*b2_authorize_account
*b2_cancel_large_file
*b2_create_bucket
*b2_delete_bucket
*b2_delete_file_version
b2_download_file_by_id
b2_download_file_by_name
*b2_finish_large_file
b2_get_file_info
*b2_get_upload_part_url
*b2_get_upload_url
b2_hide_file
*b2_list_buckets
b2_list_file_names
b2_list_file_versions
b2_list_parts
b2_list_unfinished_large_files
*b2_start_large_file
b2_update_bucket
*b2_upload_file
*b2_upload_part

https://www.backblaze.com/b2/docs/b2_list_file_names.html  Cap of 1000 files, and lists per /bucket/

https://www.backblaze.com/b2/docs/large_files.html

Large files must be at least 100MB (100MB+1byte), have a part limit of 5-billion-bytes, and a max size of 10TB (they mean billion bytes).

Parts start at 1 (Q: 0 is the whole file?)

The sha1 checksum of each segment must be specified for that segment, an sha1 of the whole file is optional (recommended).

sed -i 's/^[[:space:]]\+$//'
sed -i 's/[[:space:]]\+$//'


"""
