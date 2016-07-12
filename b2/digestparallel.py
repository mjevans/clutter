

import os
import sys
import hashlib

from multiprocessing import Process, Pipe
#, Lock, RLock
from multiprocessing.sharedctypes import Array, Value
#, Value
from ctypes import c_char

HASH_FILE_BUFFER_SIZE = 64*1024


def digest(sfile, cmds = None):
    if cmds is None:
        cmds = []
    elif isinstance(cmds, str):
        cmds = [cmds]

    # processes
        
    def mpw_reader(p, sfile):
        with open(sfile, 'rb') as bfile:
            while True:
                if "GO" != p.recv():
                    break

                b_read = bfile.read(HASH_FILE_BUFFER_SIZE)
                if b_read:
                    p.send(b_read)
                else:
                    break
        p.send(None)

    def mpw_md5(p):
        hl = hashlib.md5()
        while True:
            buf = p.recv()
            if buf is not None:
                hl.update(buf)
                p.send("OK")
            else:
                p.send(hl.hexdigest())
                break

    def mpw_sha1(p):
        hl = hashlib.sha1()
        while True:
            buf = p.recv()
            if buf is not None:
                hl.update(buf)
                p.send("OK")
            else:
                p.send(hl.hexdigest())
                break

    def mpw_sha256(p):
        hl = hashlib.sha256()
        while True:
            buf = p.recv()
            if buf is not None:
                hl.update(buf)
                p.send("OK")
            else:
                p.send(hl.hexdigest())
                break

    def mpw_sha512(p):
        hl = hashlib.sha512()
        while True:
            buf = p.recv()
            if buf is not None:
                hl.update(buf)
                p.send("OK")
            else:
                p.send(hl.hexdigest())
                break


    # Supervisor Process

    try:
        Pp_reader, Pc_reader = Pipe()
        P_reader = Process(target=mpw_reader, args=(Pc_reader, sfile))
        P_reader.start()
        Pp_reader.send("GO")

        Pp_workers = [Pipe(), Pipe(), Pipe(), Pipe()]
        
        P_workers = {
            "md5":    Process(target=mpw_md5,    args=(Pp_workers[0][1],)),
            "sha1":   Process(target=mpw_sha1,   args=(Pp_workers[1][1],)),
            "sha256": Process(target=mpw_sha256, args=(Pp_workers[2][1],)),
            "sha512": Process(target=mpw_sha512, args=(Pp_workers[3][1],))
            }
        
        for c in cmds:
            pass
        
        for p in P_workers.values():
            p.start()
        
        while True:
            buf = Pp_reader.recv()
            if buf is None:
                break

            Pp_reader.send("GO")
            for p, _ in Pp_workers:
                p.send(buf)
    
            # We need to wait for -all- workers and the default ones are (probably) fastest to slowest anyway...
            
            for p, _ in Pp_workers:
                assert "OK" == p.recv()
                # raise RuntimeError("One of the worker threads got sick, the operation failed.")
                
        for p, _ in Pp_workers:
            p.send(None)
            
        # All workers MUST exit, the following hash workers MUST return a hexdigest string/bytestring

        
        return {'md5':    Pp_workers[0][0].recv(),
                'sha1':   Pp_workers[1][0].recv(),
                'sha256': Pp_workers[2][0].recv(),
                'sha512': Pp_workers[3][0].recv()}

    except (Exception,) as e:
        raise e
