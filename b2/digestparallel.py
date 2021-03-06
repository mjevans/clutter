

import os
import sys
import hashlib

from multiprocessing import Process, Pipe
#, Lock, RLock
from multiprocessing.sharedctypes import Array, Value
#, Value
from ctypes import c_char

HASH_FILE_BUFFER_SIZE = 64*1024


def digest(sfile, sha1each = 4 * 1024 * 1024, cmds = None):
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

        Pp_b2, Pc_b2 = Pipe()
        I_b2 = 0
        H_b2 = []
        P_b2 = Process(target=mpw_sha1, args=(Pc_b2,))

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
        P_b2.start()

        while True:
            buf = Pp_reader.recv()
            if buf is None:
                break

            Pp_reader.send("GO")

            for p, _ in Pp_workers:
                p.send(buf)

            t_b2 = I_b2
            I_b2 = I_b2 + len(buf)
            if t_b2 // sha1each != I_b2 // sha1each:
                t_b2 = sha1each - (t_b2  % sha1each)
                Pp_b2.send(buf[0:t_b2])
                if "OK" != Pp_b2.recv():
                    raise RuntimeError("Partial sha1each process got sick, the operation failed on chunk.")
                Pp_b2.send(None)
                H_b2.append(Pp_b2.recv())
                P_b2 = Process(target=mpw_sha1, args=(Pc_b2,))
                P_b2.start()
                if t_b2 < HASH_FILE_BUFFER_SIZE:
                    Pp_b2.send(buf[t_b2:])
            else:
                Pp_b2.send(buf)
                if "OK" != Pp_b2.recv():
                    raise RuntimeError("Partial sha1each process got sick, the operation failed.")

            # We need to wait for -all- workers
            for p, _ in Pp_workers:
                if "OK" != p.recv():
                    raise RuntimeError("One of the worker processes got sick, the operation failed.")

        Pp_b2.send(None)
        for p, _ in Pp_workers:
            p.send(None)
        H_b2.append(Pp_b2.recv())

        # All workers MUST exit, the following hash workers MUST return a hexdigest string/bytestring


        return {'md5':    Pp_workers[0][0].recv(),
                'sha1':   Pp_workers[1][0].recv(),
                'sha256': Pp_workers[2][0].recv(),
                'sha512': Pp_workers[3][0].recv(),
                'sha1each': H_b2}

    except (Exception,) as e:
        raise e
