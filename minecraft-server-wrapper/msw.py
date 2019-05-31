from __future__ import (absolute_import, division,
                        print_function, unicode_literals)
#from builtins import *
#from future.utils import iteritems
from six import iteritems

from io import open

# kate: replace-tabs on; indent-width 4; tab-indents true; tab-width 4; indent-mode python; auto-brackets false; bom false; eol unix;
# https://docs.kde.org/stable5/en/applications/katepart/kate-part-autoindent.html

import argparse
import datetime
import json
import os
from shutil import rmtree
import sys
from tempfile import mkdtemp
import unittest
import zipfile

# local module
try:
    import nbt
except ImportError:
    # see if it can be found in the parent folder
    extrasearchpath = os.path.realpath(os.path.join(__file__,os.pardir,os.pardir))
    if not os.path.exists(os.path.join(extrasearchpath,'nbt')):
        raise
    sys.path.append(extrasearchpath)
    import nbt

def perr(*a, **vargs):
    print(*a, file=sys.stderr, **vargs)

class MinecraftServerWrapper(object):
    """A Minecraft Server Wrapper"""

    def __init__(self):
        parser = argparse.ArgumentParser()
        parser.add_argument("-d", "--basedir", nargs='?', dest="basedir", default="", help="Specify a base save directory")
        parser.add_argument("-w", "--world", nargs='?', dest="world", default="world", help="Specify the world name (this is appended on to the base directory)")
        parser.add_argument("-c", "--config", nargs='?', dest="config", default="msw.config.json", help="The absolut path to check for a configuration file")
        parser.add_argument("-u", "--update-config-only", dest="update_config_only", action="store_true", help="Over-write the configuration file after validating known arguments (empty or invalid options set to defaults, preserve unknown tags), then exit.")
        parser.add_argument("-t", "--test", action="store_true", help="Run some unit tests, then exit.")
        self.parser = parser.parse_args()
        self.config = {}
        self.configPath = self.parser.config
        self.configLoad(self.configPath)
        if self.parser.basedir != "" or "basedir" not in self.config:
            self.config["basedir"] = self.parser.basedir
        if self.parser.world != "world" or "world" not in self.config:
            self.config["world"] = self.parser.world
        perr("msw __init__ completed :: version 20190530")

    def configLoad(self, a_file):
        raw_cfg = {}
        try:
            with open(a_file, "rt") as fp_cfg:
                raw_cfg = json.load(fp_cfg)
                fp_cfg.close()
        except Exception as e:
            perr("Error loading config file '{0}' {1}".format(a_file, e.__str__()))
            #raise e
        finally:
            self.configValidateAndSet(raw_cfg)

    def configValidateAndSet(self, raw_cfg):
        valid = True

        if "basedir" in raw_cfg:
            if not os.path.isdir(raw_cfg["basedir"]):
                valid = False
                perr("Provided config: 'basedir' is not a directory that exists")
        else:
            raw_cfg["basedir"] = ""

        if "world" in raw_cfg:
            if not os.path.isdir(os.path.join(raw_cfg["basedir"], raw_cfg["world"])):
                valid = False
                perr("Provided config: 'world' is not a directory that exists within 'basedir'")
        else:
            raw_cfg["world"] = ""

        if "backupdir" in raw_cfg:
            if not os.path.isdir(raw_cfg["backupdir"]):
                valid = False
                perr("Provided config: 'backupdir' is not a directory that exists")
        else:
            raw_cfg["backupdir"] = "backups"

        if "backupexclude" not in raw_cfg:
            raw_cfg["backupexclude"] = ["backups" + os.sep, "logs" + os.sep, "mods" + os.sep, "logs" + os.sep, ".jar", ".zip"]

        if "backup_strftime" not in raw_cfg:
            raw_cfg["backup_strftime"] = "backup_%Y%m%d_%H%M%S.%f.zip"

        if "SafeTP" in raw_cfg:
            for ii in range(0, 3):
                if not isinstance(raw_cfg["SafeTP"][ii], (int, float)):
                    valid = False
                    perr("Provided config: 'SafeTP' invalid number '{0}'".format(raw_cfg["Safe_TP"][ii]))
        else:
            raw_cfg["SafeTP"] = [0, 0.5, 80.0, 0.5]

        if "SaveRegions" in raw_cfg and "0" in raw_cfg["SaveRegions"] and "-1" in raw_cfg["SaveRegions"] and "1" in raw_cfg["SaveRegions"]:
            for kd in raw_cfg["SaveRegions"]:
                for vp in raw_cfg["SaveRegions"][kd]:
                    if not (vp[0] < vp[2] and vp[1] < vp[3]):
                        valid = False
                        perr("Invalid save region (bad ordering or non-rectagle zone?) for dimension number {0}: failed tests {1} < {2} and {3} < {4}".format(kd, vp[0], vp[1], vp[2], vp[3]))
        else:
            raw_cfg["SaveRegions"] = {"0":[[float('-inf'),float('-inf'),float('inf'),float('inf')]], "-1":[[float('-inf'),float('-inf'),float('inf'),float('inf')]], "1":[[float('-inf'),float('-inf'),float('inf'),float('inf')]]}

        if not "RegionPaths" in raw_cfg:
            raw_cfg["RegionPaths"] = {"0": "region", "-1": "DIM-1", "1": "DIM1"}

        for bopt in ["RunServer", "RunLoop", "ReloadConfigAfterExit", "BackupAfterExit", "SafeTPAfterExit", "PruneRegionsAfterExit", "BackupAfterCleanup"]:
            if bopt in raw_cfg:
                raw_cfg[bopt] = bool(raw_cfg[bopt])
            else:
                raw_cfg[bopt] = False

        if valid:
            self.config = raw_cfg
            return self.config
        return False

    def configSave(self, a_file):
        try:
            with open(a_file, "wb") as fp_cfg:
                json.dump(self.config, fp_cfg, indent=4, sort_keys=True)
                fp_cfg.close()
        except Exception as e:
            perr("Error saving config file '{0}' {1}".format(a_file, e.__str__()))
            raise e

    def run(self):
        pass # ### FIXME ### I've not yet decided on how to handle communication to/from the process, this is where that would go in the future.  https://docs.python.org/2/library/subprocess.html

    def createBackup(self):
        zf = zipfile.ZipFile(os.path.join(self.config["backupdir"], datetime.utcnow().strftime(self.config["backup_strftime"])), 'w', zipfile.ZIP_STORED) # alt zipfile.ZIP_DEFLATED but most of the data files are already compressed so...
        for root, dirs, files in os.walk(self.config["basedir"]):
            label_PEP3136 = False # This uglyness is EXACTLY the PROPER USE CASE for BREAK/CONTINUE LABEL
            tp = os.path.join(root, "Testing path exclusion")
            for v in raw_cfg["backupexclude"]:
                if tp.contains(v):
                    label_PEP3136 = True
                    break
            if label_PEP3136:
                continue
            for file in files:
                label_PEP3136 = False
                for v in raw_cfg["backupexclude"]:
                    if file.contains(v):
                        label_PEP3136 = True
                        break
                if label_PEP3136:
                    continue
                zf.write(os.path.join(root, file),
                        os.path.relpath(os.path.abspath(os.path.join(root, file)), os.path.abspath(self.config["basedir"])))
        zf.close() # Not Optional -- Finalizes zipfile structures.

    def cleanPlayerSafeTP(self):
        wd = os.path.normpath(os.path.join(self.config["basedir"], self.config["world"], "playerdata"))
        sDim, sX, sY, sZ = self.config["SafeTP"]
        for root, dirs, files in os.walk(wd):
            for fn in files:
                if fn.endswith(".dat") and len(fn) == 40:
                    uuid = fn[0:36]
                    player = nbt.nbt.NBTFile(os.path.join(root, fn), 'rb')
                    pDim, pX, pZ = str(player["Dimension"].value), player['Pos'][0].value, player['Pos'][2].value
                    pSafe = False
                    for saveBox in self.config["SaveRegions"][pDim]:
                        if saveBox[0] < pX and pX <= saveBox[2] and saveBox[1] < pZ and pZ <= saveBox[3]:
                            pSafe = True
                            break
                    if not pSafe:
                        player["Dimension"].value, player['Pos'][0].value, player['Pos'][1].value , player['Pos'][2].value = sDim, sX, sY, sZ
                        player.write_file()
                        print("Player outside of saved zones, teleported UUID {} from {} / {},?,{} to {} / {},{},{}".format(uuid, pDim, pX, pZ, sDim, sX, sY, sZ))

    def cleanPruneRegions(self):
        for (dn, sb) in iteritems(self.config["SaveRegions"]):
            for root, dirs, files in os.walk(os.path.normpath(os.path.join(self.config["basedir"], self.config["world"], self.config["RegionPaths"][dn]))):
                for fn in files:
                    if fn.startswith("r.") and fn.endswith(".mca"):
                        try:
                            keep = False
                            _, x, z, _ = fn.split(".")
                            x = int(x) * 512
                            z = int(z) * 512
                            rc = (x + 0.0001, z + 0.0001, x + 511.9999, z + 511.9999)
                            for saveBox in self.config["SaveRegions"][dn]:
                                if saveBox[0] <= rc[0] and rc[0] <= saveBox[2] and saveBox[1] <= rc[1] and rc[1] <= saveBox[3]:
                                    keep = True
                                    break
                                if saveBox[0] <= rc[0] and rc[0] <= saveBox[2] and saveBox[1] <= rc[3] and rc[3] <= saveBox[3]:
                                    keep = True
                                    break
                                if saveBox[0] <= rc[2] and rc[2] <= saveBox[2] and saveBox[1] <= rc[1] and rc[1] <= saveBox[3]:
                                    keep = True
                                    break
                                if saveBox[0] <= rc[2] and rc[2] <= saveBox[2] and saveBox[1] <= rc[3] and rc[3] <= saveBox[3]:
                                    keep = True
                                    break
                            if not keep:
                                os.unlink(os.path.join(root, fn))
                        except Exception as e:
                            perr("Error evaluating region file for pruning '{}' ({}): {}".format(fn, os.path.join(root, fn), e.__str__()))
                            continue

    def worker(self):
        if self.parser.update_config_only:
            self.configSave(self.configPath)
            return
        if self.parser.test:
            unittest.main(argv=sys.argv[0:1])
            sys.exit() # never reached, just documenting the behavior
        while True:
            if self.config["RunServer"]:
                self.run()
            if self.config["ReloadConfigAfterExit"]:
                self.configLoad(self.configPath)
            if self.config["BackupAfterExit"]:
                self.createBackup()
            if self.config["SafeTPAfterExit"]:
                # Set all players outside of the save areas list to the safe area
                self.cleanPlayerSafeTP()
            if self.config["PruneRegionsAfterExit"]:
                # Identify region files outside of the save areas, delete them
                self.cleanPruneRegions()
            if self.config["BackupAfterCleanup"]:
                self.createBackup()
            if not self.config["RunLoop"]:
                break
            
class TestTrim(unittest.TestCase):
    def setUp(self):
        self.path = mkdtemp()
        p = self.path
        os.makedirs(os.path.join(p, "logs"))
        os.makedirs(os.path.join(p, "world", "playerdata"))
        for d in [os.path.join(p, "world", "region"), os.path.join(p, "world", "DIM-1", "region"), os.path.join(p, "world", "DIM1", "region")]:
            os.makedirs(d)
            for x, y in [(x, y) for x in range(-10, 10) for y in range(-10, 10)]:
                 open(os.path.join(d, "r.{}.{}.mca".format(x, y)), "wb").close() # touch file
        player = nbt.nbt.NBTFile()
        player.name = "Player"
        player.tags.append(nbt.nbt.TAG_Int(name="Dimension", value=0))
        npos = nbt.nbt.TAG_List(name="Pos", type=nbt.nbt.TAG_Double)
        npos.tags.extend([nbt.nbt.TAG_Double(0.5), nbt.nbt.TAG_Double(128.0), nbt.nbt.TAG_Double(0.5)])
        player.tags.append(npos)
        player.write_file(os.path.join(p, "world", "playerdata", "00000000-0000-0000-0000-000000000000.dat"))
        player = nbt.nbt.NBTFile()
        player.name = "Player"
        player.tags.append(nbt.nbt.TAG_Int(name="Dimension", value=1))
        npos = nbt.nbt.TAG_List(name="Pos", type=nbt.nbt.TAG_Double)
        npos.tags.extend([nbt.nbt.TAG_Double(9000.5), nbt.nbt.TAG_Double(128.0), nbt.nbt.TAG_Double(9000.5)])
        player.tags.append(npos)
        player.write_file(os.path.join(p, "world", "playerdata", "ffffffff-ffff-ffff-ffff-ffffffffffff.dat"))
        
        self.msw = MinecraftServerWrapper()
        self.msw.configValidateAndSet({"basedir": p, "world": "world", "SafeTP": [0, 0.5, 80.0, 0.5], "SaveRegions": {"0": [[-2400.0, -2400.0, 2400.0, 2400.0]], "-1": [[float('-inf'),float('-inf'),float('inf'),float('inf')]], "1": [[0.0, 0.0, 511.0, 511.0]]}})

    def tearDown(self):
        rmtree(self.path)

    def test_cleanPlayerSafeTP(self):
        self.msw.cleanPlayerSafeTP()
        player = nbt.nbt.NBTFile(os.path.join(self.path, "world", "playerdata", "00000000-0000-0000-0000-000000000000.dat"), 'rb')
        self.assertEqual([0, 0.5, 128.0, 0.5], [player["Dimension"].value, player['Pos'][0].value, player['Pos'][1].value , player['Pos'][2].value], msg="Expected [0, 0.5, 128.0, 0.5] but got [{}, {}, {}, {}]".format(player["Dimension"].value, player['Pos'][0].value, player['Pos'][1].value , player['Pos'][2].value))
        player = nbt.nbt.NBTFile(os.path.join(self.path, "world", "playerdata", "ffffffff-ffff-ffff-ffff-ffffffffffff.dat"), 'rb')
        self.assertEqual([0, 0.5,  80.0, 0.5], [player["Dimension"].value, player['Pos'][0].value, player['Pos'][1].value , player['Pos'][2].value], msg="Expected [0, 0.5,  80.0, 0.5] but got [{}, {}, {}, {}]".format(player["Dimension"].value, player['Pos'][0].value, player['Pos'][1].value , player['Pos'][2].value))

    def test_cleanPruneRegions(self):
        self.msw.cleanPruneRegions()
        d = os.path.join(self.path, "world", "region")
        for x, y in [(x, y) for x in range(-5, 5) for y in range(-5, 5)]:
            p = os.path.join(d, "r.{}.{}.mca".format(x, y))
            self.assertTrue(os.path.exists(p), msg=p)
            os.unlink(p)
        for f in os.listdir(d):
            self.fail(msg="Path not expected to exist: {}".format(f))
        d = os.path.join(self.path, "world", "DIM-1", "region")
        for x, y in [(x, y) for x in range(-10, 10) for y in range(-10, 10)]:
            p = os.path.join(d, "r.{}.{}.mca".format(x, y))
            self.assertTrue(os.path.exists(p), msg=p)
            os.unlink(p)
        for f in os.listdir(d):
            self.fail(msg="Path not expected to exist: {}".format(f))
        d = os.path.join(self.path, "world", "DIM1", "region")
        p = os.path.join(d, "r.0.0.mca")
        self.assertTrue(os.path.exists(p), msg=p)
        os.unlink(p)
        for f in os.listdir(d):
            self.fail(msg="Path not expected to exist: {}".format(f))

if __name__ == '__main__':
    msw = MinecraftServerWrapper()
    msw.worker()


# https://www.multicraft.org/site/page/features
# https://www.multicraft.org/site/docs/howto#2.2.1
# https://dinnerbone.com/minecraft/tools/coordinates/
# https://minecraft.gamepedia.com/NBT_format
# https://github.com/twoolie/NBT  ### Currently supported versions: 2.7, 3.3, 3.4, 3.5, 3.6
# Example: https://github.com/twoolie/NBT/blob/master/examples/player_print.py
# https://minecraft.gamepedia.com/Player.dat_format
# https://minecraft.gamepedia.com/Chunk_format#Entity_format >> Pos: TAG_Doubles x,y,z  Dimension: w

# ### FIXME ###
# scrub all iteratoins https://python-future.org/compatible_idioms.html#dictionaries
# backup
# subprocess runner
# test
