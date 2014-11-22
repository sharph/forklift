#!/usr/bin/env python

import sys
import os
import filecmp
import shutil

sys.path.append('..')

from forklift import backup, status

def random_data(size):
    return open('/dev/urandom','rb').read(size)

def gen_random_data(path):
    files = []
    for n in xrange(0, 24, 3):
        print "Creating {}MB file".format(n)
        data = random_data(n * 1024 * 1024)
        filename = os.path.join(path, str(n))
        files.append(str(n))
        with open(filename, 'wb') as f:
            f.write(data)
        files.append(str(n) + '.dedup')
        with open(filename + '.dedup', 'wb') as f:
            f.write(data)
    return files


configs = [
    {
        'local_paths': [''],
        'destination': [{'path': 'tmp/sqlite.test', 'type': 'sqlite'}]
    },
    {
        'local_paths': [''],
        'redundancy': 2,
        'destination': [{'path': 'tmp/fstest1', 'type': 'local'},
                        {'path': 'tmp/fstest2', 'type': 'local'},
                        {'path': 'tmp/fstest3', 'type': 'local'}]
    }
]

infilesdir = os.path.join(os.getcwd(), 'infiles/')
outfilesdir = os.path.join(os.getcwd(), 'outfiles/')

try:
    os.mkdir(infilesdir)
except OSError:
    pass

files = gen_random_data(infilesdir)

for num, config in enumerate(configs, 1):
    os.mkdir(outfilesdir) # should not exist yet
    os.mkdir('tmp')
    s = status.ConsoleStatus()
    s.printverbose = True
    b = backup.Backup(config=config, status=s)
    b.root = infilesdir
    b.snap_tree()
    if num == 2:
        shutil.rmtree('tmp/fstest2')
    b.root = outfilesdir
    b.restore_tree()
    for filename in files:
        assert filecmp.cmp(os.path.join(infilesdir, filename),
                           os.path.join(outfilesdir, filename))
        print " -- {} OK!".format(filename)
    shutil.rmtree(outfilesdir)
    shutil.rmtree('tmp')
    print " -- Test of config #{} complete".format(num)

shutil.rmtree(infilesdir)

print " -- Tests complete"
