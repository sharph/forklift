#!/usr/bin/env python

# This is, for the moment, code for testing.

from forklift import backup, status

s = status.ConsoleStatus()
s.printverbose = True

b = backup.Backup(status=s)

b.load_config_local('config')

b.snap_tree()

#b.restore_tree()

s.end()
