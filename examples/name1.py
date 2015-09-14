#!/usr/bin/env python

from pyaxo import Axolotl

argv = ['progname', '-e', 'testfile.md']

a = Axolotl('name1', dbname='name1.db', dbpassphrase=None)
a.loadState('name1', 'name2')

if argv[1] == '-e':
    a.encrypt_file(argv[2])
    print 'Encrypted file is ' + argv[2] + '.asc'
else:
    a.decrypt_file(argv[2])

a.saveState()
