#!/usr/bin/env python

from pyaxo import Axolotl

argv = ['p', '-d', 'testfile.md.asc']

a = Axolotl('name2', dbname='name2.db', dbpassphrase=None)
a.loadState('name2', 'name1')

if argv[1] == '-e':
    a.encrypt_file(argv[2])
    print 'Encrypted file is ' + argv[2] + '.asc'
else:
    a.decrypt_file(argv[2])

a.saveState()
