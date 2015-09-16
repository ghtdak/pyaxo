#!/usr/bin/env python

import os

from pyaxo import Axolotl


# start with a fresh database
try:
    os.remove('./alice.db')
    os.remove('./bob.db')
except OSError:
    pass

# unencrypted databases
a = Axolotl('alice', dbname='alice.db', dbpassphrase=None)
b = Axolotl('bob', dbname='bob.db', dbpassphrase=None)

a.initState('bob', b.state['DHIs'], b.handshakePKey,
            b.state['DHRs'], verify=False)
b.initState('alice', a.state['DHIs'], a.handshakePKey,
            a.state['DHRs'], verify=False)

a.saveState()
b.saveState()
