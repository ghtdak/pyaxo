from __future__ import print_function

"""
pyaxo.py - a python implementation of the axolotl ratchet protocol.
https://github.com/trevp/axolotl/wiki/newversion

Symmetric encryption is done using the python-gnupg module.

Copyright (C) 2014 by David R. Andersen <k0rx@RXcomm.net>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.

For more information, see https://github.com/rxcomm/pyaxo
"""

import sqlite3
from hashlib import sha256, sha224
from binascii import a2b_base64, hexlify, unhexlify, b2a_base64
import os
import sys
from getpass import getpass
from time import time

from gnupg import GPG
from passlib.utils.pbkdf2 import pbkdf2
from curve25519 import keys


# We cut out the inner cipher header to minimize bandwidth
# and then add it back at decrypt time.
cipher_hdr = {
    'IDEA': '8c0d04010308',
    '3DES': '8c0d04020308',
    'CAST5': '8c0d04030308',
    'BLOWFISH': '8c0d04040308',
    # 'RESERVED1' :   '8c0d04050308',
    # 'RESERVED2' :   '8c0d04060308',
    'AES': '8c0d04070308',
    'AES192': '8c0d04080308',
    'AES256': '8c0d04090308',
    'TWOFISH': '8c0d040a0308',
    'CAMELLIA128': '8c0d040b0308',
    'CAMELLIA192': '8c0d040c0308',
    'CAMELLIA256': '8c0d040d0308'
}

GPG_CIPHER = 'AES256'
GPG_HEADER = unhexlify(cipher_hdr[GPG_CIPHER])


class Axolotl_exception(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class Axolotl:
    def __init__(self, name, dbname='axolotl.db', dbpassphrase='',
                 user_pathstring='~'):
        self.ratchetKey = None
        self.ratchetPKey = None
        self.name = name
        self.db = None
        self.mode = None
        self.staged_HK_mk = None
        self.state = None
        self.handshakeKey = None
        self.handshakePKey = None
        self.storeTime = None

        user_path = os.path.expanduser(user_pathstring)
        keyring = [user_path + '/.gnupg/pubring.gpg']
        secret_keyring = [user_path + '/.gnupg/secring.gpg']

        self.dbname = user_path + '/tmp/pyaxo_db/' + dbname

        self.gpg = GPG(gnupghome=user_path + '/.axolotl', gpgbinary='gpg',
                       keyring=keyring,
                       secret_keyring=secret_keyring,
                       options=['--throw-keyids',
                                '--personal-digest-preferences=sha256',
                                '--s2k-digest-algo=sha256'])
        self.gpg.encoding = 'utf-8'

        if dbpassphrase != '' or dbpassphrase is None:
            self.dbpassphrase = dbpassphrase
        else:
            self.dbpassphrase = getpass(
                'Database passphrase for ' + self.name + ': ').strip()

        self.db_init()

    def db_init(self):

        try:
            self.db = self.open_db()
        except sqlite3.OperationalError:
            raise (Axolotl_exception('Bad sql! Password problem - \
            cannot create the database.'))

        self.mode = None
        self.staged_HK_mk = {}

        self.state = {}
        self.state['DHIs_priv'], self.state['DHIs'] = self.genKey()
        self.state['DHRs_priv'], self.state['DHRs'] = self.genKey()

        self.handshakeKey, self.handshakePKey = self.genKey()

        # minimum time (seconds) to store missed ephemeral message keys
        self.storeTime = 2 * 86400
        with self.db:
            cur = self.db.cursor()

            cur.execute("""\
            CREATE TABLE IF NOT EXISTS skipped_mk (
              my_identity,
              to_identity,
              HKr TEXT,
              mk TEXT,
              timestamp INTEGER )""")

            cur.execute("""\
            CREATE UNIQUE INDEX IF NOT EXISTS \
                         message_keys ON skipped_mk (mk)""")

            cur.execute("""\
            CREATE TABLE IF NOT EXISTS conversations (
              my_identity TEXT,
              other_identity TEXT,
              RK TEXT,
              HKs TEXT,
              HKr TEXT,
              NHKs TEXT,
              NHKr TEXT,
              CKs TEXT,
              CKr TEXT,
              DHIs_priv TEXT,
              DHIs TEXT,
              DHIr TEXT,
              DHRs_priv TEXT,
              DHRs TEXT,
              DHRr TEXT,
              CONVid TEXT,
              Ns INTEGER,
              Nr INTEGER,
              PNs INTEGER,
              ratchet_flag INTEGER,
              mode INTEGER
            )""")

            cur.execute("""\
            CREATE UNIQUE INDEX IF NOT EXISTS
                         conversation_route ON
                         conversations (my_identity, other_identity)""")
        self.commit_skipped_mk()

    def triple_dh(self, a, a0, B, B0):
        if self.mode is None:
            raise (Axolotl_exception('Mode must be set'))
        if self.mode:
            return sha256(
                self.gen_dh(a, B0) + self.gen_dh(a0, B) +
                self.gen_dh(a0, B0)).digest()
        else:
            return sha256(
                self.gen_dh(a0, B) + self.gen_dh(a, B0) +
                self.gen_dh(a0, B0)).digest()

    def initState(self, other_name, other_identityKey, other_handshakeKey,
                  other_ratchetKey, verify=True):
        if verify:
            print('Confirm ' + other_name + ' has identity key fingerprint:\n')
            fingerprint = sha224(other_identityKey).hexdigest().upper()
            fprint = ''
            for i in range(0, len(fingerprint), 4):
                fprint += fingerprint[i:i + 2] + ':'
            print(fprint[:-1] + '\n')
            print('Be sure to verify this fingerprint with ' + other_name +
                  ' by some out-of-band method!')
            print('Otherwise, you may be subject to a \
            Man-in-the-middle attack!\n')
            ans = raw_input('Confirm? y/N: ').strip()
            if ans != 'y':
                raise (Axolotl_exception('Key fingerprint \
                not confirmed - exception'))

        if self.state['DHIs'] < other_identityKey:
            self.mode = True
        else:
            self.mode = False
        mkey = self.triple_dh(self.state['DHIs_priv'], self.handshakeKey,
                              other_identityKey, other_handshakeKey)

        self.createState(other_name, mkey,
                         mode=self.mode,
                         other_identityKey=other_identityKey,
                         other_ratchetKey=other_ratchetKey)

    def createState(self, other_name, mkey, mode=None, other_identityKey=None,
                    other_ratchetKey=None):
        self.mode = mode

        if self.mode is None:  # mode not selected
            raise (Axolotl_exception('Mode must be set'))
        if self.mode:  # alice mode
            RK = pbkdf2(mkey, b'\x00', 10, prf='hmac-sha256')
            HKs = None
            HKr = pbkdf2(mkey, b'\x02', 10, prf='hmac-sha256')
            NHKs = pbkdf2(mkey, b'\x03', 10, prf='hmac-sha256')
            NHKr = pbkdf2(mkey, b'\x04', 10, prf='hmac-sha256')
            CKs = None
            CKr = pbkdf2(mkey, b'\x06', 10, prf='hmac-sha256')
            DHRs_priv = None
            DHRs = None
            DHRr = other_ratchetKey
            CONVid = pbkdf2(mkey, b'\x07', 10, prf='hmac-sha256')
            Ns = 0
            Nr = 0
            PNs = 0
            ratchet_flag = True
        else:  # bob mode
            RK = pbkdf2(mkey, b'\x00', 10, prf='hmac-sha256')
            HKs = pbkdf2(mkey, b'\x02', 10, prf='hmac-sha256')
            HKr = None
            NHKs = pbkdf2(mkey, b'\x04', 10, prf='hmac-sha256')
            NHKr = pbkdf2(mkey, b'\x03', 10, prf='hmac-sha256')
            CKs = pbkdf2(mkey, b'\x06', 10, prf='hmac-sha256')
            CKr = None
            DHRs_priv = self.state['DHRs_priv']
            DHRs = self.state['DHRs']
            DHRr = None
            CONVid = pbkdf2(mkey, b'\x07', 10, prf='hmac-sha256')
            Ns = 0
            Nr = 0
            PNs = 0
            ratchet_flag = False
        DHIr = other_identityKey

        self.state = \
            {'name': self.name,
             'other_name': other_name,
             'RK': RK,
             'HKs': HKs,
             'HKr': HKr,
             'NHKs': NHKs,
             'NHKr': NHKr,
             'CKs': CKs,
             'CKr': CKr,
             'DHIs_priv': self.state['DHIs_priv'],
             'DHIs': self.state['DHIs'],
             'DHIr': DHIr,
             'DHRs_priv': DHRs_priv,
             'DHRs': DHRs,
             'DHRr': DHRr,
             'CONVid': CONVid,
             'Ns': Ns,
             'Nr': Nr,
             'PNs': PNs,
             'ratchet_flag': ratchet_flag,
             }

        self.ratchetKey = False
        self.ratchetPKey = False

    def encrypt(self, plaintext):
        if self.state['ratchet_flag']:
            self.state['DHRs_priv'], self.state['DHRs'] = self.genKey()
            self.state['HKs'] = self.state['NHKs']
            self.state['RK'] = sha256(self.state['RK'] +
                                      self.gen_dh(
                                          self.state['DHRs_priv'],
                                          self.state['DHRr'])).digest()
            if self.mode:
                self.state['NHKs'] = pbkdf2(self.state['RK'], b'\x03', 10,
                                            prf='hmac-sha256')
                self.state['CKs'] = pbkdf2(self.state['RK'], b'\x05', 10,
                                           prf='hmac-sha256')
            else:
                self.state['NHKs'] = pbkdf2(self.state['RK'], b'\x04', 10,
                                            prf='hmac-sha256')
                self.state['CKs'] = pbkdf2(self.state['RK'], b'\x06', 10,
                                           prf='hmac-sha256')
            self.state['PNs'] = self.state['Ns']
            self.state['Ns'] = 0
            self.state['ratchet_flag'] = False
        mk = sha256(self.state['CKs'] + '0').digest()
        msg1 = self.enc(self.state['HKs'], str(self.state['Ns']).zfill(3) +
                        str(self.state['PNs']).zfill(3) + self.state['DHRs'])
        msg2 = self.enc(mk, plaintext)
        pad_length = 106 - len(msg1)
        pad = os.urandom(pad_length - 1) + chr(pad_length)
        msg = msg1 + pad + msg2
        self.state['Ns'] += 1
        self.state['CKs'] = sha256(self.state['CKs'] + '1').digest()
        return msg

    def commit_skipped_mk(self):
        timestamp = int(time())
        with self.db:
            cur = self.db.cursor()
            for mk, HKr in self.staged_HK_mk.iteritems():
                cur.execute("""\
                REPLACE INTO skipped_mk (
                  my_identity,
                  to_identity,
                  HKr,
                  mk,
                  timestamp
                ) VALUES (?, ?, ?, ?, ?)""",
                            (self.state['name'],
                             self.state['other_name'],
                             b2a_base64(HKr).strip(),
                             b2a_base64(mk).strip(),
                             timestamp
                             ))
            rowtime = timestamp - self.storeTime
            cur.execute('DELETE FROM skipped_mk WHERE timestamp < ?',
                        (rowtime,))

    def trySkippedMK(self, msg, pad_length, name, other_name):
        with self.db:
            cur = self.db.cursor()
            cur.execute('SELECT * FROM skipped_mk')
            rows = cur.fetchall()
            for row in rows:
                if name == row[0] and other_name == row[1]:
                    msg1 = msg[:106 - pad_length]
                    msg2 = msg[106:]
                    header = self.dec(a2b_base64(row[2]), msg1)
                    body = self.dec(a2b_base64(row[3]), msg2)
                    if header != '' and body != '':
                        cur.execute('DELETE FROM skipped_mk WHERE mk = ?',
                                    (row[3],))
                        return body
        return False

    def stageSkippedMK(self, HKr, Nr, Np, CKr):
        CKp = CKr
        for i in range(Np - Nr):
            mk = sha256(CKp + '0').digest()
            CKp = sha256(CKp + '1').digest()
            self.staged_HK_mk[mk] = HKr
        mk = sha256(CKp + '0').digest()
        CKp = sha256(CKp + '1').digest()
        return CKp, mk

    def decrypt(self, msg):
        pad = msg[105:106]
        pad_length = ord(pad)
        msg1 = msg[:106 - pad_length]

        body = self.trySkippedMK(msg, pad_length, self.state['name'],
                                 self.state['other_name'])
        if body and body != '':
            return body

        header = None
        if self.state['HKr']:
            header = self.dec(self.state['HKr'], msg1)
        if header and header != '':
            Np = int(header[:3])
            CKp, mk = self.stageSkippedMK(self.state['HKr'], self.state['Nr'],
                                          Np, self.state['CKr'])
            body = self.dec(mk, msg[106:])
            if not body or body == '':
                raise (Axolotl_exception('Undecipherable message'))
        else:
            header = self.dec(self.state['NHKr'], msg1)
            if self.state['ratchet_flag'] or not header or header == '':
                raise (Axolotl_exception('Undecipherable message'))

            Np = int(header[:3])
            PNp = int(header[3:6])
            DHRp = header[6:]
            if self.state['CKr']:
                self.stageSkippedMK(self.state['HKr'], self.state['Nr'], PNp,
                                    self.state['CKr'])
            HKp = self.state['NHKr']
            RKp = sha256(
                self.state['RK'] + self.gen_dh(self.state['DHRs_priv'],
                                               DHRp)).digest()
            if self.mode:
                NHKp = pbkdf2(RKp, b'\x04', 10, prf='hmac-sha256')
                CKp = pbkdf2(RKp, b'\x06', 10, prf='hmac-sha256')
            else:
                NHKp = pbkdf2(RKp, b'\x03', 10, prf='hmac-sha256')
                CKp = pbkdf2(RKp, b'\x05', 10, prf='hmac-sha256')
            CKp, mk = self.stageSkippedMK(HKp, 0, Np, CKp)
            body = self.dec(mk, msg[106:])
            if not body or body == '':
                raise (Axolotl_exception('Undecipherable message'))

            self.state['RK'] = RKp
            self.state['HKr'] = HKp
            self.state['NHKr'] = NHKp
            self.state['DHRr'] = DHRp
            self.state['DHRs_priv'] = None
            self.state['DHRs'] = None
            self.state['ratchet_flag'] = True
        self.commit_skipped_mk()
        self.state['Nr'] = Np + 1
        self.state['CKr'] = CKp
        return body

    def encrypt_file(self, filename):
        with open(filename, 'r') as f:
            plaintext = f.read()
        ciphertext = b2a_base64(self.encrypt(plaintext))
        with open(filename + '.asc', 'w') as f:
            lines = [ciphertext[i:i + 64] for i in
                     xrange(0, len(ciphertext), 64)]
            for line in lines:
                f.write(line + '\n')

    def decrypt_file(self, filename):
        with open(filename, 'r') as f:
            ciphertext = a2b_base64(f.read())
        plaintext = self.decrypt(ciphertext)
        print(plaintext)

    def encrypt_pipe(self):
        plaintext = sys.stdin.read()
        ciphertext = b2a_base64(self.encrypt(plaintext))
        sys.stdout.write(ciphertext)
        sys.stdout.flush()

    def decrypt_pipe(self):
        ciphertext = a2b_base64(sys.stdin.read())
        plaintext = self.decrypt(ciphertext)
        sys.stdout.write(plaintext)
        sys.stdout.flush()

    def printKeys(self):
        print('Your Identity key is:\n' + b2a_base64(
            self.state['DHIs']))
        fingerprint = sha224(self.state['DHIs']).hexdigest().upper()
        fprint = ''
        for i in range(0, len(fingerprint), 4):
            fprint += fingerprint[i:i + 2] + ':'
        print('Your identity key fingerprint is: ')
        print(fprint[:-1] + '\n')
        print('Your Ratchet key is:\n' + b2a_base64(
            self.state['DHRs']))
        if self.handshakeKey:
            print('Your Handshake key is:\n' + b2a_base64(
                self.handshakePKey))
        else:
            print('Your Handshake key is not available')

    def saveState(self):
        HKs = 0 if self.state['HKs'] is None else b2a_base64(
            self.state['HKs']).strip()
        HKr = 0 if self.state['HKr'] is None else b2a_base64(
            self.state['HKr']).strip()
        CKs = 0 if self.state['CKs'] is None else b2a_base64(
            self.state['CKs']).strip()
        CKr = 0 if self.state['CKr'] is None else b2a_base64(
            self.state['CKr']).strip()
        DHIr = 0 if self.state['DHIr'] is None else b2a_base64(
            self.state['DHIr']).strip()
        DHRs_priv = 0 if self.state[
                             'DHRs_priv'] is None else b2a_base64(
            self.state['DHRs_priv']).strip()
        DHRs = 0 if self.state['DHRs'] is None else b2a_base64(
            self.state['DHRs']).strip()
        DHRr = 0 if self.state['DHRr'] is None else b2a_base64(
            self.state['DHRr']).strip()
        ratchet_flag = 1 if self.state['ratchet_flag'] else 0
        mode = 1 if self.mode else 0
        with self.db:
            cur = self.db.cursor()
            cur.execute("""\
            REPLACE INTO conversations (
                       my_identity,
                       other_identity,
                       RK,
                       HKS,
                       HKr,
                       NHKs,
                       NHKr,
                       CKs,
                       CKr,
                       DHIs_priv,
                       DHIs,
                       DHIr,
                       DHRs_priv,
                       DHRs,
                       DHRr,
                       CONVid,
                       Ns,
                       Nr,
                       PNs,
                       ratchet_flag,
                       mode
                       ) VALUES (
                       ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                       ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (self.state['name'],
                         self.state['other_name'],
                         b2a_base64(self.state['RK']).strip(),
                         HKs,
                         HKr,
                         b2a_base64(self.state['NHKs']).strip(),
                         b2a_base64(self.state['NHKr']).strip(),
                         CKs,
                         CKr,
                         b2a_base64(self.state['DHIs_priv']).strip(),
                         b2a_base64(self.state['DHIs']).strip(),
                         DHIr,
                         DHRs_priv,
                         DHRs,
                         DHRr,
                         b2a_base64(self.state['CONVid']).strip(),
                         self.state['Ns'],
                         self.state['Nr'],
                         self.state['PNs'],
                         ratchet_flag,
                         mode
                         ))
        self.write_db()

    def loadState(self, name, other_name):
        self.db = self.open_db()
        with self.db:
            cur = self.db.cursor()
            try:
                cur.execute('SELECT * FROM conversations')
            except sqlite3.OperationalError:
                raise (Axolotl_exception('Bad sql! Password problem - \
                cannot loadState()'))

            rows = cur.fetchall()
            for row in rows:
                if row[0] == name and row[1] == other_name:
                    self.state = \
                        {'name': row[0],
                         'other_name': row[1],
                         'RK': a2b_base64(row[2]),
                         'NHKs': a2b_base64(row[5]),
                         'NHKr': a2b_base64(row[6]),
                         'DHIs_priv': a2b_base64(row[9]),
                         'DHIs': a2b_base64(row[10]),
                         'CONVid': a2b_base64(row[15]),
                         'Ns': row[16],
                         'Nr': row[17],
                         'PNs': row[18],
                         }
                    self.name = self.state['name']

                    def do_bin(loc):
                        if row[loc] == '0':
                            return None
                        else:
                            return a2b_base64(row[loc])

                    self.state['HKs'] = do_bin(3)
                    self.state['HKr'] = do_bin(4)
                    self.state['CKs'] = do_bin(7)
                    self.state['CKr'] = do_bin(8)
                    self.state['DHIr'] = do_bin(11)
                    self.state['DHRs_priv'] = do_bin(12)
                    self.state['DHRs'] = do_bin(13)
                    self.state['DHRr'] = do_bin(14)

                    ratchet_flag = row[19]
                    if ratchet_flag == 1:
                        self.state['ratchet_flag'] = True
                    else:
                        self.state['ratchet_flag'] = False

                    mode = row[20]
                    self.mode = True if mode == 1 else False
                    return  # exit at first match
            return False  # if no matches

    def open_db(self):

        db = sqlite3.connect(':memory:')

        try:
            with open(self.dbname, 'rb') as f:
                if self.dbpassphrase is not None:
                    sql = self.gpg.decrypt_file(f,
                                                passphrase=self.dbpassphrase)
                    if sql is not None and sql != '':
                        db.cursor().executescript(sql.data)
                        return db
                    else:
                        raise (Axolotl_exception('Bad passphrase!'))

                else:
                    sql = f.read()
                    db.cursor().executescript(sql)
                    return db
        except IOError:
                return db


    def write_db(self):

        sql = ''
        for item in self.db.iterdump():
            sql = sql + item + '\n'
        if self.dbpassphrase is not None:
            crypt_sql = self.gpg.encrypt(sql, recipients=None,
                                         symmetric='AES256',
                                         armor=False,
                                         always_trust=True,
                                         passphrase=self.dbpassphrase)
            with open(self.dbname, 'wb') as f:
                f.write(crypt_sql.data)
        else:
            with open(self.dbname, 'w') as f:
                f.write(sql)

    def print_state(self):

        print('\nWarning: saving this data to disk is insecure!\n')

        for key in sorted(self.state):
            if 'priv' in key:
                pass
            else:
                if self.state[key] is None:
                    print(key + ': None')
                elif type(self.state[key]) is bool:
                    if self.state[key]:
                        print(key + ': True')
                    else:
                        print(key + ': False')
                elif type(self.state[key]) is str:
                    try:
                        self.state[key].decode('ascii')
                        print(key + ': ' + self.state[key])
                    except UnicodeDecodeError:
                        print(key + ': ' + b2a_base64(
                            self.state[key]).strip())
                else:
                    print(key + ': ' + str(self.state[key]))
        if self.mode:
            print('Mode: Alice')
        else:
            print('Mode: Bob')

    @staticmethod
    def genKey():
        key = keys.Private()
        privkey = key.private
        pubkey = key.get_public().serialize()
        return privkey, pubkey

    @staticmethod
    def gen_dh(a, B):
        key = keys.Private(secret=a)
        return key.get_shared_key(keys.Public(B))

    def dec(self, key, encrypted):
        key = hexlify(key)
        msg = self.gpg.decrypt(GPG_HEADER + encrypted,
                               passphrase=key, always_trust=True)
        return msg.data

    def enc(self, key, plaintext):
        key = hexlify(key)
        msg = self.gpg.encrypt(plaintext, recipients=None,
                               symmetric=GPG_CIPHER,
                               armor=False,
                               always_trust=True, passphrase=key)
        return msg.data[6:]
