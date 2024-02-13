from pudb import set_trace; set_trace(paused=False)

from Crypto.Cipher import AES
import getopt
import sys
import os

def decrypt_mogg(fin, fout, flog):
    mogg_data = fin.read()
    print("This would decrypt the input file, if it were finished.")
    flog.write("This would be the debug log, if it were finished.")
    decmogg_data = mogg_data
    fout.write(decmogg_data)
    fout.close()
