import mogglib
import getopt
import sys
import os

def test_ofuncs():
    olog = open("ofuncs.log", "w")
    for op in range (0, 64):
        for a2 in range (0, 256):
            for a1 in range (0, 256):
                olog.write(f'a1: {a1:02X} a2: {a2:02X} op: {op}')
                ret = mogglib.o_funcs(a1, a2, op)
                olog.write(f' ret: {ret & 0xff:02X}\n')
    return

def main():
    test_ofuncs()

if __name__ == "__main__":
    main()