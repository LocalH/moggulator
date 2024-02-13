from pudb import set_trace; set_trace(paused=False)

import mogglib
import getopt
import sys
import os

def usage():
    #print(f'usage: {sys.argv[0]} [-h] [-e] [-i <input>] [-o <output>] [-v]')
    print(f'usage: {os.path.relpath(sys.argv[0])} [-h] [-i <input>] [-o <output>] [-v]')
    print("   -h / --help : print usage")
    #print("   -e / --encrypt: encrypt mogg")
    print("   -i <input> / --input=<input> : read mogg from <input>")
    print("   -o <output> / --output=<output> : write mogg to <output>")
    print("   -v / --verbose: verbose output to stderr\n")
    print("   -p / --ps3: use ps3 key derivation\n")
    print("Default with no arguments is to read from stdin and write to stdout, deriving Xbox keys.")
    print("Default action is to decrypt. Encryption coming in the future.")

def main():
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hei:o:vp", ["help", "encrypt", "input=", "output=", "verbose", "ps3"])
    except getopt.GetoptError as err:
        print(err)
        usage()
        sys.exit(2)
    launched = os.path.relpath(sys.argv[0])
    print(f'{launched} v0.1\n')
    no_opts = True
    encrypt = False
    verbose = False
    xbox = True
    infile = ""
    outfile = ""
    logfile = ""
    flog = sys.stderr
    fin = sys.stdin
    fout = sys.stdout
    for o, a in opts:
        if o in ("-v", "--verbose"):
            no_opts = False
            verbose = True
        elif o in ("-h", "--help"):
            no_opts = False
            usage()
            sys.exit()
        #elif o in ("-e", "--encrypt"):
        #   encrypt = True
        elif o in ("-i", "--input"):
            no_opts = False
            if a:
                infile = a
            else:
                print("no input file given\n")
                usage()
                sys.exit(2)
        elif o in ("-o", "--output"):
            no_opts = False
            if a:
                outfile = a
            else:
                print("no output file given\n")
                usage()
                sys.exit(2)
        elif o in ("-p", "--ps3"):
            xbox = False
        else:
            assert False, "unhandled option"
   
    if no_opts == True:
        print("no arguments passed\n")
        usage()
        sys.exit(2)

    if infile:
        fin = open(infile, 'rb')
    if outfile:
        fout = open(outfile, 'wb')
   
    if verbose:
        if xbox:
            flog.write("deriving xbox keys\n")
        else:
            flog.write("deriving ps3 keys\n")

    ret = mogglib.decrypt_mogg(xbox, fin, fout, flog, verbose)

    if ret:
        print("decryption failed, removing output file")
        os.remove(outfile)

if __name__ == "__main__":
    main()