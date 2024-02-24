import mogglib
import getopt
import sys
import os

def usage():
    print(f'usage: {os.path.relpath(sys.argv[0])} [-h] -i <input> -o <output> [-p] [-v]')
    print("   -h / --help : print usage")
    #print("   -e / --encrypt: encrypt mogg")
    print("   -i <input> / --input=<input> : read mogg from <input>")
    print("   -o <output> / --output=<output> : write mogg to <output>")
    print("   -p / --ps3: use ps3 key to decrypt")
    print("   -r / --red: use red HvKeys")
    print("   -v / --verbose: verbose output to stderr\n")
    print("Default action is to decrypt with green Xbox keys. Encryption coming in the future.")

def main():
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hei:o:vpr", ["help", "encrypt", "input=", "output=", "verbose", "ps3", "red"])
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
    red = False
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
        elif o in ("-r", "--red"):
            red = True
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
   
    if xbox:
        print("using xbox keys for decryption")
    else:
        print("using ps3 keys for decryption")

    ret = mogglib.crypt_mogg(xbox, red, fin, fout, flog, verbose)

    fin.seek(0)
    ver = int.from_bytes(fin.read(4), "little")

    if ver != 10:
        if ret:
            if not red:
                print("decryption with green keys failed, trying red keys")
                fin.seek(0)
                fout = open(outfile, 'wb')
                ret_r = mogglib.crypt_mogg(xbox, True, fin, fout, flog, verbose)
                if ret_r:
                    print("decryption with red keys failed, removing output file")
                    os.remove(outfile)
                else:
                    print("Please notify LocalH of this red key mogg and send a copy of the song package.")
    else:
        print("decryption failed, removing output file")
        os.remove(outfile)

if __name__ == "__main__":
    main()