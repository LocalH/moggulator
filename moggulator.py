import mogglib
import getopt
import sys
import os

def usage():
    print(f'usage: {os.path.relpath(sys.argv[0])} [-h] -i <input> -o <output> [-E --version=X] [-p] [-v]')
    print("   -h / --help : print usage")
#    print("   -e / --encrypt: encrypt mogg with arbitrary security values")
#    print("      --version=X : version of encryption to use")
#    print("      --nonce=00000000XXXXXXXXXXXXXXXXXXXXXXXX : nonce")
#    print("      --mask-ps3=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX : ps3 keymask in hex, v12+")
#    print("      --mask-360=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX : 360 keymask in hex, v12+")
#    print("      --index=X : key index (0-6), v12+")
#    print("      --magic-a=XXXXXXXX : magicA in hex, v12+")
#    print("      --magic-b=XXXXXXXX : magicB in hex, v12+")
    print("   -E / --encrypt-header : encrypt using security values stored in header from prior decryption")
    print("      --version=X : version of encryption to use")
    print("   -i <input> / --input=<input> : read mogg from <input>")
    print("   -o <output> / --output=<output> : write mogg to <output>")
    print("   -p / --ps3: use ps3 key to decrypt")
    print("   -r / --red: use red HvKeys")
    print("   -v / --verbose: verbose output to stderr\n")
    print("Default action is to decrypt with green Xbox keys.\n")
    print("Arbitrary encryption not available yet, coming soon\n")
    print("Encryption to v11 can be done to any mogg that was previously v11.")
    print("Encryption to v12-v13 can be done to any mogg that was previously v12-v13.")
    print("Encryption to v14-v16 can be done to any mogg that was previously v14-v16.")
    print("Encryption to v17 can currently only be done with moggs originally encrypted by v17, to the same subversion as originally encrypted.")
    
def main():
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hEi:o:vpr", ["help", "encrypt-header", "version=", "subversion=", "input=", "output=", "verbose", "ps3", "red"])
    except getopt.GetoptError as err:
        print(err)
        usage()
        sys.exit(2)
    launched = os.path.relpath(sys.argv[0])
    print(f'{launched} v1.5\n')
    no_opts = True
    encrypt = False
    enc_hdr = False
    verbose = False
    xbox = True
    red = False
    infile = ""
    outfile = ""
    #logfile = ""
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
        elif o in ("-E", "--encrypt-header"):
            enc_hdr = True
        elif o in ("--version"):
            no_opts = False
            if enc_hdr:
                if int(a) > 10:
                    enc_ver = int(a)
                elif int(a) < 11:
                    print("version must be greater than 10 to encrypt\n")
                    usage()
                    sys.exit(2)
                else:
                    print("version must be given for encryption\n")
                    usage()
                    sys.exit(2)
            else:
                print("must be encrypting to pass version argument\n")
                usage()
                sys.exit(2)
        elif o in ("--subversion"):
            no_opts = False
            if enc_hdr:
                if enc_ver == 17:
                    if a:
                        match int(a):
                            case 1 | 4 | 6 | 8 | 10:
                                enc_subver = int(a)
                            case _:
                                print("invalid subversion")
                                print("valid subversions: 1 (RB4), 4 (DropMix), 6 (Dance Central VR), 8 (Audica), 10 (FUSER)\n")
                                usage()
                                sys.exit(2)
                    else:
                        print("subversion (1, 4, 6, 8, 10) must be given for v17 encryption")
                        print("valid subversions: 1 (RB4), 4 (DropMix), 6 (Dance Central VR), 8 (Audica), 10 (FUSER)\n")
                        usage()
                        sys.exit(2)
                else:
                    print("subversion not used unless doing v17 encryption\n")
                    usage()
                    sys.exit(2)
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
   
    if not enc_hdr:
        if xbox:
            print("using xbox keys for decryption")
        else:
            print("using ps3 keys for decryption")


    if enc_hdr:
        ret = mogglib.reencrypt_mogg(xbox, red, enc_ver, fin, fout, flog, verbose)
    else:
        ret = mogglib.decrypt_mogg(xbox, red, fin, fout, flog, verbose)

    if not enc_hdr:
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
