from pudb import set_trace; set_trace(paused=False)

import mogglib
import getopt
import sys
import os

def usage():
   #print(f'usage: {sys.argv[0]} [-h] [-e] [-i <input>] [-o <output>] [-v]')
   print(f'usage: {os.path.relpath(sys.argv[0])} [-h] [-i <input>] [-o <output>] [-v <log>]')
   print("   -h / --help : print usage")
   #print("   -e / --encrypt: encrypt mogg")
   print("   -i <input> / --input=<input> : read mogg from <input>")
   print("   -o <output> / --output=<output> : write mogg to <output>")
   print("   -v <log> / --verbose=<log>: verbose output to <log>\n")
   print("Default with no arguments is to read from stdin and write to stdout.")
   print("Default action is to decrypt. Encryption coming in the future.")

def main():
   try:
      opts, args = getopt.getopt(sys.argv[1:], "hei:o:v:", ["help", "encrypt", "input=", "output=", "verbose="])
   except getopt.GetoptError as err:
      print(err)
      usage()
      sys.exit(2)
   launched = os.path.relpath(sys.argv[0])
   print(f'{launched} v0.1\n')
   no_opts = True
   encrypt = False
   verbose = False
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
         if a:
            logfile = a
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
   if logfile:
      flog = open(logfile, 'w')

   mogglib.decrypt_mogg(fin, fout, flog)
   
   print("Finished.")

if __name__ == "__main__":
   main()