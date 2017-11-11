from elftools.elf.elffile import ELFFile
import sys
import json

if __name__ == '__main__':
  if len(sys.argv) == 2:
    fname = sys.argv[1]
    with open(fname,'rb') as f:
      elf = ELFFile(f)
      funcs = []
      for sec in elf.iter_sections():
        if sec.name == '.symtab':
          for sym in sec.iter_symbols():
            if sym.entry['st_info']['type'] == 'STT_FUNC':
              funcs.append(sym.name) 
      with open('whitelist.json','w') as outf:
        json.dump(funcs,outf)
  else:
    print 'supply a filename'
    
