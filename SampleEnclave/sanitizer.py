from elftools.elf.elffile import ELFFile
import sys,math

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
#import secrets,struct
import os, json, base64

whitelist = []

PHDR_ENTRY_LEN = 56
PF_W = 2

def set_segment_writable(fbytes, segment, phdr_offs):
  phdr_flag_offs = phdr_offs+(segment*PHDR_ENTRY_LEN)+4
  fbytes = fbytes[:phdr_flag_offs] + str(ord(fbytes[phdr_flag_offs]) | PF_W) + raw_so[phdr_flag_offs+1:]
  return fbytes
'''  
def sanitize_section(emanip, section, ranges):
  text_start = emanip.shdrs['entries'][section].sh_addr
  contents = emanip.shdrs['entries'][section].contents
  for ran in ranges:
    start = ran['start']-text_start
    end = ran['end']-text_start
    contents = contents[:start] + ('\0' * (end-start)) + contents[end:]
  emanip.shdrs['entries'][section].contents = contents  
'''
def sanitize_section(fbytes, section, ranges):
  sec_start = section.header['sh_addr']
  sec_offset = section.header['sh_offset']
  for ran in ranges:
    start = ran['start']-sec_start+sec_offset
    end = ran['end']-sec_start+sec_offset
    fbytes = fbytes[:start] + ('\0' * (end-start)) + fbytes[end:]
  return fbytes

def random_bytes(count):
  b = os.urandom(count)
  print 'generated %s'%b
  return b

def encrypt_bytes(fbytes, key, iv):
  backend = default_backend()
  cipher = Cipher( algorithms.AES(key), modes.GCM(iv), backend=backend )
  encryptor = cipher.encryptor()
  ct = encryptor.update(fbytes)+encryptor.finalize()
  tag = encryptor.tag
  return (ct, tag)

if __name__ == '__main__':
  encrypted = False
  if len(sys.argv) == 2 or len(sys.argv) == 3:
    fname = ''
    if len(sys.argv) == 3:
      fname = sys.argv[2]
      if sys.argv[1] == '-c':
        encrypted = True
    else:
      fname = sys.argv[1]
    with open('whitelist.json','r') as f:
      whitelist = json.load(f)
    with open(fname,'rb') as f:
      elf = ELFFile(f)
      phdr_offs = elf.header.e_phoff
      funcs = []
      userfuncs = []
      text = ''
      initstart = 0
      textstart = 0
      textend = 0
      textind = 0
      sec_ind = 0
      for sec in elf.iter_sections():
        if sec.name == '.symtab':
          for sym in sec.iter_symbols():
            if sym.entry['st_info']['type'] == 'STT_FUNC':
              funcs.append({'name':sym.name, 'start':sym.entry['st_value']}) 
        if sec.name == '.text':
          text = sec
          textstart = sec.header['sh_addr']
          textend = sec.header['sh_addr']+sec.header['sh_size']
          textind = sec_ind
        sec_ind += 1
      for func in funcs:
        mingt = float('inf')
        for func2 in funcs:
          if func2['start'] > func['start'] and func2['start'] < mingt:
            mingt = func2['start']
        if math.isinf(mingt):
            mingt = textend
        func['end'] = mingt
      for func in funcs:
        if not func['name'] in whitelist:
          userfuncs.append(func)
        if func['name'] == 'elide_restore':
          initstart = func['start']
      raw_so = b''
      with open(fname,'rb') as f:
        raw_so = f.read()
      seg_ind = 0
      for seg in elf.iter_segments():
        if seg.section_in_segment(text):
          raw_so = set_segment_writable(raw_so, seg_ind, phdr_offs)
        seg_ind += 1
      raw_so = sanitize_section(raw_so, text, userfuncs)
      secret_bytes = text.data()
      print 'Unencrypted length: %d'%len(secret_bytes)
      meta = {}
      meta['offset'] = initstart-text.header['sh_offset']
      if encrypted:
        key = random_bytes(16)
        print 'key: %s'%key
	print 'key (hex): 0x%s'%key.encode('hex')
        iv = random_bytes(12)
        print 'iv: %s'%iv
	print 'iv (hex): 0x%s'%iv.encode('hex')
        (ct, tag) = encrypt_bytes(secret_bytes, key, iv)
        print 'tag: %s'%tag
	print 'tag (hex): 0x%s'%tag.encode('hex')
        meta['key'] = key
        meta['iv'] = iv
        meta['tag'] = tag
        #meta['key'] = base64.b64encode(key)
        #meta['iv'] = base64.b64encode(iv)
        #meta['tag'] = base64.b64encode(tag)
        secret_bytes = ct
        print 'Encrypted length: %d'%len(secret_bytes)
      with open(fname[:-3] + '.secret.dat', 'wb') as f:
        f.write(secret_bytes)
      with open(fname[:-3] + '.secret.meta', 'wb') as f:
        #json.dump(meta,f)
        f.write('%d\n'%meta['offset'])
	f.write('%d\n'%len(text.data()) )
        if encrypted:
          f.write('1\n')
          f.write(meta['key'])
          f.write(meta['iv'])
          f.write(meta['tag'])
        else:
          f.write('0\n')
        #f.write(str(initstart-text.header['sh_offset']))
      with open(fname[:-3] + '.so', 'wb') as f:
        f.write(raw_so)
      #print funcs
      #print userfuncs
  else:
    print 'supply a filename'
    
