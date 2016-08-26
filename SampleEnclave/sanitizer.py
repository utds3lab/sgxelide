from elftools.elf.elffile import ELFFile
from elfmanip.ELFManip import ELFManip
from elfmanip.Constants import SHF_WRITE
import sys,math

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
#import secrets,struct
import os, json, base64

whitelist = [u'sgx_elide_restore', u'_ZL13is_stack_addrPvm', u'_ZL8_EGETKEYP14_key_request_tPh', u'_ZL8_EREPORTPK13_targe_info_tPK18_sgx_report_data_tP9_report_t', u'_ZL6_EEXITyyyyy', u'do_relocs', u'spin_acquire_lock', u'init_mparams', u'dispose_chunk', u'__stack_chk_fail_local', u'ippsAES_GCMReset', u'sgx_init_string_lib', u'do_ereport', u'ippsAES_CMACGetSize', u'ippsAES_CMACGetTag', u'AesGcmMulGcm_table2K', u'__intel_security_check_cookie', u'memmove', u'sgx_is_within_enclave', u'cmac', u'get_enclave_state', u'get_xfeature_state', u'atol', u'__errno', u'elf_get_init_array', u'isblank', u'wrpAesGcmDec_table2K', u'ippsAES_GCMGetSize', u'sgx_ocfree', u'get_base_key', u'consttime_memequal', u'memcpy', u'elide_restore', u'ExpandRijndaelKey', u'islower', u'enter_enclave', u'malloc', u'get_enclave_base', u'sgx_register_exception_handler', u'ippsAES_GCMGetTag', u'init_stack_guard', u'ippsAES_GCMEncrypt', u'ispunct', u'ippsAES_GCMProcessAAD', u'AesGcmPrecompute_table2K', u'internal_handle_exception', u'isspace', u'ippsAESInit', u'get_td_addr', u'lock_enclave', u'_Z21_elide_server_requestiPv', u'abort', u'get_heap_size', u'sgx_init_crypto_lib', u'__stack_chk_fail', u'isxdigit', u'strtol', u'derive_key', u'__tls_get_addr', u'do_rdrand', u'get_errno_addr', u'asm_oret', u'calloc', u'sgx_cmac128_update', u'memset_s', u'update_ocall_lastsp', u'sgx_rijndael128GCM_decrypt', u'ippsAES_GCMDecrypt', u'tstdc_access_version_dummy1', u'get_heap_base', u'_Z15_elide_get_metaP10elide_meta', u'sgx_cmac128_close', u'isupper', u'init_global_object', u'realloc', u'_Z29tcrypto_access_version_dummy1v', u'sgx_rijndael128GCM_encrypt', u'__cxa_atexit', u'Safe2Encrypt_RIJ128', u'sgx_spin_unlock', u'memcmp', u'__memcpy', u'isalpha', u'do_oret', u'_Z17_elide_parse_metaP10elide_metaPhm', u'save_and_clean_xfeature_regs', u'sbrk', u'__memset', u'_Z16_elide_get_bytesP10elide_metaPh', u'memset', u'do_egetkey', u'trts_handle_exception', u'do_ocall', u'isgraph', u'_Ux86_64_setcontext', u'isalnum', u'isprint', u'load_regs', u'sgx_unregister_exception_handler', u'sgx_ocalloc', u'ippsAES_GCMProcessIV', u'Safe2Decrypt_RIJ128', u'get_bp', u'restore_xfeature_regs', u'memalign', u'elf_tls_info', u'get_thread_data', u'ippsAES_CMACUpdate', u'sgx_rijndael128_cmac_msg', u'do_ecall', u'sgx_cmac128_init', u'ippsAES_GCMInit', u'mallinfo', u'do_init_enclave', u'td_mngr_restore_td', u'relocate_enclave', u'AesGcmAuth_table2K', u'ippsAES_CMACFinal', u'isdigit', u'__memcmp', u'sgx_ocall', u'sgx_spin_lock', u'__morestack', u'set_enclave_state', u'__errno_location', u'ippsAESGetSize', u'_SE3', u'_Z20_elide_decrypt_bytesPKhjPhPA16_S_S0_jS3_', u'ippsAES_CMACInit', u'iscntrl', u'ippsAES_GCMStart', u'sgx_read_rand', u'elide_read_file', u'strlen', u'sgx_is_outside_enclave', u'continue_execution', u'wrpAesGcmEnc_table2K', u'init_optimized_libs', u'init_enclave', u'free', u'sgx_cmac128_final', u'enclave_entry']

PHDR_ENTRY_LEN = 56
PF_W = 2

#def set_section_writable(emanip, section):
  #emanip.shdrs['entries'][section].sh_flags |= SHF_WRITE 

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
      #emanip = ELFManip(fname)
      #print emanip.dump_shdrs()
      #set_section_writable(emanip,textind)
      #print emanip.dump_shdrs()
      #emanip.write_new_elf(fname[:-3] + '-sanitized.so')
  else:
    print 'supply a filename'
    
