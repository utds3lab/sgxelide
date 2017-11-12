SECTIONS
{
    .encrypted :
    {
/*        _encrypted_section_offset = .;*/
/*        _encrypted_section_start = .;*/
/*         . = ALIGN(4096);*/
 	_encrypted_section_start = .;
        *(.encrypted)
        *(.encrypted.*)
        . = ALIGN(16);
        _encrypted_section_end = .;
/*        . = ALIGN(4096);*/
    }
}
