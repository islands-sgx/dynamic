SECTIONS
{
  .atfield_pretouch ALIGN(0x1000) :
  {
    KEEP(*(.atfield_pretouch))
  }
}
INSERT AFTER .bss;
