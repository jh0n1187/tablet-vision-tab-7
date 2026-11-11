ENTRY(_start)
SECTIONS {
  . = 0x60600000;
  .text : { KEEP(*(.entry)) *(.text*) }
  .rodata : { *(.rodata*) }
  .data : { *(.data*) }
  . = ALIGN(4);
  __bss_start = .;
  .bss (NOLOAD) : { *(.bss*) *(COMMON) }
  . = ALIGN(4);
  __bss_end = .;
  /DISCARD/ : { *(.ARM.exidx*) *(.ARM.extab*) *(.comment*) *(.note*) }
  ASSERT(__bss_end < 0x60610000, "Diagnostic exceeded its RAM envelope")
}
