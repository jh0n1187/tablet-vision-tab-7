ENTRY(_start)
SECTIONS {
  . = 0x20000;
  .entry : { KEEP(*(.entry)) }
  .text : { *(.text*) *(.rodata*) }
  .data : { *(.data*) }
  .bss (NOLOAD) : { *(.bss*) *(COMMON) }
  __end = .;
  /DISCARD/ : { *(.comment*) *(.ARM.exidx*) *(.ARM.extab*) *(.note*) }
}
ASSERT(_start == 0x20000, "entry is not the load address")
ASSERT(__end <= 0x28000, "payload exceeds code window")
ASSERT(SIZEOF(.bss) == 0, "no uninitialized global state allowed")
