/* Gives Go's libfuzzer counter section its own pages, so sancov.go can remap
 * them onto AFL's shared memory without touching neighboring data. */
SECTIONS
{
  .go.fuzzcntrs ALIGN(4096) : { *(.go.fuzzcntrs) . = ALIGN(4096); }
}
INSERT AFTER .bss;
