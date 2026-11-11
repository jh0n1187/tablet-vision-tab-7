"""Narrow local correction for v1.7.1 PAX timestamps; verified by round-trip test."""
from pathlib import Path
p=Path('lib/tar.c')
s=p.read_text()
assert s.count('#if ST_MTIM_NSEC')==2
s=s.replace('#if ST_MTIM_NSEC','#if defined(HAVE_STRUCT_STAT_ST_ATIM) || defined(HAVE_STRUCT_STAT_ST_ATIMENSEC)')
p.write_text(s)
