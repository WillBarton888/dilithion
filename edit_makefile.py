#!/usr/bin/env python3
with open('/root/dilithion-windows/src/Makefile.am', 'r') as f:
    lines = f.readlines()

# Find and insert after siphash.h
new_lines = []
for line in lines:
    new_lines.append(line)
    if 'crypto/siphash.h' in line and line.strip().endswith('\'):
        new_lines.append('  crypto/randomx_hash.cpp \n')
        new_lines.append('  crypto/randomx_hash.h \n')

with open('/root/dilithion-windows/src/Makefile.am', 'w') as f:
    f.writelines(new_lines)

print('Added RandomX files to Makefile.am')
