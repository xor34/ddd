// A binary is not only code. --max stops the sweep after the instructions, so
// everything past them is data, and a constant pointing into it gets resolved
// rather than printed as a bare number.
//
// RUN: %lift --arch=aarch64 --sla=AARCH64 --base=0x1000 %s --max=3 \
// RUN:   --passes=data-refs,print-ssa | FileCheck %s

  adr  x0, msg
  adr  x1, number
  ret
msg:
  .asciz "hello, world"
number:
  .quad 0xcafef00d

// CHECK: 0x1000 adr x0, 0x100c
// CHECK: x0#0 = COPY 0x100c  ; 0x100c -> "hello, world"

// Not a string, so it comes back as the word that is actually there.
// CHECK: 0x1004 adr x1, 0x1019
// CHECK: x1#0 = COPY 0x1019  ; 0x1019 -> 0xcafef00d (8 bytes)
