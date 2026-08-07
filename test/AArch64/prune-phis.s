// Cytron's placement puts a phi wherever a storage is defined on more than
// one path, which on AArch64 means a phi for every condition flag and every
// Sleigh temporary too. Only x0 is actually read after the join, so
// prune-phis should leave exactly one behind.
//
// RUN: %lift --arch=aarch64 --sla=AARCH64 %s --passes=print-ssa \
// RUN:   | FileCheck --check-prefix=BEFORE %s
// RUN: %lift --arch=aarch64 --sla=AARCH64 %s --passes=prune-phis,print-ssa \
// RUN:   | FileCheck --check-prefix=AFTER %s

  mov  x0, #5
  cmp  x0, #10
  b.lt Lless
  add  x0, x0, #1
  b    Ldone
Lless:
  add  x0, x0, #2
Ldone:
  mov  x1, x0
  ret

// BEFORE: block 3
// BEFORE-COUNT-7: = phi
// BEFORE-NOT: = phi

// AFTER: block 3
// AFTER: x0#3 = phi x0#1@1, x0#2@2
// AFTER-NOT: = phi
