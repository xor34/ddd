// Phi placement is pruned: a phi goes in only where the storage is live.
//
// Cytron's rule -- a phi wherever a storage is defined on two paths -- puts
// one in for every condition flag and every Sleigh temporary, because those
// are written on both arms of every branch and read by neither. On this
// diamond that was seven phis for one real join.
//
// It is not just noise. A phi counts as a use of all its operands, so a phi
// nobody reads still holds the whole dead computation feeding it alive, and
// dead-code elimination cannot touch any of it.
//
// RUN: %lift --arch=aarch64 --sla=AARCH64 %s --passes=print-ssa | FileCheck %s
// RUN: %lift --arch=aarch64 --sla=AARCH64 %s --passes=prune-phis,print-ssa \
// RUN:   | FileCheck --check-prefix=PRUNED %s

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

// One phi, for the one value that is actually live across the join.
// CHECK: block 3
// CHECK: x0#3 = phi x0#1@1, x0#2@2
// CHECK-NOT: = phi

// Which leaves the prune-phis pass nothing to do here -- it now only catches
// phis that *become* dead after some other pass removes their last reader.
// PRUNED: removed 0 dead phi(s)
// PRUNED: x0#3 = phi x0#1@1, x0#2@2
// PRUNED-NOT: = phi
