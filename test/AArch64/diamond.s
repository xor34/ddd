// Both arms of a diamond write x0, so the join block needs a phi for it.
//
// RUN: %lift --arch=aarch64 --sla=AARCH64 %s --passes=print-ssa | FileCheck %s

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

// The conditional branch splits into a taken edge (marked *) and a
// fall-through; both arms reconverge on block 3.
// CHECK: block 0 (entry) preds: - succs: 2* 1
// CHECK: x0#0 = COPY 0x5
// CHECK: CBRANCH

// CHECK: block 1 preds: 0 succs: 3
// CHECK: x0#1 = COPY
// CHECK: BRANCH

// CHECK: block 2 preds: 0 succs: 3
// CHECK: x0#2 = COPY

// CHECK: block 3 preds: 1 2
// CHECK: x0#3 = phi x0#1@1, x0#2@2
// CHECK: x1#0 = COPY x0#3
// CHECK: RETURN
