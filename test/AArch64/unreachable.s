// Code the sweep walks over but nothing branches to has no predecessors, so
// it never enters the dominator tree. Its ops must still survive the lift --
// unrenamed, with raw operands -- rather than crash the renamer or vanish.
//
// RUN: %lift --arch=aarch64 --sla=AARCH64 %s --passes=print-ssa | FileCheck %s

  b    Lend
  add  x0, x0, #1
Lend:
  ret

// CHECK: block 0 (entry) preds: - succs: 2
// CHECK: BRANCH

// CHECK: block 1 (unreachable) preds: - succs: 2
// CHECK: INT_ADD x0
// CHECK-NOT: #

// CHECK: block 2 preds: 0 1
// CHECK: RETURN
