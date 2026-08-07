// Constants reach the analysis through raw (untracked) operands and are
// folded along def-use edges. The two arms disagree at the join, so the phi
// drops to bottom and nothing downstream of it is constant.
//
// RUN: %lift --arch=aarch64 --sla=AARCH64 %s --passes=const-prop | FileCheck %s

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

// CHECK: x0#0 = 0x5

// cmp is lowered as a subtract: 5 - 10 wraps to -5 in 64 bits, which is
// negative and non-zero.
// CHECK-DAG: tmpNG#0 = 0x1
// CHECK-DAG: tmpZR#0 = 0x0

// 5 + 1 on one arm, 5 + 2 on the other.
// CHECK-DAG: x0#1 = 0x6
// CHECK-DAG: x0#2 = 0x7

// The phi merging 6 and 7 is not a constant, so neither is the x1 that
// copies it.
// CHECK-NOT: x0#3 =
// CHECK-NOT: x1#0 =
