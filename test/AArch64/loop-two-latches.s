// Two ways back to the same header. One loop, not two: the back edges enclose
// the same block, and printing them as two loops would put one inside the other
// for no reason the CFG gives.
//
// Two latches also rule out the `do-while`. The first way round leaves before
// the bottom test, so the bottom test is not what goes round -- it is one of
// two decisions, and each of them is a `continue`. The loop's own edge is the
// last one, which is the `break`.
//
// RUN: %lift --arch=aarch64 --sla=AARCH64 %s \
// RUN:   --passes=dce,idioms,rename,calling-conv,hil | FileCheck %s

  mov  x0, #0
Lloop:
  add  x0, x0, #1
  cmp  x0, #2
  b.eq Lloop
  cmp  x0, #5
  b.ne Lloop
  ret

// CHECK: while (1) {
// CHECK: if (cond#0) continue;
// CHECK: if (cond) continue;
// CHECK: break;
// CHECK: }
