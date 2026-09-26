// No way out at all: the body ends by going back and nothing branches past it.
// There is no exit to name, so there is no `break` and no condition to write --
// just the loop, which is exactly what the block does. Nothing after it is
// printed, because nothing after it runs.
//
// RUN: %lift --arch=aarch64 --sla=AARCH64 %s \
// RUN:   --passes=dce,idioms,rename,calling-conv,hil | FileCheck %s

  mov  x0, #0
Lloop:
  add  x0, x0, #1
  b    Lloop

// CHECK: while (1) {
// CHECK: }
// CHECK-NOT: return
