// A back edge makes the loop header a join point, so the loop-carried
// registers get phis there -- one operand from the preheader, one from the
// latch.
//
// RUN: %lift --arch=aarch64 --sla=AARCH64 %s --passes=prune-phis,print-ssa | FileCheck %s

  mov  x0, #0
  mov  x1, #10
Lloop:
  add  x0, x0, #1
  subs x1, x1, #1
  b.ne Lloop
  ret

// CHECK: block 0 (entry) preds: - succs: 1
// CHECK: x0#0 = COPY 0x0
// CHECK: x1#0 = COPY 0xa

// The header is its own predecessor, and each phi takes the entry value from
// block 0 and the latch value from block 1.
// CHECK: block 1 preds: 0 1 succs: 1* 2
// CHECK-DAG: x0#1 = phi x0#0@0, x0#2@1
// CHECK-DAG: x1#1 = phi x1#0@0, x1#2@1

// CHECK: block 2 preds: 1
// CHECK: RETURN
