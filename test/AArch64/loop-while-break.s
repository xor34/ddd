// The exit is an `if` inside the body rather than the loop's own edge, so the
// way out is a `break` and the loop itself is `while (1)`.
//
// The condition is not hoisted into the `while (...)` clause, though a listing
// that only had to be pretty could put it there: the value tested is one the
// body computes, and naming it in a clause above its own definition would read
// it before it was written. `while (1)` with the test where it happens is the
// honest form -- and the only one that stays correct when the body changes.
//
// RUN: %lift --arch=aarch64 --sla=AARCH64 %s \
// RUN:   --passes=dce,idioms,rename,calling-conv,hil | FileCheck %s

  mov  x0, #0
Lloop:
  add  x0, x0, #1
  cmp  x0, #5
  b.eq Ldone
  b    Lloop
Ldone:
  ret

// CHECK: while (1) {
// CHECK: if (cond) break;
// CHECK: }
// CHECK: return
