// A test at the bottom of the body, with one way round: the body runs, then
// decides. That is a `do-while`, and the clause it ends with says both what
// goes round and what stops -- so the `continue` and the exit branch the CFG
// actually has are not printed at all. Two statements became one, which is the
// entire reason to prefer this shape: it is what the source said.
//
// One latch is what allows it. A second way back would run the body without
// reaching the bottom test, which is what `continue` means and not what that
// clause means (see loop-two-latches.s).
//
// The phi at the header is not part of the shape -- it is what the listing
// looks like before loop-carried values are lowered out of SSA -- so it is not
// pinned here.
//
// RUN: %lift --arch=aarch64 --sla=AARCH64 %s \
// RUN:   --passes=dce,idioms,rename,calling-conv,hil | FileCheck %s

  mov  x0, #0
  mov  x1, #10
Lloop:
  add  x0, x0, #1
  subs x1, x1, #1
  b.ne Lloop
  ret

// CHECK: do {
// CHECK: } while (cond);
// CHECK: return
