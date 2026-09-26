// A diamond whose join is one of its own arms: both edges end at the same
// block, so the taken edge goes straight to the join and there is nothing to
// reconverge. There is no `if/else` to print -- the two arms would be the block
// and the block -- so the branch stays a branch, the join is labelled, and the
// listing says where the edge goes. Honest, and the whole point of the fallback
// rule: a shape is used when the CFG has one, never when it nearly does.
//
// The goto reads as redundant here because the other arm's statements were
// folded into the phi and it prints nothing. That is the folding's doing, not
// the shape's: the edge is real, and the walk is not allowed to decide it is
// not there because the block at the far end happens to be empty.
//
// RUN: %lift --arch=aarch64 --sla=AARCH64 %s \
// RUN:   --passes=dce,idioms,rename,calling-conv,hil | FileCheck %s

  mov  x0, #1
  cmp  x0, #2
  b.eq Lend
  mov  x0, #3
Lend:
  ret

// CHECK: cond = 0x1 == 0x2;
// CHECK: if (cond) goto L2;
// CHECK: L2:
// CHECK: x0#2 = phi(0: 0x1, 1: 0x3);
// CHECK: return x0#2;
