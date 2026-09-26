// A cycle with no header: two blocks each reach the other, and neither
// dominates the other, so there is no back edge and no natural loop. The
// listing does not invent one. It prints labels and the `goto`s the blocks
// actually have, which is a worse read and a true one -- and the only thing it
// can do without claiming an entry the CFG does not have.
//
// This is the fallback every shape rule ends at, so it is the thing that makes
// the rest of them safe to attempt: the worst case is a listing full of gotos,
// never a wrong one.
//
// RUN: %lift --arch=aarch64 --sla=AARCH64 %s \
// RUN:   --passes=dce,idioms,rename,calling-conv,hil | FileCheck %s

  mov  x0, #1
  cmp  x0, #2
  b.eq L2
L1:
  add  x0, x0, #1
  cmp  x0, #5
  b.ne L2
  b    L3
L2:
  add  x0, x0, #2
  b    L1
L3:
  ret

// The taken edge leads out of the region the walk is in, and there is no join
// to continue at, so the branch is printed with its target rather than taken
// over by a shape. The label is where the walk gets there.
//
// Three gotos and two labels: the forward edge into L3 is printed where it is,
// the two blocks are swept at the top level afterwards because nothing falls
// into either of them, and a goto whose target has no label is the one thing a
// listing may not have.
// CHECK: if (cond#0) goto L3;
// CHECK: L1:
// CHECK: if (cond) goto L3;
// CHECK: L3:
// CHECK: goto L1;
