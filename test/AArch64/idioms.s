// The pattern engine recognises shapes in the SSA graph and attaches a
// sentence to the op. Matching follows COPY chains, which is what makes the
// flag-based comparison below reachable at all -- Sleigh routes it through
// four copies before the test.
//
// RUN: %lift --arch=aarch64 --sla=AARCH64 %s --passes=idioms,print-ssa | FileCheck %s

  eor  x0, x0, x0
  sub  x1, x1, x1
  and  x2, x2, x2
  lsl  x3, x3, #3
  cmp  x4, #1
  b.lt Lout
Lout:
  ret

// CHECK: 0x1000 eor x0, x0, x0
// CHECK: x0#1 = INT_XOR x0#in x0#in  ; always 0 -- idiomatic register zeroing

// CHECK: 0x1004 sub x1, x1, x1
// CHECK: INT_SUB x1#in x1#in  ; always 0

// CHECK: 0x1008 and x2, x2, x2
// CHECK: x2#1 = INT_AND x2#in x2#in  ; no-op (x & x)

// The shift amount is read out of the match and folded into the comment.
// CHECK: 0x100c lsl x3, x3, #0x3
// CHECK: INT_LEFT x3#in 0x3  ; x * 8

// b.lt is NG != OV over the flags the compare set. The rule sees through the
// copies between them.
// CHECK: INT_NOTEQUAL NG#0 OV#0  ; signed <  (NG != OV)
