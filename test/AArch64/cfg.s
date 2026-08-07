// The raw p-code CFG, before any lifting: block boundaries, terminator
// flags, and edges.
//
// RUN: %lift --arch=aarch64 --sla=AARCH64 %s --cfg --passes= | FileCheck %s

  cmp  x0, #0
  b.eq Lzero
  bl   Lcall
Lzero:
  ret
Lcall:
  ret

// Block 0 ends at the conditional branch. The taken edge goes to the b.eq
// target, the other falls through.
// CHECK: block 0 [0x1000, 0x1008) entry branch
// CHECK: CBRANCH
// CHECK: -> 2 (taken), 1

// The bl is a call: it gets a fall-through edge on the assumption the callee
// returns, and no edge to the callee.
// CHECK: block 1 [0x1008, 0x100c) call
// CHECK: CALL
// CHECK: -> 2

// CHECK: block 2 [0x100c, 0x1010) return
// CHECK: RETURN
// CHECK: -> (none)
