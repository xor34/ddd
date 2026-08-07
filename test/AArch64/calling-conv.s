// A CALL carries only its destination in p-code; the arguments are in
// registers no operand mentions. ReachingValues answers what was in each of
// them, and the convention says which registers to ask about.
//
// RUN: %lift --arch=aarch64 --sla=AARCH64 %s --passes=calling-conv,print-ssa \
// RUN:   | FileCheck %s
// RUN: %lift --arch=aarch64 --sla=AARCH64 %s --abi=aapcs64 --passes=calling-conv,print-ssa \
// RUN:   | FileCheck --check-prefix=ABI %s

  mov  x3, x0
  mov  x1, #7
  eor  x2, x2, x2
  bl   callee
  ret
callee:
  ret

// x0 is read but never written, so it is a parameter. The convention itself
// was picked by looking for its registers in the loaded spec.
// CHECK: block 0 (entry)
// CHECK: ; parameters (aapcs64): x0

// x0 is forwarded unchanged; x1, x2 and x3 were set up here.
// CHECK: CALL ram:0x1014:8  ; args: x0=x0#in, x1=x1#0, x2=x2#1, x3=x3#0
// CHECK-NEXT: ; returns in x0

// Naming the convention explicitly gives the same answer.
// ABI: CALL
// ABI-SAME: args: x0=x0#in, x1=x1#0, x2=x2#1, x3=x3#0
