// Stack slots are found by propagating "entry_sp + k" along def-use edges,
// then naming every load and store that lands on one. `rename` carries those
// names onto the values loaded out of them.
//
// RUN: %lift --arch=aarch64 --sla=AARCH64 %s --passes=stack-vars,rename,print-ssa \
// RUN:   | FileCheck %s

  sub  sp, sp, #0x20
  str  x0, [sp, #8]
  ldr  x1, [sp, #8]
  add  sp, sp, #0x20
  ret

// The frame layout is summarised on the entry block: one 8-byte local.
// CHECK: block 0 (entry)
// CHECK: ; frame: var_18[8]

// The stack pointer after the adjustment is named by its offset, not left as
// a bare register version.
// CHECK: 0x1000 sub sp, sp, #0x20
// CHECK: sp-0x20#1 = INT_SUB sp#in 0x20

// The computed address becomes &var_18, and the access says which slot it is.
// CHECK: 0x1004 str x0, [sp, #0x8]
// CHECK: &var_18#0 = INT_ADD sp-0x20#1 0x8
// CHECK: STORE ram &var_18#0 x0#in  ; store var_18 [sp-0x18]

// The loaded value inherits the slot's name from `rename`.
// CHECK: 0x1008 ldr x1, [sp, #0x8]
// CHECK: var_18#0 = LOAD ram &var_18#1  ; load var_18 [sp-0x18]
