// What the high-level listing does *not* show, and why.
//
// The information is all still in the IR -- print-ssa shows every bit of it.
// These are presentation decisions, and each one is reversible with
// --show_machine_state.
//
// RUN: %lift --arch=aarch64 --sla=AARCH64 %s | FileCheck %s
// RUN: %lift --arch=aarch64 --sla=AARCH64 %s --show_machine_state \
// RUN:   | FileCheck --check-prefix=MACHINE %s

  sub  sp, sp, #0x20
  str  x0, [sp, #8]
  ldr  x1, [sp, #8]
  add  x1, x1, #1
  str  x1, [sp, #8]
  add  sp, sp, #0x20
  ret

// A block is labelled by address as well as index, because an address is what
// everything else in the world refers to it by.
// CHECK: block 0 @ 0x1000 (entry):
// CHECK: ; frame: var_18[8]

// A store through a frame slot is written as the slot itself.
// CHECK: var_18 = arg0

// Read back out of the slot, incremented, stored again.
// CHECK: var_18 = var_18 + 0x1
// CHECK: return

// None of the following appear anywhere in that listing.
//
// The line computing `&var_18`: an address-of that is only ever dereferenced
// is not a variable of the program.
// CHECK-NOT: &var_18
// Keeping the stack pointer up to date, whether in the register or in the
// temporaries Sleigh routes the update through.
// CHECK-NOT: sp-0x20 =
// CHECK-NOT: sp =
// A negative displacement written as a huge unsigned constant.
// CHECK-NOT: 0xfffffff


// --show_machine_state puts the bookkeeping back, which is what you want when
// the stack analysis itself is what you are checking.
// MACHINE: sp-0x20 = sp - 0x20
// MACHINE: &var_18 = sp-0x20 + 0x8
