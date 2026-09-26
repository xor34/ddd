// A parameter's home.
//
//     str x0, [sp, #8]
//
// is not the program storing anything: the convention passed the first argument
// in x0 and the function is putting it where it will keep it. The slot is a
// real variable of the program -- it is the first parameter -- so it is named
// after the parameter rather than hidden the way a callee-save spill is, and
// every read of the slot afterwards reads `arg0`.
//
// What is stored is what decides this, not where it landed. AArch64 puts its
// frame above the entry stack pointer and x86-64 below it, so the offset alone
// would have called this slot `arg_28` on this architecture and `var_28` on the
// other -- which is the point: an offset is the answer only when nothing better
// is known.
//
// RUN: %lift --arch=aarch64 --sla=AARCH64 %s \
// RUN:   --passes=stack-vars,rename,print-ssa | FileCheck %s
// The same run, for the two cases below that must *not* be named.
// RUN: %lift --arch=aarch64 --sla=AARCH64 %s \
// RUN:   --passes=stack-vars,rename,print-ssa | FileCheck --check-prefix=UNNAMED %s

  sub  sp, sp, #0x30
  str  x0, [sp, #8]      // x0 is a live-in, stored once: the first parameter
  mov  x1, #7
  str  x1, [sp, #0x10]   // x1 was computed here: a local, however it is used
  str  x2, [sp, #0x18]   // x2 is a live-in, but this slot is written twice
  mov  x2, #9
  str  x2, [sp, #0x18]
  add  sp, sp, #0x30
  ret

// The frame says arg0 where it used to say var_28, and the other two keep
// their offsets. Sorted by offset, so arg0 comes first only because the
// convention puts the first argument highest in the frame.
// CHECK: ; frame: arg0[8] var_20[8] var_18[8]

// The prologue store is still a store: the value arrived in x0, and the line
// says so. What changed is the name of the slot it goes into -- which is the
// name every later read of the parameter now carries.
// CHECK: 0x1004 str x0, [sp, #0x8]
// CHECK: STORE ram &arg0#0 x0#in  ; store arg0 [sp-0x28]

//
// The two ways a slot holds a parameter only until it does not. Both are here
// so that the rule cannot quietly become "name any slot an argument register
// was stored to".
//

// Stored once, but the value was computed by this function: whatever x1 is, it
// did not arrive from the caller, and the slot is a local that holds seven.
// UNNAMED: 0x100c str x1, [sp, #0x10]
// UNNAMED: STORE ram &var_20#1 x1#0  ; store var_20 [sp-0x20]

// Stored from an argument register's live-in value, but written again below it.
// The slot starts out as the parameter and is then assigned to, so it is a
// local whose first value came from the caller: `arg2` would be true of the
// first store and a lie about the second.
// UNNAMED: 0x1010 str x2, [sp, #0x18]
// UNNAMED: STORE ram &var_18#2 x2#in  ; store var_18 [sp-0x18]
// UNNAMED: 0x1018 str x2, [sp, #0x18]
// UNNAMED: STORE ram &var_18#3 x2#1  ; store var_18 [sp-0x18]
// UNNAMED-NOT: arg2
