// Machine state is not a computation.
//
// Sleigh models `sti` as a write to the interrupt flag and `cld` as a write to
// the direction flag, and nothing in the function reads either -- so the rules
// that are right about the arithmetic flags used to delete the one instruction
// the line was there for, and `sti` decompiled to nothing at all.
//
// RUN: %lift --triple=i386 --sla=x86 %s --passes=dce,machine-flags,name-vars,hil \
// RUN:   | FileCheck %s

  sti
  cld
  std
  cli
  ret

// Every write survives, not merely the last: two of them are two events, and
// which came first is the point.
//
// CHECK: IF = 0x1
// CHECK-SAME: sti -- interrupts enabled
// CHECK: DF = 0x0
// CHECK-SAME: cld -- string operations count up
// CHECK: DF = 0x1
// CHECK-SAME: std -- string operations count down
// CHECK: IF = 0x0
// CHECK-SAME: cli -- interrupts disabled
// CHECK: return
