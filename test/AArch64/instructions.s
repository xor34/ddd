// Every lifted op is shown under the machine instruction it came from, so a
// listing can be read against the disassembly.
//
// RUN: %lift --arch=aarch64 --sla=AARCH64 %s --passes=print-ssa | FileCheck %s

  mov  x0, #5
  add  x0, x0, #1
  ret

// The header carries the address and the disassembly text; its ops are
// indented under it.
// CHECK: 0x1000 mov x0, #0x5
// CHECK-NEXT: x0#0 = COPY 0x5

// One instruction, several p-code ops, all grouped under it.
// CHECK: 0x1004 add x0, x0, #0x1
// CHECK-NEXT: unique
// CHECK: x0#1 = COPY

// CHECK: 0x1008 ret
// CHECK: RETURN
