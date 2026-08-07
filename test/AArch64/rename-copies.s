// A COPY produces the same variable under a new SSA name, so a use of the
// result is really a use of the source. Following that is the one naming rule
// that needs no other pass to have invented a name first -- it falls out of
// the SSA graph.
//
// Without it, `rename` could only relay labels stack-vars had already set, so
// a function with no stack slots got nothing from it at all.
//
// RUN: %lift --arch=aarch64 --sla=AARCH64 %s --passes=rename,print-ssa | FileCheck %s
// RUN: %lift --arch=aarch64 --sla=AARCH64 %s --passes=print-ssa \
// RUN:   | FileCheck --check-prefix=RAW %s

  mov  x0, x1
  add  x0, x0, #1
  mov  x2, x0
  ret

// CHECK: followed 3 copy/copies

// The definition still prints under its own name, so the copy stays visible
// -- otherwise this would read as `x1#in = COPY x1#in`.
// CHECK: 0x1000 mov x0, x1
// CHECK: x0#0 = COPY x1#in

// The use, though, resolves: this is x1 plus one, and says so.
// CHECK: 0x1004 add x0, x0, #0x1
// CHECK: INT_ADD x1#in

// A second copy chains onto the first. Note the operand stays x0#1 and does
// not resolve further: x0#1 came from a Sleigh temporary, and a rule below
// refuses to trade a register name for one of those.
// CHECK: 0x1008 mov x2, x0
// CHECK: x2#0 = COPY x0#1

// The link register reaches the RETURN through a copy into pc, and resolves.
// CHECK: RETURN x30#in

// Without the pass, the same use names an intermediate you have to go and
// look up.
// RAW: 0x1004 add x0, x0, #0x1
// RAW: INT_ADD x0#0
