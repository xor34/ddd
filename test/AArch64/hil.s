// The expression IL, folded out of the def-use chains.
//
// Two rules do the work, and both come straight from SSA: a value used once
// folds into the place that uses it, and a value used more than once stays a
// variable assigned once. On top sits a rewrite table matched against the
// def-use graph, which turns the flag dance back into the comparison it came
// from.
//
// RUN: %lift --arch=aarch64 --sla=AARCH64 %s --passes=print-ssa \
// RUN:   | FileCheck --check-prefix=PCODE %s
// RUN: %lift --arch=aarch64 --sla=AARCH64 %s \
// RUN:   --passes=dce,idioms,rename,calling-conv,hil | FileCheck %s

  mov  x0, #5
  cmp  x0, #10
  b.lt Lless
  add  x0, x0, #1
  b    Ldone
Lless:
  add  x0, x0, #2
Ldone:
  ret

// The comparison arrives as a flag computation spread over several ops, none
// of which says "less than".
// PCODE: INT_SBORROW
// PCODE: INT_SLESS
// PCODE: INT_NOTEQUAL

// The rewrite table matches that whole shape through the copies between the
// flags and the test, and prints what the source said. The address leads the
// line and the note is a comment on it, which is the shape every statement has.
// CHECK: 0x1008    cond = 0x5 <s 0xa;  ; signed <  (NG != OV)

// Control flow reads as control flow rather than a CBRANCH on a temporary, and
// as a diamond rather than as four blocks with a goto on every edge. `if` and
// `else` are what the CFG says; the join is where control falls to, so nothing
// is printed for it at all.
//
// The taken arm is printed first, which is why the addresses go out of order:
// the fall-through arm is what `else` means, and putting the two the other way
// round would mean negating the condition -- inventing a condition the
// instruction never computed to say something the graph already says.
// CHECK: if (cond) {
// CHECK: x0#2 = 0x5 + 0x2;
// CHECK: } else {
// CHECK: x0#1 = 0x5 + 0x1;
// CHECK: }

// Constants fold into every use, so the `mov x0, #5` does not survive as a
// variable holding a literal: what both arms add to is the literal itself, and
// the two additions are the only places it was used.

// A phi is still a phi -- its arguments come from other blocks and folding
// them would move work across control flow.
//
// Each argument says which predecessor it arrives from, because that is the
// entire content of a phi: without it the node is a list of names, and which
// branch produced which value is exactly what the reader came to find out.
// CHECK: x0#3 = phi(1: x0#1, 2: x0#2)
// CHECK: return

// Nothing in the folded form mentions a raw p-code opcode for these.
// CHECK-NOT: INT_ADD
// CHECK-NOT: INT_NOTEQUAL
