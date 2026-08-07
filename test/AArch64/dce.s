// Sleigh models an instruction completely, so every flag an `add` writes is
// in the IR whether or not the program reads it. SSA makes removing them a
// local decision: a value with no uses is read nowhere, because SSA already
// resolved every "which definition does this read see" question.
//
// RUN: %lift --arch=aarch64 --sla=AARCH64 %s --passes=print-ssa \
// RUN:   | FileCheck --check-prefix=BEFORE %s
// RUN: %lift --arch=aarch64 --sla=AARCH64 %s --passes=dce,print-ssa | FileCheck %s

  add  x0, x0, #1
  ret

// The flag writes are all there, and nothing reads any of them.
// BEFORE-DAG: tmpCY#0 = INT_CARRY
// BEFORE-DAG: tmpOV#0 = INT_SCARRY
// BEFORE-DAG: tmpNG#0 = INT_SLESS
// BEFORE-DAG: tmpZR#0 = INT_EQUAL

// CHECK: removed 4 dead op(s)

// The arithmetic survives: x0 is this convention's result register, so the
// last write to it is observable by the caller even though nothing in the
// function reads it.
// CHECK: 0x1000 add x0, x0, #0x1
// CHECK: INT_ADD x0#in
// CHECK: x0#1 = COPY

// The flags do not.
// CHECK-NOT: INT_CARRY
// CHECK-NOT: INT_SCARRY
// CHECK-NOT: INT_SLESS
// CHECK-NOT: INT_EQUAL

// CHECK: RETURN


// Without a calling convention there is nothing to call observable, and the
// pass says so rather than deleting the function's output.
// The abi complaint is an error and goes to stderr, hence the redirect.
// RUN: %lift --arch=aarch64 --sla=AARCH64 %s --abi=nonesuch --passes=dce 2>&1 \
// RUN:   | FileCheck --check-prefix=NOABI %s

// NOABI: unknown abi: nonesuch
// NOABI: no calling convention: nothing is treated as live at exit
// Everything goes, including the function's own result -- which is exactly
// why the roots come from the ABI.
// NOABI: removed 7 dead op(s)
