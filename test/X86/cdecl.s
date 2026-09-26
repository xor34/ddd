// The 32-bit x86 calling convention, which passes everything on the stack.
//
// A convention with no argument registers is not a convention nobody knows: on
// cdecl the arguments are above the return address the call pushed, and the
// caller's pushes are what a call is passing. Without that, a 32-bit binary got
// no parameters at its entry and no arguments at any of its calls.
//
// RUN: %lift --triple=i386 --sla=x86 %s --passes=stack-vars,dce,rename,name-vars,calling-conv,hil \
// RUN:   | FileCheck %s
//
// The caller, which pushes three arguments and calls.
// RUN: %lift --triple=i386 --sla=x86 %s --entry=0x1009 \
// RUN:   --passes=stack-vars,dce,rename,name-vars,calling-conv,hil \
// RUN:   | FileCheck --check-prefix=CALLER %s

callee:
  movl 4(%esp), %eax
  addl 8(%esp), %eax
  ret

caller:
  subl $12, %esp
  movl $7, 4(%esp)
  movl $5, (%esp)
  calll callee
  addl $12, %esp
  ret

// The two slots above the return address are the parameters, and the frame
// says so by name.
//
// The sum is the function's whole result, so it is written where the result
// goes rather than parked in EAX and named twice: the convention says EAX is
// where a cdecl function returns, which is the line saying `return`.
//
// CHECK: frame: retaddr[4] arg_4[4] arg_8[4]
// CHECK: parameters (cdecl-x86): the stack, from sp+0x4
// CHECK: return address: pushed by the call, at the entry sp
// CHECK: return arg_4 + arg_8

// And at a call, what was pushed for it -- in the order the callee reads them,
// with the call's own return-address push left out of the list.
//
// CALLER: parameters (cdecl-x86): the stack, from sp+0x4
// CALLER: call ram:0x1000
// CALLER-SAME: args: var_c=0x5, var_8=0x7
// CALLER-NEXT: returns in EAX
