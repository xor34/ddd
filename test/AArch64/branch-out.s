// A conditional branch that leaves the function. There is no join to continue
// at and no fallthrough worth taking over, so the branch stays a branch and the
// address it goes to is printed as itself.
//
// It is not `if (cond) call ...` and it is not a tail call with a condition on
// it: what the instruction does is leave, and the listing says where to. An
// address is not a block, so there is no label to use instead -- which is the
// one place the address column earns its keep on a line of its own.
//
// The region is bounded at 0xc so that the branch really does leave: the code
// the target points at is not swept, and so is not a block the walk could have
// gone to instead.
//
// RUN: %sleigh-poc --base=0 --bytes=600000b4200080d2c0035fd6 --region=0:0xc:AARCH64 \
// RUN:   --specs=%specs --passes=dce,idioms,rename,calling-conv,hil \
// RUN:   | FileCheck %s

// CHECK: cond = x0#in == 0x0;
// CHECK: if (cond) goto 0xc;
// CHECK: return 0x1;
