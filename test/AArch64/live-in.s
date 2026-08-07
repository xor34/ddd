// A register read before anything writes it gets a synthesised live-in
// value: a parameter, or genuinely uninitialised storage. x30 is read by
// every `ret`, so it shows up too.
//
// RUN: %lift --arch=aarch64 --sla=AARCH64 %s --passes=print-ssa | FileCheck %s
// RUN: %lift --arch=aarch64 --sla=AARCH64 %s --passes=liveness | FileCheck --check-prefix=LIVE %s

  add  x0, x1, x2
  ret

// CHECK: block 0 (entry)

// Live in to the entry block means live on entry to the function.
// LIVE: block 0 live-in:
// LIVE-SAME: x1#in
// LIVE-SAME: x2#in
// LIVE-SAME: x30#in
