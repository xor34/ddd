// view.cpp -- what every renderer shares.
//
// Almost nothing, which is the point: the three renderers differ in what they
// state and agree only on how a note hangs under a line. Anything more shared
// than this would be one of them deciding something for the others.
#include "render/view.h"

#include <ostream>

namespace ddd {

void render_notes(std::ostream &os, const PassContext &ctx, const SsaOp &op,
                  const char *indent) {
  if (ctx.annotations == nullptr)
    return;

  const std::vector<std::string> &notes = ctx.annotations->comments(op);
  for (const std::string &note : notes)
    os << indent << "; " << note << "\n";
}

} // namespace ddd
