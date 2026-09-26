// server.h -- one command line in, one line of JSON out.
//
// The command vocabulary is the same one the interfaces use, so there is
// nothing to parse here and no JSON reader in this binary -- only a writer.
// What the web interface talks to.
#pragma once

#include <iosfwd>

namespace ddd {

class Session;

// Reads commands from `in` until it closes or `quit` arrives, answering each
// with exactly one line on `out`. Saves the project before returning.
int serve(Session &session, std::istream &in, std::ostream &out);

} // namespace ddd
