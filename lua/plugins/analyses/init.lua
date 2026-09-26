-- The readability workflow.
--
-- What makes a listing readable is a sequence of small opinions about what a
-- shape in the IR means -- this constant is a string, this xor is a zeroing,
-- this name was chosen by a person and outranks the one we invented. None of
-- them are engines and none of them need to be compiled: they are exactly the
-- part of a decompiler that is worth changing while looking at a binary.
--
-- So they are declared here, in the workflow's `passes` scope. Each one lands
-- in the same registry as the passes written in C++, and --passes cannot tell
-- which is which.
local ddd = require "ddd"

require "plugins.analyses.idioms"
require "plugins.analyses.symbols"
require "plugins.analyses.user_names"
require "plugins.analyses.data_refs"
require "plugins.analyses.rename"
require "plugins.analyses.calling_conv"
require "plugins.analyses.machine_flags"
require "plugins.analyses.signatures"

ddd.workflow "readability" {
  description = "turn lifted p-code into something a person can read",

  passes = function(scope)
    -- Order is the whole content of a pipeline. Everything that annotates has
    -- to run before whatever renders, and the naming passes have to run after
    -- the analyses whose guesses they overrule -- `user-names` last of those,
    -- because a person outranks all of them.
    scope.pipeline "default" {
      -- First of all: the prototype a person wrote, if they wrote one. It is
      -- the only naming here that is not a guess, and every guess below is
      -- worse for having been made before it -- the slot a parameter is
      -- spilled to, in particular, is named from the value that arrived,
      -- which is the one this pass has just named.
      "signatures",
      "stack-vars",
      "simplify",
      -- One machine read is one LOAD: before dce, so that the ops left reading
      -- a duplicate of a read are the ones dce then finds dead.
      "mem-reads",
      -- Folding a computation into a constant leaves its definition dead, so
      -- this also has to precede dce. Before data-refs, which wants an address
      -- that has already been computed out of its parts.
      "const-prop",
      -- After const-prop, because the constant an identity turns on is often
      -- itself computed: `shl eax, 0` lowers the shift amount as `0 & 0x1f`,
      -- and until that is folded to a constant there is no identity to see.
      -- Before dce, which collects the operands this strands.
      "identities",
      "dce",
      "idioms",
      "machine-flags",
      "data-refs",
      "symbols",
      "rename",
      "name-vars",
      -- Last, because a person outranks every other name here -- and it
      -- renames under the name `signatures` gave a parameter, that being the
      -- name the person reads in the listing and would type again.
      "user-names",
      "types",
      "calling-conv",
      "hil",
    }
  end,
}
