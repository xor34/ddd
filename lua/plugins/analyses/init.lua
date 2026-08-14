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
require "plugins.analyses.signatures"

ddd.workflow "readability" {
  description = "turn lifted p-code into something a person can read",

  passes = function(scope)
    -- Order is the whole content of a pipeline. Everything that annotates has
    -- to run before whatever renders, and the naming passes have to run after
    -- the analyses whose guesses they overrule -- `user-names` last of those,
    -- because a person outranks all of them.
    scope.pipeline "default" {
      "stack-vars",
      "simplify",
      "dce",
      "idioms",
      "data-refs",
      "symbols",
      "rename",
      "name-vars",
      -- After name-vars, which invents the names these override, and before
      -- user-names, so a parameter renamed afterwards is renamed under the
      -- name the signature gave it.
      "signatures",
      "user-names",
      "types",
      "calling-conv",
      "hil",
    }
  end,
}
