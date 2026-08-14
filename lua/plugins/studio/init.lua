-- studio -- the windowed interface.
--
-- Registering it costs nothing: the toolkit, the views and the commands are
-- pulled in when someone actually opens a window, so `--list_passes` on a
-- machine with no GTK installed still works, and a broken toolkit is an error
-- about the interface rather than about the tool.
local ddd = require "ddd"

ddd.workflow "studio" {
  description = "the window: a listing, what is around it, and what refers to it",

  ui = function(scope)
    scope.interface "studio" {
      description = "a windowed interface, in the shape of Binary Ninja's",

      run = function(ui)
        require("plugins.studio.window").open(ui)
      end,
    }
  end,
}
