-- Jump to a function, from a box over the middle of the window.
--
-- The function list down the side is for reading; this is for going somewhere
-- you can already name. Type part of a name, press enter, be there -- which in
-- a binary with three thousand functions is the difference between navigating
-- and hunting.
local gtk = require "plugins.studio.gtk"
local ddd = require "ddd"

local M = {}

function M.open(ui)
  local window = gtk.picker(ui.window, {
    decorated = false,
    width = 620,
    height = 420,
    placeholder = "Function name or address",
    noun = "function",
    limit = ddd.ui.limits.rows,

    items = function(pattern) return ui.session.functions(pattern or "") end,

    row = function(func)
      return ("<span foreground='%s'>%08x</span>  %s")
        :format(ui.theme.token.address, func.addr, ddd.format.escape(func.name))
    end,

    on_activate = function(item) ui:navigate(item.addr) end,

    -- An address typed in goes there, whether or not it is a function: this is
    -- also the quickest way to reach one.
    on_no_match = function(text, close)
      local addr = tonumber(text) or (text ~= "" and ui.session.resolve(text))
      if addr then
        close()
        ui:navigate(addr)
      end
    end,
  })

  return window
end

return M
