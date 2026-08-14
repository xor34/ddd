-- The same function, one line per p-code op.
--
-- The folded listing is what you read; this is what you check it against. Every
-- comment and label the passes attached is on both, because they are two
-- renderings of one analysis rather than two analyses.
--
-- Only while it is the page being shown, though. It ends in a different
-- printer, which makes it a different listing under a different key, so
-- rendering it is a pipeline run of its own -- and doing that on every
-- navigation, for a tab nobody is looking at, is a wait per jump that nothing
-- on screen accounts for. It is the second-cheapest kind of slow there is:
-- invisible, and paid by whoever moves around the most.
local gtk = require "plugins.studio.gtk"
local ddd = require "ddd"

local Gtk = gtk.Gtk

local M = {}

function M.build(ui)
  local buffer = Gtk.TextBuffer()

  local comment = Gtk.TextTag { name = "comment",
                                foreground = ui.theme.token.comment }
  buffer.tag_table:add(comment)

  local view = Gtk.TextView {
    buffer = buffer,
    editable = false,
    cursor_visible = false,
    monospace = true,
    left_margin = 10,
    top_margin = 6,
    bottom_margin = 200,
  }
  view:add_css_class("ddd-listing")

  local widget = gtk.scrolled(view)
  local stale = true

  local function render()
    -- Not the visible page: remember that it is out of date and do the work
    -- when someone actually switches to it.
    if not widget:get_mapped() then
      stale = true
      return
    end
    stale = false

    -- Nothing is lifted while the references are being indexed, here either: a
    -- function analysed without them is analysed wrong, and the sweep throws it
    -- away when it finishes anyway. The invalidate at the end of the sweep
    -- brings this back.
    if ui.sweeping then
      buffer:set_text("indexing references", -1)
      stale = true
      return
    end

    local listing = ui:listing(nil, { printer = "print-ssa" })
    if not listing or not listing.ok then
      buffer:set_text(listing and listing.error or "nothing to show", -1)
      return
    end

    buffer:set_text(listing.text, -1)

    -- Everything to the right of a `;` was put there by a pass, and it reads
    -- as noise unless it is coloured as an aside.
    local offset = 0
    for line in listing.text:gmatch("([^\n]*)\n?") do
      local at = line:find(";", 1, true)
      if at then
        buffer:apply_tag(comment, buffer:get_iter_at_offset(offset + at - 1),
                         buffer:get_iter_at_offset(offset + (utf8.len(line) or #line)))
      end
      offset = offset + (utf8.len(line) or #line) + 1
    end
  end

  ui:on("navigate", render)
  ui:on("invalidate", render)

  -- Switching to the tab is what asks for it, and is also the only moment at
  -- which a wait here is one the user asked for.
  widget.on_map = function() if stale then render() end end

  return { widget = widget, render = render }
end

ddd.workflow "studio" {
  ui = function(scope)
    scope.view "ssa" {
      title = "SSA",
      place = "main",
      order = 20,
      build = function(ui) return M.build(ui).widget end,
    }
  end,
}

return M
