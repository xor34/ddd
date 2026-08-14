-- The same function, one line per p-code op.
--
-- The folded listing is what you read; this is what you check it against. Every
-- comment and label the passes attached is on both, because they are two
-- renderings of one analysis rather than two analyses.
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

  local function render()
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
  render()

  return { widget = gtk.scrolled(view), render = render }
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
