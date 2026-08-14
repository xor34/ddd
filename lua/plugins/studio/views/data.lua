-- Data, as items rather than as a hex dump.
--
-- A hex dump is not exploration. The thing you want to know about a word of
-- data is what it *is*: an ARM literal pool is a run of words sitting inside
-- the code, each one an address or a constant that some nearby PC-relative load
-- reads, and reading it as sixteen bytes to a row tells you none of that. So
-- each item is decoded, resolved against the symbols and the strings, and
-- carries the references that point at it.
local gtk = require "plugins.studio.gtk"
local ddd = require "ddd"

local Gtk = gtk.Gtk

local M = {}

function M.build(ui)
  local where = Gtk.Entry { placeholder_text = "address or symbol" }
  where:add_css_class("ddd-mono")
  where.margin_top = 6
  where.margin_bottom = 6
  where.margin_start = 8
  where.margin_end = 8

  local list = gtk.list(function(item)
    -- Following the pointer is the point of the panel.
    ui:navigate(item.points and item.value or item.addr)
  end)

  -- So that `x` answers "what reads this word" about whatever is highlighted
  -- here, the same way it does in the listing.
  list.on_select = function(item)
    ui.selection = { addr = item.addr, target = item.addr }
  end

  local function fill(addr)
    list:clear()
    if not addr then return end

    local limit = ddd.ui.limits.rows
    local view = ui.session.data(addr, math.min(limit, 128))
    local theme = ui.theme.token

    for _, item in ipairs(view.items) do
      local text
      if item.kind == "string" then
        text = ("<span foreground='%s'>%08x</span>  <span foreground='%s'>\"%s\"</span>")
          :format(theme.address, item.addr, theme.string,
                  ddd.format.escape(item.text))
      else
        text = ("<span foreground='%s'>%08x</span>  <span foreground='%s'>%016x</span>")
          :format(theme.address, item.addr, theme.const, item.value)

        if item.points == "string" then
          text = text .. (" <span foreground='%s'>-&gt; \"%s\"</span>")
            :format(theme.string, ddd.format.escape(item.target or ""))
        elseif item.target and item.target ~= "" then
          text = text .. (" <span foreground='%s'>-&gt; %s</span>")
            :format(theme["function"], ddd.format.escape(item.target))
        elseif item.points and item.points ~= "" then
          text = text .. (" <span foreground='%s'>(%s)</span>")
            :format(theme.comment, item.points)
        end
      end

      if item.label and item.label ~= "" then
        text = text .. (" <span foreground='%s'>%s</span>")
          :format(theme.label, ddd.format.escape(item.label))
      end
      if #item.xrefs > 0 then
        text = text .. (" <span foreground='%s'>; %d xref%s</span>")
          :format(theme.xref, #item.xrefs, #item.xrefs == 1 and "" or "s")
      end

      list:add(text, item)
    end
  end

  where.on_activate = function()
    local addr = tonumber(where.text) or ui.session.resolve(where.text)
    if addr then
      fill(addr)
    else
      ui:status(("cannot resolve %s"):format(where.text))
    end
  end

  local box = gtk.box(Gtk.Orientation.VERTICAL)
  box:append(where)
  box:append(gtk.scrolled(list.widget))

  -- Somewhere to start: the end of the code is where the data usually begins.
  local info = ui.info
  fill(info.code_end ~= 0 and info.code_end or info.base)

  ui:on("data", function(_, addr)
    where.text = ddd.format.addr(addr)
    fill(addr)
  end)

  return { widget = box, fill = fill }
end

ddd.workflow "studio" {
  ui = function(scope)
    scope.view "data" {
      title = "Data",
      place = "main",
      order = 30,
      build = function(ui) return M.build(ui).widget end,
    }
  end,
}

return M
