-- The toolkit, and the few things every view wants from it.
--
-- lgi is a GObject-introspection binding, so this is not a wrapper around a
-- window written in C: the widgets, the layout, the signals and the main loop
-- are all Lua. Nothing in the C++ side of this tool knows a window exists.
local M = {}

-- lgi ships compatibility overrides for Gtk and Gdk that were written for
-- version 3: the Gdk one takes over a threading lock that GTK 4 removed, and
-- loading it against Gdk 4 fails outright. Presetting package.loaded is how you
-- tell require they are already dealt with, and everything they used to add is
-- either gone from GTK 4 or in lgi's core rather than the override.
package.loaded["lgi.override.Gdk"] = package.loaded["lgi.override.Gdk"] or {}
package.loaded["lgi.override.Gtk"] = package.loaded["lgi.override.Gtk"] or {}

local ok, lgi = pcall(require, "lgi")
if not ok then
  error("the studio interface needs lgi (dnf install lua-lgi, or "
        .. "luarocks install lgi)\n" .. tostring(lgi), 0)
end

M.lgi = lgi
M.Gtk = lgi.require("Gtk", "4.0")
M.Gdk = lgi.require("Gdk", "4.0")
M.Gio = lgi.Gio
M.GLib = lgi.GLib
M.Pango = lgi.Pango

-- And because the override is what used to call it: without this, building the
-- first widget walks uninitialised GTK state and takes the process with it.
M.Gtk.init()

local Gtk, Gdk = M.Gtk, M.Gdk

-- ---- styling -------------------------------------------------------------

function M.style(css)
  local provider = Gtk.CssProvider()

  -- load_from_string arrived in 4.12 and is the only one of the two that does
  -- not want a length; both exist on the way through.
  if provider.load_from_string then
    provider:load_from_string(css)
  else
    provider:load_from_data(css, #css)
  end

  Gtk.StyleContext.add_provider_for_display(Gdk.Display.get_default(), provider,
                                            600)
  return provider
end

-- ---- layout --------------------------------------------------------------

function M.box(orientation, spacing)
  return Gtk.Box {
    orientation = orientation or Gtk.Orientation.VERTICAL,
    spacing = spacing or 0,
  }
end

function M.scrolled(child, options)
  options = options or {}
  local window = Gtk.ScrolledWindow {
    hexpand = options.hexpand ~= false,
    vexpand = options.vexpand ~= false,
  }
  window:set_child(child)
  if options.class then window:add_css_class(options.class) end
  return window
end

-- A titled panel. The bar is what tells you which of four things you are
-- looking at, so every panel has one and they all look the same.
function M.panel(title, child)
  local box = M.box(Gtk.Orientation.VERTICAL)
  box:add_css_class("ddd-panel")

  local label = Gtk.Label { label = title:upper(), xalign = 0 }
  label:add_css_class("ddd-title")
  box:append(label)

  child.vexpand = true
  box:append(child)
  return box
end

function M.label(text, classes)
  local label = Gtk.Label { label = text or "", xalign = 0 }
  for _, class in ipairs(classes or {}) do label:add_css_class(class) end
  return label
end

-- ---- lists ---------------------------------------------------------------

-- A list whose rows are plain text and whose data is kept beside it, because
-- lgi objects will not hold arbitrary Lua fields and a row index is a perfectly
-- good key.
local List = {}
List.__index = List

function M.list(on_activate)
  local self = setmetatable({ items = {} }, List)

  self.widget = Gtk.ListBox { selection_mode = Gtk.SelectionMode.SINGLE }
  self.widget:add_css_class("ddd-list")

  self.widget.on_row_activated = function(_, row)
    local item = self.items[row:get_index() + 1]
    if item and on_activate then on_activate(item) end
  end

  self.widget.on_row_selected = function(_, row)
    if not row or not self.on_select then return end
    local item = self.items[row:get_index() + 1]
    if item then self.on_select(item) end
  end

  return self
end

function List:clear()
  local row = self.widget:get_first_child()
  while row do
    local next_row = row:get_next_sibling()
    self.widget:remove(row)
    row = next_row
  end
  self.items = {}
end

-- `markup` keeps the two-tone rows -- an address in grey beside a name in the
-- foreground colour -- without a column view and the cell factories it needs.
function List:add(markup, item)
  local label = Gtk.Label { use_markup = true, label = markup, xalign = 0 }
  label:add_css_class("ddd-mono")
  label.margin_start = 8
  label.margin_end = 8
  label.margin_top = 2
  label.margin_bottom = 2

  self.widget:append(Gtk.ListBoxRow { child = label })
  self.items[#self.items + 1] = item
end

function List:select(index)
  local row = self.widget:get_row_at_index(index - 1)
  if row then self.widget:select_row(row) end
end

-- ---- asking for something ------------------------------------------------

-- One line of text, modally. GtkDialog is deprecated in this GTK and the
-- replacement does not take an entry, so this is a small window that behaves
-- like the dialog everyone means.
function M.prompt(parent, options, on_accept)
  local window = Gtk.Window {
    title = options.title or "",
    transient_for = parent,
    modal = true,
    resizable = false,
    default_width = 420,
  }
  window:add_css_class("ddd")

  local box = M.box(Gtk.Orientation.VERTICAL, 8)
  box.margin_top = 12
  box.margin_bottom = 12
  box.margin_start = 12
  box.margin_end = 12

  if options.subtitle then
    box:append(M.label(options.subtitle, { "ddd-muted" }))
  end

  local entry = Gtk.Entry { text = options.text or "", activates_default = true }
  entry:add_css_class("ddd-mono")
  box:append(entry)

  local buttons = M.box(Gtk.Orientation.HORIZONTAL, 8)
  buttons.halign = Gtk.Align.END

  local cancel = Gtk.Button { label = "Cancel" }
  local accept = Gtk.Button { label = options.accept or "OK" }
  accept:add_css_class("suggested-action")

  buttons:append(cancel)
  buttons:append(accept)
  box:append(buttons)

  window:set_child(box)

  local function finish(text)
    window:close()
    if text and on_accept then on_accept(text) end
  end

  cancel.on_clicked = function() finish(nil) end
  accept.on_clicked = function() finish(entry.text) end
  entry.on_activate = function() finish(entry.text) end

  local keys = Gtk.EventControllerKey()
  keys.on_key_pressed = function(_, keyval)
    if Gdk.keyval_name(keyval) == "Escape" then
      finish(nil)
      return true
    end
    return false
  end
  window:add_controller(keys)

  window:present()
  entry:grab_focus()
  return window
end

-- Several lines of text, modally. For anything with one item per line -- a
-- prototype's arguments, say -- where a single entry would mean counting
-- commas.
function M.edit_lines(parent, options, on_accept)
  local window = Gtk.Window {
    title = options.title or "",
    transient_for = parent,
    modal = true,
    default_width = 520,
    default_height = 320,
  }
  window:add_css_class("ddd")

  local box = M.box(Gtk.Orientation.VERTICAL, 8)
  box.margin_top = 12
  box.margin_bottom = 12
  box.margin_start = 12
  box.margin_end = 12

  if options.subtitle then
    box:append(M.label(options.subtitle, { "ddd-muted", "ddd-mono" }))
  end

  local buffer = Gtk.TextBuffer()
  buffer:set_text(options.text or "", -1)

  local view = Gtk.TextView {
    buffer = buffer,
    monospace = true,
    left_margin = 8,
    top_margin = 6,
  }
  view:add_css_class("ddd-listing")
  box:append(M.scrolled(view))

  local buttons = M.box(Gtk.Orientation.HORIZONTAL, 8)
  buttons.halign = Gtk.Align.END

  local cancel = Gtk.Button { label = "Cancel" }
  local accept = Gtk.Button { label = options.accept or "Apply" }
  accept:add_css_class("suggested-action")
  buttons:append(cancel)
  buttons:append(accept)
  box:append(buttons)

  window:set_child(box)

  local function finish(text)
    window:close()
    if text and on_accept then on_accept(text) end
  end

  cancel.on_clicked = function() finish(nil) end
  accept.on_clicked = function()
    finish(buffer:get_text(buffer:get_start_iter(), buffer:get_end_iter(), false))
  end

  local keys = Gtk.EventControllerKey()
  keys.on_key_pressed = function(_, keyval, _, state)
    local name = Gdk.keyval_name(keyval)
    if name == "Escape" then
      finish(nil)
      return true
    end
    -- Enter inserts a line; ctrl+Enter is done, because the whole point of
    -- this dialog is that the content has lines in it.
    local control = type(state) == "table" and state.CONTROL_MASK
      or (tonumber(state) or 0) & (tonumber(Gdk.ModifierType.CONTROL_MASK) or 0) ~= 0
    if control and (name == "Return" or name == "KP_Enter") then
      finish(buffer:get_text(buffer:get_start_iter(), buffer:get_end_iter(), false))
      return true
    end
    return false
  end
  window:add_controller(keys)

  window:present()
  view:grab_focus()
  return window
end

return M
