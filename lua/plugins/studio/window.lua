-- The window itself.
--
-- A host rather than a layout: it asks the UI registry what views exist and
-- puts them where each one says it belongs. Everything on screen -- the
-- function list, the listing, the references, the data -- is a separate plugin
-- registered in a workflow's `ui` scope, and so is every command the keyboard
-- and the palette offer. Adding a panel is a file; it does not touch this one.
--
-- Nothing in here is loaded until an interface actually opens, so a machine
-- without a toolkit installed still has a working command line.
local gtk = require "plugins.studio.gtk"
local ddd = require "ddd"

local Gtk, Gdk = gtk.Gtk, gtk.Gdk

require "plugins.studio.commands"
require "plugins.studio.views.functions"
require "plugins.studio.views.listing"
require "plugins.studio.views.ssa"
require "plugins.studio.views.data"

-- ---- keys ----------------------------------------------------------------

local function modifier(state, name)
  if state == nil then return false end
  if type(state) == "table" then return state[name] == true end

  local mask = Gdk.ModifierType[name]
  mask = tonumber(mask) or 0
  return (state & mask) ~= 0
end

-- "<control>q", "<alt>Left", "semicolon", "g" -- the shape GTK writes
-- accelerators in, without pulling in the accelerator machinery, which wants
-- actions rather than a table of closures.
local function matches(accelerator, name, state)
  local wanted = {}
  local key = accelerator:gsub("<(%a+)>", function(found)
    wanted[found:lower()] = true
    return ""
  end)

  if (wanted.control or false) ~= modifier(state, "CONTROL_MASK") then return false end
  if (wanted.alt or false) ~= modifier(state, "ALT_MASK") then return false end
  return key:lower() == (name or ""):lower()
end

-- ---- the command palette -------------------------------------------------

local function palette(ui)
  local window = Gtk.Window {
    transient_for = ui.window,
    modal = true,
    decorated = false,
    default_width = 520,
    default_height = 380,
  }
  window:add_css_class("ddd")

  local search = Gtk.SearchEntry { placeholder_text = "Command" }
  search.margin_top = 8
  search.margin_bottom = 8
  search.margin_start = 8
  search.margin_end = 8

  local commands = ui:commands_available()
  local list

  local function run(item)
    window:close()
    ui:run(item.name)
  end

  list = gtk.list(run)

  local function fill(pattern)
    list:clear()
    pattern = (pattern or ""):lower()

    for _, command in ipairs(commands) do
      local title = command.title or command.name
      if pattern == "" or title:lower():find(pattern, 1, true)
         or command.name:lower():find(pattern, 1, true) then
        local shortcut = command.key and
          (" <span foreground='%s'>%s</span>"):format(ui.theme.colour.muted,
                                                      ddd.format.escape(command.key))
          or ""
        list:add(ddd.format.escape(title) .. shortcut, command)
      end
    end
    list:select(1)
  end

  search.on_search_changed = function() fill(search.text) end
  search.on_activate = function()
    local row = list.widget:get_selected_row()
    local item = row and list.items[row:get_index() + 1] or list.items[1]
    if item then run(item) end
  end

  local keys = Gtk.EventControllerKey()
  keys.on_key_pressed = function(_, keyval, _, state)
    local name = Gdk.keyval_name(keyval)
    if name == "Escape" then
      window:close()
      return true
    end
    -- Up and down belong to the list even while the entry has the focus, which
    -- is the whole ergonomics of a palette.
    if name == "Down" or name == "Up" then
      local row = list.widget:get_selected_row()
      local index = row and row:get_index() or -1
      local next_row = list.widget:get_row_at_index(index + (name == "Down" and 1 or -1))
      if next_row then list.widget:select_row(next_row) end
      return true
    end
    return false
  end
  window:add_controller(keys)

  local box = gtk.box(Gtk.Orientation.VERTICAL)
  box:append(search)
  box:append(gtk.scrolled(list.widget))
  window:set_child(box)

  fill()
  window:present()
  search:grab_focus()
end

-- ---- the window ----------------------------------------------------------

local function side(ui, place, width)
  local views = ddd.ui.views_at(place)
  if #views == 0 then return nil end

  local box = gtk.box(Gtk.Orientation.VERTICAL)
  box:add_css_class("ddd-sidebar")
  box.width_request = width

  for _, view in ipairs(views) do
    local widget = view.build(ui)
    if widget then box:append(gtk.panel(view.title or view.name, widget)) end
  end

  return box
end

local function build(ui, app)
  local window = Gtk.ApplicationWindow {
    application = app,
    title = "ddd",
    default_width = 1500,
    default_height = 920,
  }
  window:add_css_class("ddd")
  ui.window = window

  -- The main views become the pages of a stack, so a plugin that adds one gets
  -- a tab in the header for free.
  local stack = Gtk.Stack {
    transition_type = Gtk.StackTransitionType.NONE,
    hexpand = true,
    vexpand = true,
  }
  for _, view in ipairs(ddd.ui.views_at("main")) do
    local widget = view.build(ui)
    if widget then stack:add_titled(widget, view.name, view.title or view.name) end
  end

  local header = Gtk.HeaderBar { show_title_buttons = true }

  local back = Gtk.Button { icon_name = "go-previous-symbolic", tooltip_text = "Back" }
  local forward = Gtk.Button { icon_name = "go-next-symbolic", tooltip_text = "Forward" }
  back.on_clicked = function() ui:run("back") end
  forward.on_clicked = function() ui:run("forward") end
  header:pack_start(back)
  header:pack_start(forward)

  header:set_title_widget(Gtk.StackSwitcher { stack = stack })

  local commands = Gtk.Button {
    icon_name = "open-menu-symbolic",
    tooltip_text = "Commands (ctrl+p)",
  }
  commands.on_clicked = function() palette(ui) end
  header:pack_end(commands)

  window:set_titlebar(header)

  -- Left, main, right, each side only if something registered a view for it.
  local body = stack
  local right = side(ui, "right", 340)
  if right then
    local split = Gtk.Paned { orientation = Gtk.Orientation.HORIZONTAL }
    split:set_start_child(body)
    split:set_end_child(right)
    split.resize_end_child = false
    split.position = 1140
    body = split
  end

  local left = side(ui, "left", 300)
  if left then
    local split = Gtk.Paned { orientation = Gtk.Orientation.HORIZONTAL }
    split:set_start_child(left)
    split:set_end_child(body)
    split.resize_start_child = false
    split.position = 300
    body = split
  end

  -- Where you are, and whatever just happened.
  local place = gtk.label("", { "ddd-mono" })
  local message = gtk.label("", { "ddd-mono", "ddd-muted" })
  message.hexpand = true
  message.xalign = 1

  local status = gtk.box(Gtk.Orientation.HORIZONTAL, 12)
  status:add_css_class("ddd-status")
  status:append(place)
  status:append(message)

  local root = gtk.box(Gtk.Orientation.VERTICAL)
  body.vexpand = true
  root:append(body)
  root:append(status)
  window:set_child(root)

  ui:on("status", function(_, text) message.label = text or "" end)

  -- Where you are, at every scale at once: image, segment, function, block.
  -- The same path undefining walks up, which is what makes `u` predictable --
  -- you can see what it is about to act on.
  local function breadcrumb(addr)
    if not addr then return "" end

    local parts = {}
    for _, region in ipairs(ui.session.region_path(addr)) do
      parts[#parts + 1] = region.name ~= "" and region.name or region.kind
    end

    return ("%s   %s"):format(ddd.format.addr(addr),
                              table.concat(parts, " › "))
  end

  ui:on("navigate", function(_, addr) place.label = breadcrumb(addr) end)
  ui:on("invalidate", function() place.label = breadcrumb(ui.focus or ui.addr) end)
  ui:on("select", function(_, addr) place.label = breadcrumb(addr) end)
  ui:on("show", function(_, name) stack:set_visible_child_name(name) end)
  ui:on("quit", function() window:close() end)

  -- One controller for every command that named a key. A view that wants a key
  -- of its own registers a command for it rather than adding a controller,
  -- which is what keeps the palette and the keyboard in agreement.
  local keys = Gtk.EventControllerKey()
  keys.on_key_pressed = function(_, keyval, _, state)
    local name = Gdk.keyval_name(keyval)

    if matches("<control>p", name, state) then
      palette(ui)
      return true
    end

    for _, command in ipairs(ddd.ui.commands) do
      if command.key and matches(command.key, name, state) then
        ui:run(command.name)
        return true
      end
    end
    return false
  end
  window:add_controller(keys)

  return window
end

-- ---- opening it ----------------------------------------------------------

local M = {}

function M.open(ui)
  gtk.style(ui.theme.css())

  local app = Gtk.Application {
    application_id = "org.ddd.studio",
    -- Never hand off to an instance that is already open: two binaries are two
    -- sessions, and the second one arriving as a message to the first would
    -- show the wrong file.
    flags = gtk.Gio.ApplicationFlags.NON_UNIQUE,
  }

  app.on_activate = function()
    local window = build(ui, app)

    local info = ui.info
    local name = info.project ~= "" and info.project:gsub("%.ddd$", "") or "image"
    window.title = ("%s  --  %s"):format(name, info.describe or "")

    -- Building every view and rendering a listing into them is most of what
    -- can go wrong, and none of it needs a window on screen -- so there is a
    -- way to do exactly that and stop, which is what the test suite runs.
    if os.getenv("DDD_SMOKE") then
      ui:navigate(ui.addr or info.entry, { replace = true })
      io.write("studio: built\n")

      -- What the listing pane actually ended up holding, so a test can check
      -- the rendering without a screen to draw it on.
      local listing = ui.listing_view
      local mode = os.getenv("DDD_SMOKE")

      if listing and mode == "dump" then
        local buffer = listing.buffer
        io.write(buffer:get_text(buffer:get_start_iter(), buffer:get_end_iter(),
                                 false))
        io.write("\n")
      end

      if listing and mode == "click" then
        io.write(listing:probe(), "\n")
      end

      -- Running a command builds whatever dialog it opens, which is where the
      -- mistakes in one are, and then shows what the listing looks like where
      -- the user was -- which is how you tell "it did nothing" from "it did
      -- something somewhere off screen". `DDD_SMOKE=command:undefine`.
      local wanted = mode and mode:match("^command:(.+)$")
      if wanted then
        ui:run(wanted)
        io.write(("command %s: %s\n"):format(wanted, ui.status_text))

        if listing then
          local line = listing:line_for(ui.focus or ui.addr)
          io.write(("at 0x%x -> line %s\n"):format(ui.focus or ui.addr or 0,
                                                   tostring(line)))
          if line then
            local buffer = listing.buffer
            local from = buffer:get_iter_at_line(math.max(0, line - 2))
            local to = buffer:get_iter_at_line(line + 4)
            io.write(buffer:get_text(from, to or buffer:get_end_iter(), false))
            io.write("\n")
          end
        end
      end

      app:quit()
      return
    end

    window:present()

    ui:navigate(ui.addr or info.entry, { replace = true })
    ui:status("ctrl+p for commands")
  end

  app:run(nil)
end

return M
