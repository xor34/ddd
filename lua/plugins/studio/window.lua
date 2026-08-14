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
require "plugins.studio.views.map"

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
    if widget then
      -- A view can ask for no chrome. The map is a strip down the edge of the
      -- window rather than a panel with a heading; giving it one would make it
      -- look like something to read instead of something to steer with.
      box:append(view.bare and widget or gtk.panel(view.title or view.name, widget))
    end
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
  -- The right strip is narrow on purpose: it is a map of the file rather than
  -- a panel, and the listing is what the window is for.
  local kRight, kLeft = 22, 300

  local body = stack

  -- A box rather than a paned: the strip is 20 pixels of map, there is nothing
  -- to drag it to, and a paned given a position before it has been allocated
  -- clamps it -- which is how the strip ended up with no width at all.
  local right = side(ui, "right", kRight)
  if right then
    local row = gtk.box(Gtk.Orientation.HORIZONTAL)
    body.hexpand = true
    row:append(body)
    row:append(right)
    body = row
  end

  local left = side(ui, "left", kLeft)
  if left then
    local split = Gtk.Paned { orientation = Gtk.Orientation.HORIZONTAL }
    split:set_start_child(left)
    split:set_end_child(body)
    split.resize_start_child = false
    split.position = kLeft
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

-- Doing things to a window that is actually running.
--
-- The smoke modes build everything and stop, which catches a great deal but
-- not anything about the main loop -- and "I clicked and nothing happened" is
-- always about the main loop. This performs a sequence against a live window,
-- one step at a time, so it can be watched.
--
--   DDD_DRIVE="goto:0x400490;run:define-function;shot"
--
-- `shot` only marks the moment; the screenshot is taken from outside.
function M.drive(ui, script)
  if not script or script == "" then return end

  local steps = {}
  for step in script:gmatch("[^;]+") do steps[#steps + 1] = step end

  local at = 1
  gtk.GLib.timeout_add(gtk.GLib.PRIORITY_DEFAULT, 700, function()
    local step = steps[at]
    if not step then return false end
    at = at + 1

    local verb, argument = step:match("^([%a-]+):?(.*)$")

    if verb == "goto" then
      local addr = tonumber(argument)
      ui:navigate(addr)
      ui.focus = addr
      ui.selection = { addr = addr }
    elseif verb == "run" then
      ui:run(argument)
    elseif verb == "quit" then
      ui:quit()
      return false
    end

    io.write(("drive: %-28s %s\n"):format(step, ui.status_text or ""))
    io.flush()
    return true
  end)
end

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
      -- No main loop here, so the background stages never fire; the map's
      -- snapshot does the same work synchronously for the tests that need it.
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

        -- Jumping between functions, which is what following a reference does.
        local addresses = {}
        for _, func in ipairs(ui.session.functions()) do
          addresses[#addresses + 1] = func.addr
        end
        io.write(listing:probe_navigation(addresses), "\n")

        -- And going to an address typed in by hand, which lands wherever it
        -- lands: inside an instruction, in the middle of a data region, in a
        -- stretch nothing has been decided about.
        local info = ui.info
        local dense = {}
        for addr = info.base, info.limit - 1, 64 do
          dense[#dense + 1] = addr
        end
        io.write("dense ", listing:probe_navigation(dense), "\n")
      end

      -- Rendering every function there is. The listing is a lot of code over
      -- data produced by analysis, and one function with a shape nothing else
      -- has -- an unresolved branch, a block nothing reaches -- is enough to
      -- make it throw, which shows up as a listing that has quietly stopped
      -- agreeing with the rest of the window.
      if listing and mode == "render" then
        local failed, first = 0, nil

        for _, func in ipairs(ui.session.functions()) do
          local ok, problem = pcall(listing.show, listing, func.addr)
          if not ok then
            failed = failed + 1
            first = first or ("%s at 0x%x: %s"):format(func.name, func.addr,
                                                       tostring(problem))
          end
        end

        io.write(("render: %d failed of %d%s\n"):format(
          failed, #ui.session.functions(), first and ("  " .. first) or ""))
      end

      local to = mode and mode:match("^map:(.+)$")
      if to and ui.map_view then
        -- Before and after, because the difference between them is the thing
        -- the strip exists to show.
        ui.map_view:render_to((to:gsub("%.png$", "-before.png")), 34, 420)
        local blue, grey = ui.map_view:snapshot(to, 34, 420)
        io.write(("map: %d bucket(s) analysed of %d with functions -> %s\n")
          :format(blue, grey, to))
      end

      -- Running a command builds whatever dialog it opens, which is where the
      -- mistakes in one are, and then shows what the listing looks like where
      -- the user was -- which is how you tell "it did nothing" from "it did
      -- something somewhere off screen". `DDD_SMOKE=command:undefine`.
      local wanted = mode and mode:match("^command:(.+)$")
      if wanted then
        -- Somewhere in particular, since most of what a command does depends
        -- on where the cursor is.
        local at = tonumber(os.getenv("DDD_SMOKE_AT") or "")
        if at then
          ui:navigate(at)
          ui.focus = at
          ui.selection = { addr = at }
        end

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

      -- A view that raised while being told something is caught and logged, so
      -- that one bad handler does not stop the rest of the window from
      -- updating. That is right, and it is also how a view silently stops
      -- redrawing -- so the log is part of the report.
      for _, message in ipairs(ui.messages) do
        io.write("log: ", message, "\n")
      end

      app:quit()
      return
    end

    -- On screen first, and only then the work. Presenting only queues a
    -- frame, so everything that costs anything -- rendering the first listing,
    -- indexing every reference, finding the functions -- goes after the main
    -- loop has had its turn and actually drawn the window.
    window:present()

    gtk.GLib.idle_add(gtk.GLib.PRIORITY_DEFAULT_IDLE, function()
      ui:navigate(ui.addr or info.entry, { replace = true })
      ui:status("ctrl+p for commands")

      require("plugins.studio.analysis").start(ui)
      M.drive(ui, os.getenv("DDD_DRIVE"))
      return false
    end)
  end

  app:run(nil)
end

return M
