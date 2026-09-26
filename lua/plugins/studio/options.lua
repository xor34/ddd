-- What the analysis is being told about the image.
--
-- Everything else in this interface acts on one address: rename this, comment
-- that, this is a function. These are the decisions that apply to the whole
-- file -- where the code starts, what else is mapped alongside it, which
-- instruction set reads which stretch, how much machine to spend on it -- and
-- they were reachable only from the command line, which is the wrong place for
-- them: you find out that a blob starts at 0x8000 by looking at it, and by then
-- the tool is already open.
--
-- A list rather than a form. Each row says what the setting is now, so the menu
-- doubles as the answer to "what does it think this file is", and activating
-- one asks for the new value in the same box everything else in this interface
-- asks in.
local gtk = require "plugins.studio.gtk"
local ddd = require "ddd"

local Gtk = gtk.Gtk

local M = {}

-- Whatever a row opens belongs to the options window rather than to the main
-- one: this window is modal, and a dialog parented past it is a dialog nobody
-- can type into.
local function over(ui) return M.parent or ui.window end

local function ask(ui, options, accept) gtk.prompt(over(ui), options, accept) end

-- ---- the options ----------------------------------------------------------

local function entry_point(ui)
  local info = ui.info

  return {
    title = "Entry point",
    value = ddd.format.addr(info.entry or 0),
    detail = "where the analysis starts; a blob has none until you say",

    run = function(reopen)
      ask(ui, {
        title = "Entry point",
        subtitle = "an address, a symbol, or a name you gave one",
        text = ("0x%x"):format(info.entry or ui.info.base),
      }, function(text)
        local addr = tonumber(text) or ui.session.resolve(text)
        if not addr then
          ui:status("cannot resolve " .. text)
          return
        end

        ui.session.set_entry(addr)
        ui.info = ui.session.info()
        ui:status(("entry point is %s"):format(ddd.format.addr(addr)))

        -- It is a function start now, so the listing there is a different
        -- listing; everything else in the image reads as it did.
        ui:invalidate_at(addr)
        ui:navigate(addr)
      end)
    end,
  }
end

local function objects(ui)
  local mapped = ui.session.objects()

  local where = {}
  for _, object in ipairs(mapped) do
    where[#where + 1] = ("%s @ %s"):format(object.path:match("[^/]+$")
                                             or object.path,
                                           ddd.format.addr(object.at))
  end

  return {
    title = "Map another object",
    value = #mapped == 0 and "none" or table.concat(where, ", "),
    detail = "a second file in the same address space: a bootloader and an "
      .. "application, a firmware and the blob it calls",

    run = function(reopen)
      ask(ui, {
        title = "Map an object",
        subtitle = "PATH ADDRESS [SPEC] -- e.g. /tmp/app.bin 0x8000 ARM7_le",
        text = "",
      }, function(text)
        local path, at, spec = text:match("^%s*(%S+)%s+(%S+)%s*(%S*)")
        if not path or not tonumber(at) then
          ui:status("give a path and an address")
          return
        end

        if not ui.session.load_object(path, tonumber(at),
                                      spec ~= "" and spec or nil) then
          ui:status(("cannot map %s at %s -- unreadable, below the base of the "
                     .. "image, or no such spec"):format(path, at))
          return
        end

        ui.info = ui.session.info()
        ui:status(("mapped %s at %s"):format(path, at))

        -- New bytes are new everything: the image is a different image, and
        -- what was analysed was analysed against the old one.
        ui:invalidate()
      end)
    end,
  }
end

-- What the bytes are being read as, and what they look like.
--
-- An ELF names its own machine and there is nothing to decide; a blob names
-- nothing, and reading it as the wrong instruction set produces a listing that
-- is wrong everywhere without ever looking broken. Detection is trial
-- disassembly -- a Sleigh load per candidate -- so it is offered rather than
-- run on the way in, and what it thinks is shown with the confidence it
-- deserves.
local function instruction_set(ui)
  local found = ui.session.regions()
  local first = found[1] or {}
  local named = (first.spec or ""):match("[^/]+%.sla$") or first.name or "none"

  return {
    title = "Instruction set",
    value = named:gsub("%.sla$", ""),
    detail = ("%d installed; every code region is read with this one")
      :format(#ui.session.specs()),

    run = function(reopen)
      local guesses = ui.session.detect_specs(5)
      local scored = {}
      for _, guess in ipairs(guesses) do scored[guess.spec] = guess end

      gtk.picker(over(ui), {
        title = "Instruction set",
        width = 560,
        height = 460,
        placeholder = "A spec name",

        items = function(pattern)
          pattern = (pattern or ""):lower()
          local found_specs = {}

          -- What the bytes suggest first, then everything installed.
          for _, guess in ipairs(guesses) do
            if pattern == "" or guess.spec:lower():find(pattern, 1, true) then
              found_specs[#found_specs + 1] = { spec = guess.spec, guess = guess }
            end
          end
          for _, spec in ipairs(ui.session.specs()) do
            if not scored[spec]
               and (pattern == "" or spec:lower():find(pattern, 1, true)) then
              found_specs[#found_specs + 1] = { spec = spec }
            end
          end
          return found_specs
        end,

        row = function(item)
          if not item.guess then return ddd.format.escape(item.spec) end
          return ("%s  <span foreground='%s'>%d%% -- %s</span>")
            :format(ddd.format.escape(item.spec), ui.theme.colour.flow_taken,
                    math.floor(item.guess.confidence * 100),
                    ddd.format.escape(item.guess.detail or ""))
        end,

        on_activate = function(item)
          if not ui.session.retarget(0, item.spec, {}) then
            ui:status("cannot read this as " .. item.spec)
            return
          end

          ui.info = ui.session.info()
          ui.indexed = nil
          ui:status(("reading the image as %s"):format(item.spec))
          ui:invalidate()
          reopen()
        end,
      })
    end,
  }
end

-- The p-code context: what a spec needs to be told before it decodes the way
-- its name suggests.
--
-- A .sla has no default mode -- that lives in Ghidra's .ldefs, which this tool
-- does not read -- so x86-64.sla decodes 16-bit real mode until told
-- `longMode=1`, and an ARM spec decodes ARM until told `TMode=1`. The variables
-- are whatever the spec declared; it is asked rather than assumed.
local function context(ui)
  local found = ui.session.regions()
  local first = found[1] or {}
  local settings = first.context or {}
  local variables = first.context_variables or {}

  -- What each is set to now, so a row can show it.
  local value_of = {}
  for _, setting in ipairs(settings) do
    local name, value = setting:match("^(%S-)=(%S*)$")
    if name then value_of[name] = value end
  end

  local shown = {}
  for index, name in ipairs(variables) do
    if index > 6 then
      shown[#shown + 1] = ("(+%d more)"):format(#variables - 6)
      break
    end
    shown[#shown + 1] = name
  end

  local function apply(wanted, reopen)
    local spec = (first.spec or ""):match("([^/]+)%.sla$") or first.spec
    if not spec or not ui.session.retarget(0, spec, wanted) then
      ui:status("cannot read this that way")
      return
    end

    ui.info = ui.session.info()
    ui.indexed = nil
    ui:status(#wanted > 0
              and ("decoding with " .. table.concat(wanted, " "))
              or "decoding with the spec's defaults")
    ui:invalidate()
    if reopen then reopen() end
  end

  return {
    title = "Decoding mode",
    value = #settings > 0 and table.concat(settings, " ") or "spec defaults",
    detail = #variables > 0
      and ("p-code context: " .. table.concat(shown, " "))
      or "the spec declares no context variables",

    -- A list rather than a line of text, because a spec has more of these than
    -- anyone remembers: x86-64 declares forty-three, of which `longMode`,
    -- `addrsize` and `opsize` are the ones that decide whether the listing is
    -- 16-, 32- or 64-bit and the rest are decoding plumbing. Typing a name you
    -- half-remember is not the way to find that out; searching is.
    run = function(reopen)
      if #variables == 0 then
        ui:status("this spec has no context variables")
        reopen()
        return
      end

      gtk.picker(over(ui), {
        title = "Decoding mode",
        width = 560,
        height = 460,
        placeholder = "A context variable, or `clear`",

        items = function(pattern)
          pattern = (pattern or ""):lower()
          local matched = {}
          for _, name in ipairs(variables) do
            if pattern == "" or name:lower():find(pattern, 1, true) then
              matched[#matched + 1] = { name = name, value = value_of[name] }
            end
          end
          return matched
        end,

        row = function(item)
          if not item.value then return ddd.format.escape(item.name) end
          return ("%s <span foreground='%s'>= %s</span>")
            :format(ddd.format.escape(item.name), ui.theme.colour.accent,
                    ddd.format.escape(item.value))
        end,

        on_activate = function(item)
          ask(ui, {
            title = item.name,
            subtitle = "a number, or empty to leave it to the spec",
            text = item.value or "",
          }, function(text)
            local wanted = {}
            for _, setting in ipairs(settings) do
              if not setting:match("^" .. item.name .. "=") then
                wanted[#wanted + 1] = setting
              end
            end
            if text ~= "" then
              wanted[#wanted + 1] = ("%s=%s"):format(item.name, text)
            end

            apply(wanted, reopen)
          end)
        end,

        -- Typing `clear` and pressing enter puts the spec back the way it
        -- came, which is otherwise a lot of rows to visit.
        on_no_match = function(text, close)
          if text ~= "clear" then return end
          close()
          apply({}, reopen)
        end,
      })
    end,
  }
end

local function regions(ui)
  local found = ui.session.regions()

  local names = {}
  for _, region in ipairs(found) do
    names[#names + 1] = ("%s %s-%s"):format(region.name,
                                            ddd.format.addr(region.begin),
                                            ddd.format.addr(region["end"]))
  end

  return {
    title = "Instruction sets",
    value = #names == 0 and "none" or table.concat(names, ", "),
    detail = ("%d spec(s) installed; carve a flat image once and it is kept")
      :format(#ui.session.specs()),

    -- Its own prompt rather than the command's: that one is parented to the
    -- main window, and this one is modal over it.
    run = function(reopen)
      local addr = (ui.selection or {}).addr or ui.addr or ui.info.base

      ask(ui, {
        title = "Region and its instruction set",
        subtitle = "BEGIN END SPEC [ABI] -- e.g. 0x8000 0x9000 ARM7_le",
        text = ("0x%x  0x%x  "):format(addr, addr + 0x1000),
      }, function(text)
        local from, to, spec, abi =
          text:match("^%s*(%S+)%s+(%S+)%s+(%S+)%s*(%S*)")
        if not spec or not tonumber(from) or not tonumber(to) then
          ui:status("give a beginning, an end and a spec")
          reopen()
          return
        end

        if not ui.session.add_region(tonumber(from), tonumber(to), spec,
                                     abi ~= "" and abi or nil) then
          ui:status(("no spec called %s (%d installed)")
            :format(spec, #ui.session.specs()))
          reopen()
          return
        end

        ui:status(("%s-%s is %s"):format(from, to, spec))
        ui.indexed = nil
        ui:invalidate()
        reopen()
      end)
    end,
  }
end

local function threads(ui)
  local now = ui.session.threads()

  return {
    title = "Threads",
    value = now == 0 and "as many as the machine has" or tostring(now),
    detail = "how many the sweeps may use; 1 keeps everything on this one",

    run = function(reopen)
      ask(ui, {
        title = "Threads",
        subtitle = "0 decides from the size of the image",
        text = tostring(now),
      }, function(text)
        local count = tonumber(text)
        if not count then
          ui:status("give a number")
          return
        end

        ui:status(("%d thread(s)"):format(ui.session.threads(math.floor(count))))
      end)
    end,
  }
end

-- Which analyses run, and in what order.
--
-- The pipeline is the whole difference between a listing you can read and a
-- page of flag arithmetic, and it is the one setting that is genuinely a
-- matter of taste: some of these passes are guesses, and a guess you disagree
-- with is worse than no guess. Toggling one re-runs the listings and nothing
-- else -- the sweep and the functions are not affected by any of this.
local function analyses(ui)
  local pipeline = ui.pipeline or {}

  local running = {}
  for _, name in ipairs(pipeline) do running[name] = true end

  return {
    title = "Analyses",
    value = ("%d pass(es)"):format(#pipeline),
    detail = table.concat(pipeline, " "),

    run = function(reopen)
      local known = ddd.passes()

      gtk.picker(over(ui), {
        title = "Analyses",
        width = 620,
        height = 460,
        placeholder = "A pass to turn on or off",
        count = false,

        items = function(pattern)
          pattern = (pattern or ""):lower()
          local found = {}
          for _, pass in ipairs(known) do
            if pattern == "" or pass.name:lower():find(pattern, 1, true) then
              found[#found + 1] = pass
            end
          end
          return found
        end,

        row = function(pass)
          local on = running[pass.name]
          return ("<span foreground='%s'>%s</span>  %s\n"
                  .. "<span foreground='%s' size='small'>%s</span>")
            :format(on and ui.theme.colour.flow_taken or ui.theme.colour.muted,
                    on and "on " or "off",
                    ddd.format.escape(pass.name), ui.theme.colour.muted,
                    ddd.format.escape(pass.description or ""))
        end,

        -- Order matters -- everything that annotates has to run before whatever
        -- prints -- so turning one on puts it back where the default pipeline
        -- had it rather than at the end.
        on_activate = function(pass)
          local wanted = {}
          local turning_on = not running[pass.name]
          running[pass.name] = turning_on or nil

          for _, name in ipairs(require("ddd.workflow").pipeline() or {}) do
            if running[name] then wanted[#wanted + 1] = name end
          end
          for _, name in ipairs(pipeline) do
            local already = false
            for _, have in ipairs(wanted) do already = already or have == name end
            if running[name] and not already then wanted[#wanted + 1] = name end
          end

          ui.pipeline = wanted
          ui:status(("%s %s -- %d pass(es)")
            :format(turning_on and "added" or "removed", pass.name, #wanted))
          ui:invalidate()
          reopen()
        end,
      })
    end,
  }
end

local function reindex(ui)
  return {
    title = "Rebuild the reference index",
    value = "",
    detail = "sweeps the whole image again. Editing repairs the index where it "
      .. "changed, so this is for when something else did",

    run = function(reopen)
      ui.session.reanalyse()
      ui.indexed = nil -- so the sweep that follows counts as the first one
      ui:status("rebuilding the reference index...")
      ui:refresh()
      reopen()
    end,
  }
end

local function discover(ui)
  return {
    title = "Find functions now",
    value = ("%d found"):format(#ui.session.functions()),
    detail = "runs discovery to completion rather than in the background; the "
      .. "window waits",

    run = function(reopen)
      ui:status("finding functions...")
      local count = ui.session.discover_functions()
      ui:status(("%d function(s)"):format(count))
      ui:invalidate()
      reopen()
    end,
  }
end

function M.open(ui, how)
  how = how or {}

  local window
  local started = false

  -- Starting is a decision, not a side effect of the window going away.
  --
  -- Activating a row used to close the list, and closing the list used to mean
  -- "begin" -- so choosing an entry point started the sweep before the entry
  -- point had been typed in. The sweep now begins exactly once, when somebody
  -- says so.
  local function start()
    if started then return end
    started = true
    if how.on_start then how.on_start() end
  end

  local list = gtk.list(function(item)
    -- The row opens its own dialog and this one stays where it is: what
    -- follows is a question about the value, and answering it is not a reason
    -- to lose the list it came from.
    item.run(function() M.refresh(ui, list) end)
  end)

  M.refresh(ui, list)

  local heading = gtk.label(
    how.title or "What the analysis is being told about this image",
    { "ddd-mono" })
  heading.margin_start = 12
  heading.margin_end = 12
  heading.margin_top = 12
  heading.xalign = 0

  local body = gtk.box(Gtk.Orientation.VERTICAL, 8)
  body:append(heading)

  local scroller = gtk.scrolled(list.widget)
  scroller.vexpand = true
  body:append(scroller)

  -- The button, because a window that begins when you dismiss it is a window
  -- you cannot read twice.
  local buttons = gtk.box(Gtk.Orientation.HORIZONTAL, 8)
  buttons.margin_start = 12
  buttons.margin_end = 12
  buttons.margin_bottom = 12
  buttons.halign = Gtk.Align.END

  local note = gtk.label(how.note or "", { "ddd-mono", "ddd-muted" })
  note.hexpand = true
  note.xalign = 0
  buttons:append(note)

  local go = Gtk.Button { label = how.accept or "Start analysis" }
  go:add_css_class("suggested-action")
  go.on_clicked = function()
    start()
    window:close()
  end
  buttons:append(go)

  body:append(buttons)

  window = gtk.modal(ui.window, {
    title = "Analysis",
    width = 720,
    height = 520,
  })
  window:set_child(body)
  M.parent = window

  -- Escape, or the title bar: the analysis was going to run either way, and
  -- refusing to start it because the window was dismissed rather than
  -- confirmed would only leave a window that never analyses anything.
  window.on_close_request = function()
    M.parent = nil
    start()
    return false
  end

  window:present()
  go:grab_focus()

  return window
end

-- The rows, rebuilt: every one of them shows a setting, and a setting that has
-- just been changed has to say so.
function M.refresh(ui, list)
  local items = {
    instruction_set(ui), context(ui), entry_point(ui), objects(ui),
    regions(ui), analyses(ui), threads(ui), discover(ui), reindex(ui),
  }

  list:clear()
  for _, item in ipairs(items) do
    list:add(("%s   <span foreground='%s'>%s</span>\n"
              .. "<span foreground='%s' size='small'>%s</span>")
      :format(ddd.format.escape(item.title), ui.theme.colour.accent,
              ddd.format.escape(item.value or ""), ui.theme.colour.muted,
              ddd.format.escape(item.detail or "")), item)
  end
end

ddd.workflow "studio" {
  ui = function(scope)
    scope.command "analysis" {
      title = "Analysis options",
      key = "<control>a",
      run = function(ui) M.open(ui) end,
    }
  end,
}

return M
