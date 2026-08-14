-- What a person can ask for.
--
-- Commands are registered rather than wired into the window, so the palette,
-- the keyboard and anything else that wants to offer them all read one list --
-- and a later plugin can add to it without touching the window at all.
--
-- Half of these exist because inference is wrong sometimes. A sweep decides
-- what is code, references decide where the functions are, and a convention
-- decides what a call is passing; all three are guesses, and a person who has
-- read the bytes outranks every one of them. Undefining, marking data, carving
-- a region and writing a prototype are how they say so.
local gtk = require "plugins.studio.gtk"
local ddd = require "ddd"

local function prompt(ui, options, accept)
  gtk.prompt(ui.window, options, accept)
end

-- The function the selection is in, which in a linear listing is not
-- necessarily the one that was last navigated to.
local function selected_function(ui)
  local selection = ui.selection or {}
  return selection.func or ui.func
end

local function selected_address(ui)
  local selection = ui.selection or {}
  return selection.addr or ui.focus or ui.addr
end

ddd.workflow "studio" {
  ui = function(scope)
    -- The one IDA has on ctrl+L and everyone else has on ctrl+P: a box over the
    -- middle of the window, type a name, be there.
    scope.command "functions" {
      title = "Jump to a function",
      key = "<control>l",
      run = function(ui) require("plugins.studio.finder").open(ui) end,
    }

    scope.command "find" {
      title = "Jump to a function (search)",
      key = "<control>f",
      run = function(ui) require("plugins.studio.finder").open(ui) end,
    }

    -- Escape goes back, which is what it does in IDA and what everyone tries
    -- first after following a call.
    scope.command "escape" {
      title = "Back (escape)",
      key = "Escape",
      run = function(ui)
        if not ui:back() then ui:status("nowhere to go back to") end
      end,
    }

    scope.command "goto" {
      title = "Go to address or symbol",
      key = "g",
      run = function(ui)
        prompt(ui, {
          title = "Go to",
          subtitle = "an address, a symbol, or a name you gave one",
        }, function(text)
          if ui:navigate_to(text) then ui:status(ddd.format.addr(ui.addr)) end
        end)
      end,
    }

    scope.command "rename" {
      title = "Rename what is selected",
      key = "n",
      run = function(ui)
        local func = selected_function(ui)
        if not func then
          ui:status("nothing to rename here")
          return
        end

        local selection = ui.selection or {}

        -- A variable if one is selected, the function otherwise. That is what
        -- pressing n means in every other tool of this shape.
        if selection.id then
          prompt(ui, {
            title = "Rename variable",
            subtitle = ("in %s"):format(func.name),
            text = selection.id,
          }, function(text)
            if text == "" or text == selection.id then return end
            ui.session.rename_variable(func.addr, selection.id, text)
            ui:status(("%s is now %s"):format(selection.id, text))
            ui:invalidate()
          end)
        else
          prompt(ui, { title = "Rename function", text = func.name },
            function(text)
              if text == "" or text == func.name then return end
              ui.session.rename_function(func.addr, text)
              ui:status(("%s is now %s"):format(func.name, text))
              ui:invalidate()
            end)
        end
      end,
    }

    scope.command "comment" {
      title = "Comment this address",
      key = "semicolon",
      run = function(ui)
        local addr = selected_address(ui)
        if not addr then return end

        prompt(ui, {
          title = "Comment",
          subtitle = ddd.format.addr(addr),
          text = ui.session.comment(addr) or "",
        }, function(text)
          ui.session.set_comment(addr, text)
          ui:invalidate()
        end)
      end,
    }

    scope.command "type" {
      title = "Declare the type of what is selected",
      key = "y",
      run = function(ui)
        local func = selected_function(ui)
        local selection = ui.selection or {}
        if not func or not selection.id then
          ui:status("select a variable first")
          return
        end

        prompt(ui, {
          title = "Type of " .. selection.id,
          subtitle = "a C type, as you would write it",
          text = "",
        }, function(text)
          if text == "" then return end
          ui.session.set_type(func.addr, selection.id, text)
          ui:invalidate()
        end)
      end,
    }

    -- A prototype, the way Binary Ninja takes one -- but edited a line at a
    -- time, because what you actually want to change is one argument's type,
    -- or its name, or where it arrives. Squeezing that into a single line of
    -- text means counting commas to find the one you meant.
    --
    --   int compute            <- what it returns, and what it is called
    --   int limit @ RDI        <- one argument per line: type name @ place
    --   char *name @ RSI
    --
    -- `@ place` is what makes the whole thing applicable rather than
    -- decorative: it says where the argument arrives, so the analysis can put
    -- that name on that value everywhere it is used.
    scope.command "signature" {
      title = "Edit the function signature",
      key = "s",
      run = function(ui)
        local func = selected_function(ui)
        if not func then
          ui:status("no function here")
          return
        end

        local signature =
          ddd.parse_signature(ui.session.signature(func.addr) or "")

        -- Seeded from the convention when there is nothing yet, so the common
        -- case is correcting lines rather than writing them.
        if not signature then
          signature = { result = "void", name = func.name, parameters = {} }
          for index, register in ipairs(ui.info.abi_arguments or {}) do
            if index > 3 then break end
            signature.parameters[index] =
              { type = "void *", name = "arg" .. index, at = register }
          end
        end

        gtk.edit_lines(ui.window, {
          title = "Signature of " .. func.name,
          subtitle = "result and name, then one argument per line",
          text = ddd.signature_lines(signature),
          accept = "Apply",
        }, function(text)
          local written = ddd.signature_from_lines(text)
          ui.session.set_signature(func.addr, written)
          ui:status(written == "" and "signature cleared" or written)
          ui:invalidate()
        end)
      end,
    }

    scope.command "xrefs" {
      title = "What refers to what is selected",
      key = "x",
      run = function(ui)
        local selection = ui.selection or {}

        -- A variable answers the same question about a value: every place it
        -- appears. Anything else answers it about a place.
        require("plugins.studio.references").open(ui, {
          id = selection.id,
          addr = selection.target or selected_address(ui)
                 or (ui.func and ui.func.addr),
        })
      end,
    }

    -- ---- correcting what was inferred ------------------------------------

    -- Undefining walks up. Everything in the image is a region inside another
    -- region -- a block inside a function inside a segment -- so "this is not
    -- a thing" needs to say which thing, and pressing it again in the same
    -- place is how you say "no, the one that was in". No level counting is
    -- needed for that: removing the innermost exposes its parent, so the next
    -- press acts on that.
    scope.command "undefine" {
      title = "This is not a region (again to go up a level)",
      key = "u",
      run = function(ui)
        local addr = selected_address(ui)
        if not addr then return end

        local kind = ui.session.undefine_at(addr)
        if not kind then
          ui:status("nothing left to undefine here")
          return
        end

        ui:status(("undefined the %s at %s -- u again for what it was in")
          :format(kind, ddd.format.addr(addr)))
        ui:invalidate()
      end,
    }

    -- The other direction. `c` puts bytes back in play for the disassembler,
    -- `a` says a stretch is a string and stops it reading them as
    -- instructions.
    -- Code is blocks. Saying "this is code" says where a block starts, and
    -- disassembling from there says where it ends; it does not say anybody
    -- calls it, which is what a function would claim.
    scope.command "define-code" {
      title = "This is code",
      key = "c",
      run = function(ui)
        local addr = selected_address(ui)
        if not addr then return end

        local ends = ui.session.define_code(addr)
        if not ends then
          ui:status(("nothing decodes at %s"):format(ddd.format.addr(addr)))
          return
        end

        ui:status(("code %s-%s"):format(ddd.format.addr(addr),
                                        ddd.format.addr(ends)))
        ui:invalidate()
      end,
    }

    -- The stronger claim, and the one that makes a listing out of it.
    scope.command "define-function" {
      title = "This is a function",
      key = "p",
      run = function(ui)
        local addr = selected_address(ui)
        if not addr then return end

        local ends = ui.session.define_function_at(addr)
        if not ends then
          ui:status(("nothing decodes at %s"):format(ddd.format.addr(addr)))
          return
        end

        local func = ui.session.function_at(addr)
        ui:status(("%s  %s-%s"):format(func and func.name or "function",
                                       ddd.format.addr(addr),
                                       ddd.format.addr(ends)))
        ui:invalidate()
      end,
    }

    scope.command "define-string" {
      title = "This is a null-terminated string",
      key = "a",
      run = function(ui)
        local addr = selected_address(ui)
        if not addr then return end

        local size = ui.session.define_string(addr)
        if not size then
          ui:status(("nothing readable at %s"):format(ddd.format.addr(addr)))
          return
        end

        ui:status(("string of %d byte%s at %s"):format(size,
                                                       size == 1 and "" or "s",
                                                       ddd.format.addr(addr)))
        ui:invalidate()
      end,
    }

    -- The other half: saying that a stretch *is* something. Any kind, because
    -- what is worth marking in a binary is not a fixed list.
    scope.command "define-region" {
      title = "Define a region here",
      key = "<control>r",
      run = function(ui)
        local addr = selected_address(ui)
        if not addr then return end

        prompt(ui, {
          title = "Define region",
          subtitle = ("at %s -- SIZE KIND [NAME], e.g. `4 item counter`")
            :format(ddd.format.addr(addr)),
          text = "4 item ",
        }, function(text)
          local size, kind, name = text:match("^%s*(%S+)%s+(%S+)%s*(.*)$")
          if not size or not tonumber(size) then
            ui:status("give a size and a kind")
            return
          end

          local region = ui.session.define_region(addr, tonumber(size), kind,
                                                  name ~= "" and name or kind)
          if not region then
            ui:status("that does not fit inside anything")
            return
          end

          ui:status(("%s %s at %s"):format(region.kind, region.name,
                                           ddd.format.addr(region.addr)))
          ui:invalidate()
        end)
      end,
    }

    scope.command "define-data" {
      title = "This is not code",
      key = "<control>d",
      run = function(ui)
        local addr = selected_address(ui)
        if not addr then return end

        local func = selected_function(ui)
        local suggestion = func and ("0x%x"):format(func["end"]) or ""

        prompt(ui, {
          title = "Define as data",
          subtitle = ("from %s -- to where?"):format(ddd.format.addr(addr)),
          text = suggestion,
        }, function(text)
          local last = tonumber(text)
          if not last or last <= addr then
            ui:status("that is not an address after " .. ddd.format.addr(addr))
            return
          end

          ui.session.define_data(addr, last)
          ui:status(("%s-%s is data"):format(ddd.format.addr(addr),
                                             ddd.format.addr(last)))
          ui:invalidate()
        end)
      end,
    }

    -- What makes a flat firmware image tractable: say which stretch is which
    -- instruction set, once, and it is kept in the project.
    scope.command "region" {
      title = "Define a region and its instruction set",
      run = function(ui)
        local addr = selected_address(ui) or ui.info.base

        prompt(ui, {
          title = "Define region",
          subtitle = "BEGIN END SPEC  (e.g. 0x8000 0x9000 ARM7_le)",
          text = ("0x%x  0x%x  "):format(addr, addr + 0x1000),
        }, function(text)
          local begin, last, spec, abi =
            text:match("^%s*(%S+)%s+(%S+)%s+(%S+)%s*(%S*)")
          if not spec then
            ui:status("give a beginning, an end and a spec")
            return
          end

          local ok = ui.session.add_region(tonumber(begin), tonumber(last),
                                           spec, abi ~= "" and abi or nil)
          if not ok then
            ui:status(("no spec called %s (%d installed)")
              :format(spec, #ui.session.specs()))
            return
          end

          ui:status(("region %s-%s is %s"):format(begin, last, spec))
          ui.session.discover_functions()
          ui:invalidate()
        end)
      end,
    }

    scope.command "back" {
      title = "Back",
      key = "<alt>Left",
      run = function(ui)
        if not ui:back() then ui:status("nowhere to go back to") end
      end,
    }

    scope.command "forward" {
      title = "Forward",
      key = "<alt>Right",
      run = function(ui)
        if not ui:forward() then ui:status("nowhere to go forward to") end
      end,
    }

    scope.command "machine" {
      title = "Show or hide the machine bookkeeping",
      key = "m",
      run = function(ui)
        ui.machine = not ui.machine
        ui:status(ui.machine and "showing stack and return-address bookkeeping"
                              or "hiding machine bookkeeping")
        ui:refresh()
      end,
    }

    scope.command "data" {
      title = "Show this address as data",
      key = "d",
      run = function(ui)
        local selection = ui.selection or {}
        ui:emit("data", selection.target or selected_address(ui))
        ui:emit("show", "data")
      end,
    }

    scope.command "analyse" {
      title = "Index every reference in the image",
      run = function(ui)
        ui:status("analysing all references...")
        local count = ui.session.build_xrefs()
        ui:status(("%d reference(s)"):format(count))
        ui:refresh()
      end,
    }

    scope.command "entry" {
      title = "Go to the entry point",
      run = function(ui) ui:navigate(ui.info.entry) end,
    }

    scope.command "quit" {
      title = "Quit",
      key = "<control>q",
      run = function(ui) ui:quit() end,
    }
  end,
}
