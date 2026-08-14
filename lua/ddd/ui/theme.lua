-- ddd.ui.theme -- what the interface looks like.
--
-- One table, because everything that draws reads from it: the CSS the window
-- is styled with, and the colours the listing tags its tokens with. A plugin
-- that wants a different look declares a theme in its ui scope and patches the
-- fields it cares about; nothing else has to know.
local M = {}

-- Dark by default, and not apologetically: this is a tool you look at for
-- hours at a time, and the thing on screen is mostly monospace text whose
-- meaning is carried by colour.
M.colour = {
  background  = "#1b1d21",
  surface     = "#22252a",
  raised      = "#2a2e35",
  border      = "#343941",
  text        = "#d7dae0",
  muted       = "#828b98",
  accent      = "#4d9cf6",
  selection   = "#2c3b52",
  highlight   = "#3b4c66", -- the other occurrences of what the cursor is on
  warning     = "#e5a04a",
}

-- One colour per token kind, which is what `tokenize` hands out: var, const,
-- op, punct, cast, keyword.
M.token = {
  var       = "#61afef",
  const     = "#d19a66",
  op        = "#56b6c2",
  punct     = "#828b98",
  cast      = "#c678dd",
  keyword   = "#c678dd",
  address   = "#5c6370",
  comment   = "#5f6b7a",
  label     = "#98c379",
  xref      = "#7f8896",
  string    = "#98c379",
  ["function"] = "#61afef",
}

M.font = "monospace 10"

-- GTK styling. Everything structural is a class the widgets ask for by name,
-- so a theme can be replaced wholesale without any widget code changing.
function M.css()
  local c = M.colour
  return ([[
    window.ddd { background-color: %s; color: %s; }

    .ddd-sidebar { background-color: %s; }
    .ddd-panel { background-color: %s; }

    .ddd-title {
      font-size: 0.85em;
      font-weight: bold;
      letter-spacing: 0.08em;
      color: %s;
      padding: 6px 10px;
      background-color: %s;
      border-bottom: 1px solid %s;
    }

    .ddd-status {
      background-color: %s;
      color: %s;
      border-top: 1px solid %s;
      padding: 3px 10px;
      font-family: monospace;
    }

    .ddd-listing { background-color: %s; color: %s; }
    .ddd-listing text { background-color: %s; }

    .ddd-list { background-color: %s; color: %s; }
    .ddd-list row:selected { background-color: %s; }

    .ddd-mono { font-family: monospace; }
    .ddd-muted { color: %s; }
    .ddd-accent { color: %s; }

    .ddd-search entry { font-family: monospace; }
  ]]):format(
    c.background, c.text,
    c.surface,
    c.surface,
    c.muted, c.surface, c.border,
    c.surface, c.muted, c.border,
    c.background, c.text, c.background,
    c.surface, c.text, c.selection,
    c.muted, c.accent
  )
end

return M
