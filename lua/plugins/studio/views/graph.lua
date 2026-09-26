-- The function as a graph, the way everyone actually reads control flow.
--
-- A linear listing is the truth about a binary -- these bytes, in this order --
-- and it is the wrong shape for the one question a reader asks constantly:
-- what happens next. The arrows down the gutter answer it for one branch at a
-- time; a graph answers it for the whole function at once, which is why every
-- disassembler grew one.
--
-- The same listing feeds both. Blocks, lines, tokens and the two edges out of
-- a condition all arrive from the pipeline already worked out, so this file is
-- layout and paint and nothing else: no second idea of what a block is, and no
-- way for the two views to disagree about what the function does.
--
-- Drawn rather than built out of widgets. A block is monospace text in a box
-- and there can be two hundred of them; that is a drawing, and making it a
-- widget tree means the toolkit laying out ten thousand labels every time
-- something moves.
--
-- The layout is judged rather than admired: `DDD_SMOKE=graph` lays out every
-- function in a binary and prints how many edges cross, how many run straight
-- down, how wide the result is and how long it took, so a change here is a
-- change in numbers. `DDD_GRAPH_PLACE=priority` or `=bk` forces one of the two
-- placements below, which is how the two were compared.
local gtk = require "plugins.studio.gtk"
local ddd = require "ddd"
local format = require "ddd.format"

local Gtk, GLib = gtk.Gtk, gtk.GLib

local M = {}

-- How wide a character is, for deciding how wide a box has to be. An estimate,
-- because the box is sized before anything has been drawn and the toy text API
-- has nothing to say about a font until it has drawn with it -- so it is a
-- generous one. Painting does not use it: the text advances itself.
local kFont = 12.5
local kCharW = kFont * 0.65
local kLineH = kFont * 1.45

local kPad = 10        -- inside a block, around the text
local kGapX = 34       -- between blocks in a row
local kGapY = 52       -- between rows, where the edges run
local kMargin = 40     -- around the whole graph

-- A block with a thousand lines in it is a wall, and nobody reads a wall in a
-- graph -- they read it in the listing. Enough to recognise the block and see
-- how it ends.
local kMaxRows = 28

-- How far to bend an edge out of the way of the blocks it passes.
local kBackLane = 26

-- How much room a long edge is given where it passes a row: enough that it
-- reads as running beside the blocks rather than against them.
local kLane = 12

local Graph = {}
Graph.__index = Graph

local function rgb(hex)
  local r, g, b = tostring(hex or ""):match("^#(%x%x)(%x%x)(%x%x)$")
  if not r then return 0.8, 0.8, 0.8 end
  return tonumber(r, 16) / 255, tonumber(g, 16) / 255, tonumber(b, 16) / 255
end

-- ---- what a block looks like ---------------------------------------------

-- One row of text: the pieces it is made of and what colour each one is, so
-- the paint is a loop and the measuring is arithmetic.
local function row_of(line, theme, labels)
  local parts, width = {}, 0

  local function put(text, colour)
    if text == "" then return end
    parts[#parts + 1] = { text = text, colour = colour }
    width = width + (utf8.len(text) or #text)
  end

  put(("%08x  "):format(line.addr), theme.token.address)

  local previous, earlier
  for _, token in ipairs(line.tokens) do
    if format.space_before(token, previous, earlier) then put(" ") end

    local text, colour = token.s, theme.token[token.k] or theme.colour.text

    if token.k == "block" then
      -- The label the block is drawn under, the same one the listing prints:
      -- the box is on screen, but which box is a question the text has to
      -- answer as well as the arrow does -- a phi says which predecessor each
      -- of its arguments came from, and "loc" twice says nothing.
      local id = tonumber(token.s)
      text = (id and labels[id]) or ("block " .. token.s)
      colour = theme.token.label
      if id and id == line.taken then
        colour = line.fallthrough and theme.colour.flow_taken
          or theme.colour.flow_jump
      elseif id and id == line.fallthrough then
        colour = theme.colour.flow_other
      end
    elseif token.k == "extern" then
      colour = theme.token.extern
    end

    put(text, colour)
    earlier, previous = previous, token
  end

  return { parts = parts, width = width }
end

-- Every edge leaving a block, and which of the two it is.
--
-- The last line of the block says: a condition names both of its edges, an
-- unconditional jump names one, and a block that simply runs into the next one
-- says nothing at all -- which is itself the answer, and is drawn as the plain
-- edge it is.
local function edges_of(block, theme)
  local last = block.lines[#block.lines]
  local found = {}

  if last and last.taken then
    found[#found + 1] = { to = last.taken,
                          kind = last.fallthrough and "taken" or "jump",
                          colour = last.fallthrough and theme.colour.flow_taken
                            or theme.colour.flow_jump }
    if last.fallthrough then
      found[#found + 1] = { to = last.fallthrough, kind = "other",
                            colour = theme.colour.flow_other }
    end
    return found
  end

  for _, succ in ipairs(block.succs) do
    found[#found + 1] = { to = succ, kind = "flow", colour = theme.colour.muted }
  end
  return found
end

-- ---- laying it out --------------------------------------------------------

-- Rows first, then columns.
--
-- Each block goes one row below the deepest thing that reaches it, ignoring the
-- edges that go backwards -- a loop has to close somewhere, and a layer
-- assignment that respects it does not terminate. Then each row is ordered by
-- where its predecessors ended up, which is the whole of what makes a graph
-- readable: edges that do not cross unless they have to.
function Graph:layout(listing)
  local theme = self.ui.theme
  local blocks, by_id = {}, {}

  -- What each block is called, before any of them is drawn: a branch names a
  -- block that has not been reached yet as often as not.
  local labels = {}
  for _, raw in ipairs(listing.blocks) do
    labels[raw.id] = raw.entry and listing.name or ("loc_%x"):format(raw.addr)
  end

  for _, raw in ipairs(listing.blocks) do
    local heading = labels[raw.id] .. ":"
    local rows = {}
    rows[#rows + 1] = {
      parts = { { text = heading,
                  colour = raw.entry and theme.colour.text
                    or theme.token.label } },
      width = utf8.len(heading),
    }

    for index, line in ipairs(raw.lines) do
      if index > kMaxRows then
        local text = ("... %d more line(s)"):format(#raw.lines - kMaxRows)
        rows[#rows + 1] = { parts = { { text = text,
                                        colour = theme.token.comment } },
                            width = #text }
        break
      end
      rows[#rows + 1] = row_of(line, theme, labels)
    end

    local widest = 0
    for _, row in ipairs(rows) do widest = math.max(widest, row.width) end

    local block = {
      id = raw.id,
      addr = raw.addr,
      entry = raw.entry,
      rows = rows,
      succs = raw.succs,
      edges = edges_of(raw, theme),
      w = widest * kCharW + kPad * 2,
      h = #rows * kLineH + kPad * 2,
      layer = 0,
    }

    blocks[#blocks + 1] = block
    by_id[raw.id] = block
  end

  if #blocks == 0 then return nil end

  -- Rows.
  --
  -- Relaxed rather than solved: a handful of passes settles every shape a
  -- compiler emits, and the answer only has to be readable. An edge that goes
  -- backwards is a loop closing, and pushes nothing down -- a layering that
  -- respected it would not terminate.
  for _ = 1, math.min(#blocks, 12) do
    local moved = false
    for _, block in ipairs(blocks) do
      for _, edge in ipairs(block.edges) do
        local target = by_id[edge.to]
        if target and target.addr > block.addr
           and target.layer < block.layer + 1 then
          target.layer = block.layer + 1
          moved = true
        end
      end
    end
    if not moved then break end
  end

  -- Every edge as a chain of nodes, one per row it crosses.
  --
  -- This is what stops a graph reading as a knot. An edge that skips three rows
  -- has to get past whatever is in them, and drawing it as a straight line from
  -- one box to another means drawing it *through* those boxes -- so the rows in
  -- between each get a placeholder the line passes through, and the placeholder
  -- takes part in the ordering below like anything else. The line then goes
  -- round the blocks rather than over them, and the space it needs is space the
  -- layout actually reserved.
  local nodes = {}
  for _, block in ipairs(blocks) do nodes[#nodes + 1] = block end

  local links = {} -- { from = node, to = node, colour, back }
  for _, block in ipairs(blocks) do
    for _, edge in ipairs(block.edges) do
      local target = by_id[edge.to]
      if target then
        if target.layer <= block.layer then
          -- Backwards: routed round the side when it is drawn, not threaded
          -- through the rows it passes, which are full of the loop body.
          links[#links + 1] = { from = block, to = target, colour = edge.colour,
                                back = true }
        else
          local previous = block
          for layer = block.layer + 1, target.layer - 1 do
            local dummy = { dummy = true, layer = layer, w = kLane, h = 0,
                            addr = block.addr }
            nodes[#nodes + 1] = dummy
            links[#links + 1] = { from = previous, to = dummy,
                                  colour = edge.colour }
            previous = dummy
          end
          links[#links + 1] = { from = previous, to = target,
                                colour = edge.colour }
        end
      end
    end
  end

  for _, link in ipairs(links) do
    link.from.out = link.from.out or {}
    link.to.into = link.to.into or {}
    if not link.back then
      link.from.out[#link.from.out + 1] = link
      link.to.into[#link.to.into + 1] = link
    end
  end

  local rows = {}
  local deepest = 0
  for _, node in ipairs(nodes) do
    rows[node.layer] = rows[node.layer] or {}
    local row = rows[node.layer]
    row[#row + 1] = node
    deepest = math.max(deepest, node.layer)
  end
  for layer = 0, deepest do rows[layer] = rows[layer] or {} end

  -- Order within a row, by where the things connected to it are.
  --
  -- Straight down the middle of the whole business: two blocks in one row
  -- whose parents are in the other order means two edges crossing, for no
  -- reason other than the order they were listed in. Sweeping down and then up
  -- a few times, each time putting a node at the average position of what it is
  -- attached to in the row before, settles it -- this is the standard way and
  -- it is standard because a couple of passes is usually all it takes.
  for layer = 0, deepest do
    for index, node in ipairs(rows[layer]) do node.order = index end
  end

  local function barycentre(node, side)
    local total, count = 0, 0
    for _, link in ipairs(node[side] or {}) do
      local other = side == "into" and link.from or link.to
      total = total + other.order
      count = count + 1
    end
    return count > 0 and (total / count) or node.order
  end

  local function reorder(layer, side)
    local row = rows[layer]
    for _, node in ipairs(row) do node.want = barycentre(node, side) end
    table.sort(row, function(a, b)
      if a.want ~= b.want then return a.want < b.want end
      return a.order < b.order
    end)
    for index, node in ipairs(row) do node.order = index end
  end

  -- And then adjacent exchanges, which is what finishes the job.
  --
  -- A barycentre is an average, and an average settles long before the
  -- crossings do: two nodes whose neighbours average out the same are left in
  -- whatever order they happened to arrive in, and swapping them is free. So
  -- every neighbouring pair is tried, and a swap that removes more crossings
  -- than it makes is kept. This pair -- sweep, then transpose -- is what `dot`
  -- does, and it is most of the difference between the two.
  local function crossings_between(left, right, side)
    local count = 0
    for _, one in ipairs(left[side] or {}) do
      local a = (side == "into" and one.from or one.to).order
      for _, other in ipairs(right[side] or {}) do
        local b = (side == "into" and other.from or other.to).order
        if a > b then count = count + 1 end
      end
    end
    return count
  end

  local function transpose()
    local improved, rounds = true, 0

    while improved and rounds < 8 do
      improved, rounds = false, rounds + 1

      for layer = 0, deepest do
        local row = rows[layer]
        for index = 1, #row - 1 do
          local left, right = row[index], row[index + 1]

          local now = crossings_between(left, right, "into")
            + crossings_between(left, right, "out")
          local swapped = crossings_between(right, left, "into")
            + crossings_between(right, left, "out")

          if swapped < now then
            row[index], row[index + 1] = right, left
            left.order, right.order = index + 1, index
            improved = true
          end
        end
      end
    end
  end

  for _ = 1, 4 do
    for layer = 1, deepest do reorder(layer, "into") end
    for layer = deepest - 1, 0, -1 do reorder(layer, "out") end
    transpose()
  end

  -- ---- columns, two ways -------------------------------------------------
  --
  -- Both are kept while the choice is being made: the numbers the probe prints
  -- are the only honest way to compare them, and a metric read off one of the
  -- two algorithms' own objective is not a comparison at all.

  -- The priority method: pack the row, then move each node towards the middle
  -- of what it is attached to, as far as its neighbours give way -- and who
  -- gives way is decided by what they have to lose, placeholders first.
  local function place_by_priority()
    for _, node in ipairs(nodes) do
      node.priority = node.dummy and 1e6
        or (#(node.into or {}) + #(node.out or {}))
    end

    for layer = 0, deepest do
      local x = kMargin
      for index, node in ipairs(rows[layer]) do
        node.index = index
        node.x = x
        x = x + node.w + kGapX
      end
    end

    local function room(row, index, direction, priority)
      local node = row[index]
      local neighbour = row[index + direction]
      if not neighbour then return math.huge end

      local gap = direction > 0
        and (neighbour.x - (node.x + node.w + kGapX))
        or (node.x - (neighbour.x + neighbour.w + kGapX))
      gap = math.max(0, gap)

      if neighbour.priority >= priority then return gap end
      return gap + room(row, index + direction, direction, priority)
    end

    local function push(row, index, delta, direction)
      local node = row[index]
      node.x = node.x + delta * direction

      local neighbour = row[index + direction]
      if not neighbour then return end

      local overlap = direction > 0
        and ((node.x + node.w + kGapX) - neighbour.x)
        or ((neighbour.x + neighbour.w + kGapX) - node.x)
      if overlap > 0 then push(row, index + direction, overlap, direction) end
    end

    local function pull(layer, side)
      local row = rows[layer]

      local order = {}
      for _, node in ipairs(row) do order[#order + 1] = node end
      table.sort(order, function(a, b)
        if a.priority ~= b.priority then return a.priority > b.priority end
        return a.index < b.index
      end)

      for _, node in ipairs(order) do
        local total, count = 0, 0
        for _, link in ipairs(node.into or {}) do
          local weight = side == "into" and 2 or 1
          total = total + (link.from.x + link.from.w / 2) * weight
          count = count + weight
        end
        for _, link in ipairs(node.out or {}) do
          local weight = side == "out" and 2 or 1
          total = total + (link.to.x + link.to.w / 2) * weight
          count = count + weight
        end

        if count > 0 then
          local want = total / count - node.w / 2
          local delta = want - node.x
          local direction = delta < 0 and -1 or 1
          delta = math.min(math.abs(delta),
                           room(row, node.index, direction, node.priority))
          if delta > 0.5 then push(row, node.index, delta, direction) end
        end
      end
    end

    for _ = 1, 6 do
      for layer = 1, deepest do pull(layer, "into") end
      for layer = deepest - 1, 0, -1 do pull(layer, "out") end
    end
  end

  -- Columns, by Brandes and Köpf.
  --
  -- The problem is easy to state and not easy to solve: put every node where
  -- the things it is attached to are, without any two in a row overlapping.
  -- Pulling each node towards its neighbours in turn -- the obvious answer, and
  -- the one that was here -- walks a whole row sideways one step at a time,
  -- because a node only ever knows about its own edges.
  --
  -- This is the standard answer instead. Each node is aligned with the median
  -- of its neighbours, giving chains of nodes that want to share a column; each
  -- chain is then placed as a unit, as far towards where it wants to be as the
  -- chain beside it allows. That is done four times -- aligning upwards and
  -- downwards, biased left and biased right -- and each node ends up at the
  -- average of the middle two answers, which is what keeps a diamond
  -- symmetrical instead of leaning whichever way the sweep happened to run.
  --
  -- The one subtlety is the conflicts. A long edge is a chain of placeholders
  -- and it should come out dead straight; an ordinary edge that crosses one
  -- must not be allowed to drag it out of line. Those pairs are marked first
  -- and the alignment refuses them.
  local function neighbours(node, side)
    local found = {}
    for _, link in ipairs(node[side] or {}) do
      found[#found + 1] = side == "into" and link.from or link.to
    end
    table.sort(found, function(a, b) return a.order < b.order end)
    return found
  end

  local function place_by_brandes_koepf()
  local conflicted = {}
  local function mark_conflict(u, v)
    conflicted[u] = conflicted[u] or {}
    conflicted[u][v] = true
  end
  local function in_conflict(u, v)
    return (conflicted[u] and conflicted[u][v])
      or (conflicted[v] and conflicted[v][u]) or false
  end

  for layer = 1, deepest do
    local row, above = rows[layer], rows[layer - 1]
    local k0, scan = 1, 1

    for position, v in ipairs(row) do
      -- The upper end of a long edge passing through here, if that is what
      -- this node is.
      local inner
      if v.dummy then
        for _, link in ipairs(v.into or {}) do
          if link.from.dummy then inner = link.from end
        end
      end

      if position == #row or inner then
        local k1 = inner and inner.order or #above

        while scan <= position do
          for _, u in ipairs(neighbours(row[scan], "into")) do
            if u.order < k0 or u.order > k1 then mark_conflict(u, row[scan]) end
          end
          scan = scan + 1
        end

        k0 = k1
      end
    end
  end

  -- Right-biased runs are the same code on a mirrored graph, rather than the
  -- same code again with every comparison the other way round -- which is
  -- where an implementation of this usually goes wrong.
  local function mirror()
    for layer = 0, deepest do
      local row = rows[layer]
      for index = 1, #row // 2 do
        row[index], row[#row - index + 1] = row[#row - index + 1], row[index]
      end
      for index, node in ipairs(row) do node.order = index end
    end
  end

  local function align(down)
    local root, aligned = {}, {}
    for _, node in ipairs(nodes) do
      root[node], aligned[node] = node, node
    end

    local first, last, step, side = 1, deepest, 1, "into"
    if not down then first, last, step, side = deepest - 1, 0, -1, "out" end

    for layer = first, last, step do
      local previous
      for _, v in ipairs(rows[layer]) do
        local ns = neighbours(v, side)
        if #ns > 0 then
          local middle = (#ns + 1) / 2
          for _, m in ipairs({ math.floor(middle), math.ceil(middle) }) do
            if aligned[v] == v then
              local u = ns[m]
              if not in_conflict(u, v) and (not previous or previous < u.order) then
                aligned[u] = v
                root[v] = root[u]
                aligned[v] = root[v]
                previous = u.order
              end
            end
          end
        end
      end
    end

    return root, aligned
  end

  local function compact(root, aligned)
    local sink, shift, place = {}, {}, {}
    for _, node in ipairs(nodes) do
      sink[node], shift[node] = node, math.huge
    end

    local function place_block(v)
      if place[v] then return end
      place[v] = 0

      local w = v
      repeat
        local row = rows[w.layer]
        local left = row[w.order - 1]

        if left then
          local u = root[left]
          place_block(u)

          if sink[v] == v then sink[v] = sink[u] end

          local gap = (w.w + left.w) / 2 + kGapX
          if sink[v] ~= sink[u] then
            shift[sink[u]] = math.min(shift[sink[u]], place[v] - place[u] - gap)
          else
            place[v] = math.max(place[v], place[u] + gap)
          end
        end

        w = aligned[w]
      until w == v
    end

    for _, node in ipairs(nodes) do
      if root[node] == node then place_block(node) end
    end

    local out = {}
    for _, node in ipairs(nodes) do
      local at = place[root[node]] or 0
      local moved = shift[sink[root[node]]]
      out[node] = at + (moved < math.huge and moved or 0)
    end
    return out
  end

  -- The four runs, and then the middle of them.
  local layouts = {}

  for _, mirrored in ipairs({ false, true }) do
    if mirrored then mirror() end

    for _, down in ipairs({ true, false }) do
      local root, aligned = align(down)
      local centres = compact(root, aligned)


      layouts[#layouts + 1] = { centres = centres, mirrored = mirrored }
    end

    if mirrored then mirror() end -- back to the order everything else reads
  end

  -- Each run is only defined up to a shift, so they are lined up against the
  -- narrowest of them -- left edges for the left-biased runs, right edges for
  -- the mirrored ones -- before anything is averaged.
  local narrowest, best
  for _, layout in ipairs(layouts) do
    local low, high = math.huge, -math.huge
    for node, at in pairs(layout.centres) do
      low = math.min(low, at - node.w / 2)
      high = math.max(high, at + node.w / 2)
    end
    layout.low, layout.high = low, high

    if not narrowest or (high - low) < narrowest then
      narrowest, best = high - low, layout
    end
  end

  for _, layout in ipairs(layouts) do
    local delta = layout.mirrored and (best.high - layout.high)
      or (best.low - layout.low)
    if delta ~= 0 then
      for node, at in pairs(layout.centres) do
        layout.centres[node] = at + delta
      end
    end
  end

  for _, node in ipairs(nodes) do
    local values = {}
    for _, layout in ipairs(layouts) do
      values[#values + 1] = layout.centres[node] or 0
    end
    table.sort(values)

    -- The average of the middle two: the outer answers are the ones that leant
    -- hardest one way, and neither of them is the shape of the graph.
    node.x = (values[2] + values[3]) / 2 - node.w / 2
  end
  end

  -- Both, and keep the better one.
  --
  -- They are not two attempts at the same thing: aligning chains straightens
  -- edges and pays for it in width, and pulling nodes about keeps the graph
  -- narrow and bends everything slightly. Which is worth more depends on the
  -- function -- ordinary compiled control flow comes out straighter *and*
  -- narrower under the alignment, while a jump table full of scrambled gotos
  -- comes out half the width under the pulling -- and there is no way to know
  -- which from the shape of the graph without laying it out.
  --
  -- So lay it out twice. Width decides, because a graph wider than the window
  -- is one you cannot read at all; straightness decides between layouts of
  -- much the same width, because a straight edge is one you can follow without
  -- thinking. Both together are about three milliseconds for a function of
  -- thirty blocks, paid once when it is opened.
  local function score()
    local low, high, straight = math.huge, -math.huge, 0

    for _, node in ipairs(nodes) do
      low = math.min(low, node.x)
      high = math.max(high, node.x + node.w)
    end

    for _, link in ipairs(links) do
      if not link.back then
        local moved = math.abs((link.from.x + link.from.w / 2)
                               - (link.to.x + link.to.w / 2))
        if moved < 1 then straight = straight + 1 end
      end
    end

    return high - low, straight
  end

  local function remember()
    local where = {}
    for _, node in ipairs(nodes) do where[node] = node.x end
    return where
  end

  local function restore(where)
    for _, node in ipairs(nodes) do node.x = where[node] end
  end

  local wanted = os.getenv("DDD_GRAPH_PLACE")

  if wanted == "priority" then
    place_by_priority()
  elseif wanted == "bk" then
    place_by_brandes_koepf()
  else
    place_by_priority()
    local pulled_width, pulled_straight = score()
    local pulled = remember()

    place_by_brandes_koepf()
    local aligned_width, aligned_straight = score()

    -- Within a tenth of each other counts as the same width, and then the one
    -- with more edges going straight down wins.
    local same = math.abs(aligned_width - pulled_width)
      <= math.max(aligned_width, pulled_width) * 0.1

    local keep_aligned = same and (aligned_straight >= pulled_straight)
      or (not same and aligned_width < pulled_width)

    if not keep_aligned then restore(pulled) end
  end

  -- And rows down the page, each as tall as the tallest thing in it.
  local y = kMargin
  local width = 0

  for layer = 0, deepest do
    local tallest = 0
    for _, node in ipairs(rows[layer]) do
      node.y = y
      tallest = math.max(tallest, node.h)
      width = math.max(width, node.x + node.w + kMargin)
    end
    y = y + tallest + kGapY
  end

  -- Everything moved back against the margin, in either direction: giving way
  -- above walks a row left as readily as right, and a node at a negative x is
  -- drawn off the edge of the surface where nobody can see it.
  local leftmost = math.huge
  for _, node in ipairs(nodes) do leftmost = math.min(leftmost, node.x) end

  if leftmost ~= math.huge and leftmost ~= kMargin then
    local shift = leftmost - kMargin
    for _, node in ipairs(nodes) do node.x = node.x - shift end
    width = width - shift
  end

  return {
    blocks = blocks,
    nodes = nodes,
    links = links,
    by_id = by_id,
    width = width,
    height = y - kGapY + kMargin,
    name = listing.name,
    addr = listing.addr,
  }
end

-- ---- judging it -----------------------------------------------------------

-- Two numbers that say whether a layout is any good.
--
-- Crossings are the first thing a reader trips over: two lines that meet
-- somewhere neither of them goes. Deviation is how far an edge moves sideways
-- between its two ends, summed -- a graph of straight vertical lines has none,
-- and every bend in it is somebody following a line with a finger.
--
-- Both are counted over the layout rather than the picture, so a change to the
-- ordering or the placement can be judged by a number over a whole binary
-- instead of by looking at a few of them.
function M.measure(plan)
  local crossings, deviation, straight, links = 0, 0, 0, 0

  -- Every pair of links between the same two rows, in the order their ends sit
  -- in: they cross exactly when the two orders disagree.
  local between = {}
  for _, link in ipairs(plan.links) do
    if not link.back then
      local layer = link.from.layer
      between[layer] = between[layer] or {}
      table.insert(between[layer], link)

      local moved = math.abs((link.from.x + link.from.w / 2)
                             - (link.to.x + link.to.w / 2))
      deviation = deviation + moved
      links = links + 1
      if moved < 1 then straight = straight + 1 end
    end
  end

  for _, links in pairs(between) do
    for i = 1, #links do
      for j = i + 1, #links do
        local a, b = links[i], links[j]
        local top = a.from.order - b.from.order
        local bottom = a.to.order - b.to.order
        if top * bottom < 0 then crossings = crossings + 1 end
      end
    end
  end

  return crossings, deviation, straight, links, plan.width
end

-- ---- painting -------------------------------------------------------------

local function arrowhead(cr, x, y, dx, dy)
  local length = math.sqrt(dx * dx + dy * dy)
  if length < 0.001 then return end
  dx, dy = dx / length, dy / length

  local size = 7
  local px, py = -dy, dx
  cr:move_to(x, y)
  cr:line_to(x - dx * size + px * size * 0.5, y - dy * size + py * size * 0.5)
  cr:line_to(x - dx * size - px * size * 0.5, y - dy * size - py * size * 0.5)
  cr:close_path()
  cr:fill()
end

-- Where an edge leaves a block and where it arrives.
--
-- Spread across the width, in the left-to-right order of the other end: two
-- edges out of a condition leave from two places rather than from one, and two
-- edges arriving at a merge point arrive at two -- and neither pair crosses on
-- the way out or on the way in, because the slots are handed out in the order
-- the far ends are sitting in.
local function slot(node, links, link, side)
  if node.dummy then return node.x + node.w / 2 end

  local order = {}
  for _, one in ipairs(links) do order[#order + 1] = one end
  table.sort(order, function(a, b)
    local left = side == "out" and a.to or a.from
    local right = side == "out" and b.to or b.from
    if left.x ~= right.x then return left.x < right.x end
    return (left.addr or 0) < (right.addr or 0)
  end)

  local index = 1
  for position, one in ipairs(order) do
    if one == link then index = position end
  end

  return node.x + node.w * (index / (#order + 1))
end

function Graph:draw_edges(cr, plan)
  -- Every link that starts or ends at a node, so the slots can be worked out
  -- once rather than per link.
  local out, into = {}, {}
  for _, link in ipairs(plan.links) do
    if not link.back then
      out[link.from] = out[link.from] or {}
      table.insert(out[link.from], link)
      into[link.to] = into[link.to] or {}
      table.insert(into[link.to], link)
    end
  end

  for _, link in ipairs(plan.links) do
    local from, to = link.from, link.to

    cr:set_source_rgb(rgb(link.colour))
    cr:set_line_width(1.6)

    if link.back then
      -- A loop, drawn round the outside: through the rows between its foot and
      -- its head is where the loop body is, and a line across all of it is the
      -- one thing a reader cannot follow.
      local x1 = from.x + from.w / 2
      local y1 = from.y + from.h
      local x2 = to.x + to.w / 2
      local y2 = to.y

      local left = math.min(from.x, to.x) - kBackLane
      local right = math.max(from.x + from.w, to.x + to.w) + kBackLane
      local lane = (x2 <= x1) and left or right

      cr:move_to(x1, y1)
      cr:line_to(x1, y1 + kBackLane * 0.6)
      cr:line_to(lane, y1 + kBackLane * 0.6)
      cr:line_to(lane, y2 - kBackLane)
      cr:line_to(x2, y2 - kBackLane)
      cr:line_to(x2, y2)
      cr:stroke()
      arrowhead(cr, x2, y2, 0, 1)

    else
      local x1 = slot(from, out[from] or { link }, link, "out")
      local y1 = from.dummy and from.y or (from.y + from.h)
      local x2 = slot(to, into[to] or { link }, link, "into")
      local y2 = to.y

      local bend = math.min(kGapY * 0.8, math.max(8, (y2 - y1) / 2))
      cr:move_to(x1, y1)
      cr:curve_to(x1, y1 + bend, x2, y2 - bend, x2, y2)
      cr:stroke()

      -- Only where it actually arrives: a link into a placeholder is the middle
      -- of somebody's edge, and an arrowhead there says an edge ends in mid-air.
      if not to.dummy then arrowhead(cr, x2, y2, 0, 1) end
    end
  end
end

function Graph:draw_block(cr, block, current)
  local theme = self.ui.theme

  cr:set_source_rgb(rgb(theme.colour.surface))
  cr:rectangle(block.x, block.y, block.w, block.h)
  cr:fill()

  -- Where you are, and where the function starts: the two things worth
  -- picking out of a screenful of identical boxes.
  if current then
    cr:set_source_rgb(rgb(theme.colour.accent))
    cr:set_line_width(2)
  elseif block.entry then
    -- Not green: green means the condition held, everywhere else in this
    -- window, and one colour cannot mean two things in one picture.
    cr:set_source_rgb(rgb(theme.colour.text))
    cr:set_line_width(1.4)
  else
    cr:set_source_rgb(rgb(theme.colour.border))
    cr:set_line_width(1)
  end
  cr:rectangle(block.x, block.y, block.w, block.h)
  cr:stroke()

  cr:select_font_face("monospace", 0, 0)
  cr:set_font_size(kFont)

  -- One move_to per row and then straight on: cairo advances the current point
  -- by exactly what it drew, which is the only thing that knows how wide a
  -- glyph really is. Stepping x by an estimate instead drifts, and what drifts
  -- away is the narrow pieces -- a `:` between a label and a value, the space
  -- before an `else` -- overprinted by whatever came next.
  local y = block.y + kPad + kLineH * 0.78
  for _, row in ipairs(block.rows) do
    cr:move_to(block.x + kPad, y)
    for _, part in ipairs(row.parts) do
      cr:set_source_rgb(rgb(part.colour or theme.colour.text))
      cr:show_text(part.text)
    end
    y = y + kLineH
  end
end

function Graph:draw(cr, width, height)
  local theme = self.ui.theme

  cr:set_source_rgb(rgb(theme.colour.background))
  cr:rectangle(0, 0, width, height)
  cr:fill()

  local plan = self.plan
  if not plan then
    cr:select_font_face("monospace", 0, 0)
    cr:set_font_size(kFont)
    cr:set_source_rgb(rgb(theme.colour.muted))
    cr:move_to(20, 30)
    cr:show_text(self.message or "nothing to show")
    return
  end

  cr:scale(self.zoom, self.zoom)

  -- Edges under the blocks, so a line passing behind one does not draw over
  -- its text.
  self:draw_edges(cr, plan)

  -- Which block the cursor is in: the last one that starts at or before it,
  -- which is the same rule the listing uses to decide what a line belongs to.
  local here = self.ui.focus or self.ui.addr
  local current
  for _, block in ipairs(plan.blocks) do
    if here and here >= block.addr
       and (not current or block.addr > current.addr) then
      current = block
    end
  end

  for _, block in ipairs(plan.blocks) do
    self:draw_block(cr, block, block == current)
  end
end

-- ---- what is on screen ----------------------------------------------------

-- Moving the camera to whatever is being looked at.
--
-- A graph is bigger than the window in every direction, so "you are here" is
-- worth nothing if here is eight hundred pixels below the viewport: following
-- an edge, clicking a name in the function list, coming back from a callee all
-- put the focus on a block that is off screen, and the only sign of it was a
-- border being drawn somewhere nobody could see.
--
-- A block already on screen is left where it is. Yanking the view to centre
-- something that was perfectly visible is its own kind of lost.
-- Where the view has to be for a stretch [from, from + size] to be on it, or
-- nil if it already is. Pure, so it can be checked without a screen -- the one
-- part of this that has an arithmetic answer rather than a visual one.
local function scroll_to(value, page, lower, upper, from, size)
  if page <= 0 then return nil end

  local margin = math.min(kMargin, page / 4)
  if from >= value + margin and from + size <= value + page - margin then
    return nil
  end

  -- Centred when it fits, and against the leading edge when it does not: the
  -- beginning of a block is the part worth seeing.
  local wanted = size > page - margin * 2 and (from - margin)
    or (from - (page - size) / 2)

  return math.max(lower, math.min(math.max(lower, upper - page), wanted))
end

M.scroll_to = scroll_to

function Graph:reveal(block)
  block = block or self:current()
  if not block or not self.plan then return end

  local function bring(adjustment, from, size)
    if not adjustment then return end

    local wanted = scroll_to(adjustment.value, adjustment.page_size,
                             adjustment.lower, adjustment.upper, from, size)
    if wanted then adjustment.value = wanted end
  end

  bring(self.widget:get_vadjustment(), block.y * self.zoom, block.h * self.zoom)
  bring(self.widget:get_hadjustment(), block.x * self.zoom, block.w * self.zoom)
end

-- After the drawing area has been given its new size, which is what decides how
-- far the view can scroll: revealing against the size it had a moment ago
-- clamps to the wrong place, and lands next to the block rather than on it.
function Graph:reveal_soon(block)
  GLib.idle_add(GLib.PRIORITY_DEFAULT_IDLE, function()
    local ok, problem = pcall(self.reveal, self, block)
    if not ok then self.ui:log("graph: " .. tostring(problem)) end
    return false
  end)
end

function Graph:render()
  local ui = self.ui

  if not self.widget:get_mapped() then
    self.stale = true
    return
  end
  self.stale = false

  local addr = ui.focus or ui.addr
  local func = addr and ui.session.function_at(addr)
  if not func then
    self.plan, self.message = nil, "no function here"
    self.area:queue_draw()
    return
  end

  -- The same function as a moment ago, and nothing has been re-analysed: the
  -- picture is the picture. Moving the cursor in the listing emits a selection
  -- for every line it passes, and laying out a graph of two hundred blocks per
  -- keystroke is a window that stops answering while you hold `j`.
  if self.plan and self.plan.addr == func.addr and not self.dirty then
    self:reveal()
    self.area:queue_draw()
    return
  end

  -- Drawn from what has been analysed, like everything else: if the pipeline
  -- has not reached this function the graph says so and asks for it, rather
  -- than running it here and freezing the window.
  local listing = ui.eager and ui:listing(func.addr) or ui:ready(func.addr)
  if not listing or not listing.ok then
    ui:want(func.addr)
    self.plan = nil
    self.message = ui.sweeping and "indexing references..." or "analysing..."
    self.area:queue_draw()
    return
  end

  self.plan = self:layout(listing)
  self.message = self.plan and nil or "nothing to show"
  self.dirty = false

  if self.plan then
    self.area:set_size_request(math.ceil(self.plan.width * self.zoom),
                               math.ceil(self.plan.height * self.zoom))
    self:reveal_soon()
  end
  self.area:queue_draw()
end

-- Which block the cursor is in: the last one that starts at or before it.
function Graph:current()
  local here = self.ui.focus or self.ui.addr
  if not self.plan or not here then return nil end

  local current
  for _, block in ipairs(self.plan.blocks) do
    if here >= block.addr and (not current or block.addr > current.addr) then
      current = block
    end
  end
  return current
end

-- The same `t` and `o` the listing has, along the edges that are drawn right
-- there: take the branch, or take the other way.
function Graph:follow_edge(which)
  local block = self:current()
  if not block then return end

  for _, edge in ipairs(block.edges) do
    local wanted = (which == "taken" and (edge.kind == "taken" or edge.kind == "jump"))
      or (which == "other" and (edge.kind == "other" or edge.kind == "flow"))

    if wanted then
      local target = self.plan.by_id[edge.to]
      if target then
        self.ui:navigate(target.addr)
        return
      end
    end
  end

  self.ui:status(which == "taken" and "nothing is taken from here"
                                   or "nothing falls through from here")
end

function Graph:block_at(x, y)
  if not self.plan then return nil end

  x, y = x / self.zoom, y / self.zoom
  for _, block in ipairs(self.plan.blocks) do
    if x >= block.x and x <= block.x + block.w
       and y >= block.y and y <= block.y + block.h then
      return block
    end
  end
  return nil
end

-- Laying out and painting every function there is, without a window.
--
-- The layout is a lot of code over data produced by analysis -- a block with no
-- lines, an edge to a block the tokeniser dropped, a function that is one
-- enormous switch -- and none of it is exercised by building the widget. The
-- drawing is the same: a surface that is never on screen takes the same calls
-- as one that is.
function Graph:probe()
  local cairo = gtk.lgi.cairo
  local surface = cairo.ImageSurface.create(cairo.Format.ARGB32, 900, 700)
  local cr = cairo.Context.create(surface)

  local failed, first, blocks = 0, nil, 0
  local crossings, deviation = 0, 0
  local straight, edges, width = 0, 0, 0
  local spent = 0

  for _, func in ipairs(self.ui.session.functions()) do
    local listing = self.ui:listing(func.addr)
    if listing and listing.ok then
      local ok, problem = pcall(function()
        local began = os.clock()
        self.plan = self:layout(listing)
        spent = spent + (os.clock() - began)
        if self.plan then
          blocks = blocks + #self.plan.blocks
          local crossed, moved, upright, count, wide = M.measure(self.plan)
          crossings = crossings + crossed
          deviation = deviation + moved
          straight = straight + upright
          edges = edges + count
          width = width + wide
          self:draw(cr, 900, 700)
        end
      end)

      if not ok then
        failed = failed + 1
        first = first or ("%s at 0x%x: %s"):format(func.name, func.addr,
                                                   tostring(problem))
      end
    end
  end

  return ("graph: %d failed of %d, %d block(s), %d crossing(s), "
          .. "%d/%d straight, %d deviation, %d wide, %.0fms laid out%s  %s")
    :format(failed, #self.ui.session.functions(), blocks, crossings,
            straight, edges, math.floor(deviation), math.floor(width),
            spent * 1000, first and ("  " .. first) or "", M.probe_camera())
end

-- The camera, which has no window in a smoke run and does have arithmetic.
function M.probe_camera()
  local checks = {
    -- on screen already: do not move
    { 0, 500, 0, 3000, 100, 80, nil },
    -- below the viewport: centred
    { 0, 500, 0, 3000, 1200, 100, 1000 },
    -- above it: centred
    { 1000, 500, 0, 3000, 200, 100, 0 },
    -- taller than the window: against the leading edge, not centred
    { 0, 500, 0, 3000, 900, 900, 860 },
    -- and never past the end of what there is to scroll
    { 0, 500, 0, 1000, 900, 100, 500 },
  }

  local failed = 0
  for _, one in ipairs(checks) do
    local value, page, lower, upper, from, size, wanted = table.unpack(one)
    local got = scroll_to(value, page, lower, upper, from, size)
    if got ~= wanted then failed = failed + 1 end
  end

  return ("camera: %d/%d"):format(#checks - failed, #checks)
end

-- One function's graph, to a file. What the test suite looks at, and the only
-- way to see whether a layout is readable without opening a window.
function Graph:render_to(path, addr)
  local listing = self.ui:listing(addr or self.ui.addr)
  if not listing or not listing.ok then return nil end

  self.plan = self:layout(listing)
  if not self.plan then return nil end

  local cairo = gtk.lgi.cairo
  local width = math.ceil(self.plan.width)
  local height = math.ceil(self.plan.height)

  local surface = cairo.ImageSurface.create(cairo.Format.ARGB32, width, height)
  local cr = cairo.Context.create(surface)
  self:draw(cr, width, height)
  surface:write_to_png(path)

  return width, height, #self.plan.blocks
end

function M.build(ui)
  local self = setmetatable({ ui = ui, zoom = 1, stale = true }, Graph)

  self.area = Gtk.DrawingArea { hexpand = true, vexpand = true }
  self.area:set_draw_func(function(_, cr, width, height)
    local ok, problem = pcall(self.draw, self, cr, width, height)
    if not ok then ui:log("graph: " .. tostring(problem)) end
  end)

  self.widget = gtk.scrolled(self.area)

  -- Clicking a block goes there, which is what makes the graph a way of
  -- navigating rather than a picture of one.
  local click = Gtk.GestureClick { button = 1 }
  click.on_pressed = function(_, presses, x, y)
    local block = self:block_at(x, y)
    if not block then return end

    ui.focus = block.addr
    ui.selection = { addr = block.addr,
                     func = ui.session.function_at(block.addr) }
    ui:emit("select", block.addr)

    -- Twice means "show me this in the listing", which is where everything
    -- that acts on an address happens.
    if presses >= 2 then
      ui:navigate(block.addr)
      ui:emit("show", "listing")
    else
      self.area:queue_draw()
    end
  end
  self.area:add_controller(click)

  -- The same hand position as the listing: hjkl moves, enter follows, b goes
  -- back. Here they pan, because what a graph has instead of a cursor is a
  -- viewport -- and a graph you can only move with the scrollbars is a graph
  -- you stop using.
  local keys = Gtk.EventControllerKey()
  keys.propagation_phase = Gtk.PropagationPhase.CAPTURE
  keys.on_key_pressed = function(_, keyval)
    local name = gtk.Gdk.keyval_name(keyval)
    local step = 90

    local function pan(adjustment, delta)
      if not adjustment then return end
      adjustment.value = math.max(adjustment.lower,
                                  math.min(adjustment.upper - adjustment.page_size,
                                           adjustment.value + delta))
    end

    if name == "j" or name == "Down" then
      pan(self.widget:get_vadjustment(), step)
    elseif name == "k" or name == "Up" then
      pan(self.widget:get_vadjustment(), -step)
    elseif name == "l" or name == "Right" then
      pan(self.widget:get_hadjustment(), step)
    elseif name == "h" or name == "Left" then
      pan(self.widget:get_hadjustment(), -step)
    elseif name == "t" or name == "o" then
      self:follow_edge(name == "t" and "taken" or "other")
    elseif name == "b" then
      if not ui:back() then ui:status("nowhere to go back to") end
    elseif name == "Return" or name == "KP_Enter" then
      -- Into the listing, at whatever this graph is about, which is where
      -- everything that acts on an address happens.
      ui:navigate(ui.focus or ui.addr)
      ui:emit("show", "listing")
    else
      return false
    end

    return true
  end
  self.area:add_controller(keys)

  self.area.focusable = true
  self.area.can_focus = true

  -- Ctrl and the wheel, the way every canvas does it. A graph of a big
  -- function is wider than any window, and the shape of it is most of what it
  -- is for.
  local scroll = Gtk.EventControllerScroll {
    flags = Gtk.EventControllerScrollFlags.BOTH_AXES,
  }
  scroll.on_scroll = function(controller, _, dy)
    local state = controller:get_current_event_state()
    local control = false
    if type(state) == "table" then
      control = state.CONTROL_MASK == true
    elseif state ~= nil then
      control = (tonumber(state) or 0) & 4 ~= 0 -- GDK_CONTROL_MASK
    end
    if not control then return false end

    self.zoom = math.max(0.35, math.min(2.5, self.zoom * (dy > 0 and 0.9 or 1.1)))
    if self.plan then
      self.area:set_size_request(math.ceil(self.plan.width * self.zoom),
                                 math.ceil(self.plan.height * self.zoom))
      -- Zooming out of sight of what you were looking at is the commonest way
      -- to get lost in a graph.
      self:reveal_soon()
    end
    self.area:queue_draw()
    return true
  end
  self.area:add_controller(scroll)

  local function later()
    if self.pending then return end
    self.pending = true
    GLib.idle_add(GLib.PRIORITY_DEFAULT_IDLE, function()
      self.pending = false
      local ok, problem = pcall(self.render, self)
      if not ok then ui:log("graph: " .. tostring(problem)) end
      return false
    end)
  end

  ui:on("navigate", later)
  ui:on("refresh", later)
  ui:on("select", later)

  -- The analysis changed under it: what is on screen is a picture of a listing
  -- that no longer exists, so the next render has to build a new one rather
  -- than reveal its way around the old one.
  ui:on("invalidate", function()
    self.dirty = true
    later()
  end)

  -- The analysis turning this function from bytes into code is the one report
  -- worth redrawing for; the rest of the binary is not on screen.
  ui:on("analysis", function()
    if not self.plan then later() end
  end)

  -- Switching to the tab is what asks for the layout, and is also the only
  -- moment at which a wait here is one the user asked for. The keys go to the
  -- drawing rather than to whatever had the focus in the page before it.
  self.widget.on_map = function()
    self.area:grab_focus()
    if self.stale then later() end
  end

  ui.graph_view = self
  return self
end

ddd.workflow "studio" {
  ui = function(scope)
    scope.view "graph" {
      title = "Graph",
      place = "main",
      order = 15,
      build = function(ui) return M.build(ui).widget end,
    }
  end,
}

return M
