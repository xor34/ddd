// hil_shape.cpp -- arranging the blocks of a function back into a shape.
//
// One walk, following the CFG rather than the statement list, so a statement
// an earlier pass elided cannot desynchronise it from the edges. The rules, in
// the order they are tried:
//
//   1. Falling into the join is not an edge a listing has to mention, so the
//      fallthrough is always the edge the walk takes.
//   2. An unconditional branch is followed rather than printed: if the block
//      it goes to has not been printed yet, the jump *is* the fallthrough and
//      the goto was never needed.
//   3. `if (cond) { ... }` when the fallthrough is the join -- the arm is the
//      taken edge, and the condition needs no negating because the statement
//      already reads that way.
//   4. `if/else` when the branch's immediate postdominator is neither arm and
//      the two arms do not reach into each other. The postdominator is the
//      join; each arm is walked with it as the follow.
//   5. Everything else is `if (cond) goto L;` and the fallthrough, which is
//      always sound and is the honest thing to print when the CFG has no
//      shape to show.
//
// The universal guard is the `emitted` set. Reaching a block already printed
// emits a jump to it rather than printing it twice, so no block is ever
// structured twice, and after the walk every reachable block that was missed
// is printed at the top level with a label. That is the guarantee that every
// jump has a target -- the worst case is a listing full of gotos, never a
// wrong one.
#include "render/hil_shape.h"

#include "ir/loops.h"
#include "ir/postdom.h"

#include <algorithm>
#include <map>

namespace ddd {
namespace {

class Walk {
public:
  Walk(const Hil &hil, const SsaFunction &fn)
      : fn_(fn), cfg_(fn.cfg()), dom_(fn.dominance()), pd_(fn.cfg()),
        loops_(fn.cfg(), fn.dominance()) {
    for (const HilBlock &block : hil.blocks())
      blocks_.emplace(block.id, &block);
  }

  HilShapes run() {
    HilShapes out;

    if (cfg_.entry)
      out.shapes = region(*cfg_.entry, std::nullopt);

    // What the walk never reached: a block only a `goto` names, or one an arm
    // left behind because the arms did not reconverge. Printed at the top
    // level and labelled, because there is nothing to fall through from.
    for (int i = 0; i < cfg_.size(); ++i) {
      const BlockId block{i};
      if (!dom_.reachable(block) || emitted(block))
        continue;

      forced_.insert(block);
      std::vector<Shape> more = region(block, std::nullopt);
      out.shapes.insert(out.shapes.end(), more.begin(), more.end());
    }

    for (const Shape &shape : out.shapes)
      collect(shape, out.labelled, nullptr);
    out.labelled.insert(forced_.begin(), forced_.end());
    return out;
  }

private:
  const HilBlock *hil_block(BlockId block) const {
    auto it = blocks_.find(block);
    return it == blocks_.end() ? nullptr : it->second;
  }

  bool emitted(BlockId block) const {
    return block.index >= 0 && block.index < static_cast<int>(emitted_.size())
               ? emitted_[block]
               : false;
  }

  const Statement *branch_of(BlockId block) const {
    const HilBlock *hil = hil_block(block);
    if (hil == nullptr || hil->statements.empty())
      return nullptr;

    const Statement &last = hil->statements.back();
    const bool branching = last.kind == StatementKind::CondBranch ||
                           last.kind == StatementKind::Branch;
    return branching ? &last : nullptr;
  }

  void mark_emitted(BlockId block) {
    if (emitted_.size() <= static_cast<size_t>(block.index))
      emitted_.resize(block.index + 1, false);
    emitted_[block] = true;
  }

  // The statements to print: all of them, less the branch the shape takes
  // over. A branch the shape cannot express stays, because it is the only
  // thing that can say where that edge goes.
  void emit_statements(std::vector<Shape> &out, BlockId block,
                       const Statement *drop) {
    const HilBlock *hil = hil_block(block);
    if (hil == nullptr)
      return;

    Shape node;
    node.kind = ShapeKind::Statements;
    node.block = block;
    for (const Statement &statement : hil->statements)
      if (&statement != drop)
        node.statements.push_back(&statement);
    out.push_back(std::move(node));
  }

  Shape jump(BlockId target, const Statement *statement, bool conditional) {
    Shape node;
    node.kind = ShapeKind::Jump;
    node.block = target;
    node.statement = statement;
    node.conditional = conditional;
    return node;
  }

  // The blocks reachable from `from` without stepping through `stop` or
  // through anything already printed -- those are boundaries the walk will not
  // cross, so an arm that only reaches the other arm by going round an
  // already-printed block is not reaching into it.
  std::set<BlockId> reach_without(BlockId from, BlockId stop) const {
    std::set<BlockId> found{from};
    if (from == stop)
      return found;

    std::vector<BlockId> work{from};
    for (int guard = 0; !work.empty() && guard <= 4 * cfg_.size() + 16;
         ++guard) {
      const BlockId block = work.back();
      work.pop_back();

      for (const Edge &edge : cfg_[block].succs) {
        if (edge.target == stop || emitted(edge.target))
          continue;
        if (found.insert(edge.target).second)
          work.push_back(edge.target);
      }
    }

    return found;
  }

  // Whether the two arms of a branch can be printed one after the other,
  // which needs them not to reach into each other: the then-arm's blocks are
  // all printed before the else-arm's are, and a block in both would be
  // printed under whichever came first with a goto from the other.
  bool arms_apart(BlockId join, BlockId taken, BlockId fall) const {
    const std::set<BlockId> then_ = reach_without(taken, join);
    const std::set<BlockId> else_ = reach_without(fall, join);

    for (BlockId block : else_)
      if (then_.count(block) != 0)
        return false;

    return true;
  }

  // The two words a jump inside a loop can be spelled with, asked of a shape
  // that has not been printed yet -- which is what lets the walk recognise a
  // loop-back and an exit by the same rule the printer would use.
  static bool is_jump_word(const Shape &shape, const Shape &loop,
                           JumpWord word) {
    return shape.kind == ShapeKind::Jump && !shape.conditional &&
           jump_word(shape.block, &loop) == word;
  }

  // A jump back to the loop's header, which is what `continue` means and what
  // falling off the end of the body does anyway.
  static bool is_back_jump(const Shape &shape, const Shape &loop) {
    return is_jump_word(shape, loop, JumpWord::Continue);
  }

  // A jump out of the loop, which `arrived` put there because the end of a
  // loop body would otherwise go round again.
  static bool is_exit_jump(const Shape &shape, const Shape &loop) {
    return is_jump_word(shape, loop, JumpWord::Break);
  }

  // Whether the body has anything in it but the jump: a block whose statements
  // the shape took over prints nothing, so counting nodes would count a block
  // that is already silent as content.
  static bool says_anything(const std::vector<Shape> &body, size_t upto) {
    for (size_t i = 0; i < upto && i < body.size(); ++i) {
      const Shape &shape = body[i];
      if (shape.kind == ShapeKind::Statements && shape.statements.empty())
        continue;
      return true;
    }
    return false;
  }

  // Control has arrived at the block the region was walking towards.
  //
  // For a join that is the one edge a listing does not have to mention: the
  // region is over and the shape around it carries on there, so there is
  // nothing to write. For a loop's exit it is the opposite -- the end of a loop
  // body goes round again, not out, so control leaving has to be said and
  // `break` is the word for it. Without it the printed loop runs forever and
  // everything after it is unreachable.
  void arrived(std::vector<Shape> &out, std::optional<BlockId> follow) {
    if (follow && !loop_follow_.empty() && loop_follow_.back() &&
        *loop_follow_.back() == *follow)
      out.push_back(jump(*follow, nullptr, false));
  }

  Shape loop(const Loop &l, std::optional<BlockId> enclosing) {
    // One way out is the usual case and is worth saying plainly. More than one
    // and the join above the header is the only block certainly outside the
    // loop, so that is what `break` means; the other exits become gotos, which
    // is what they are.
    std::optional<BlockId> after;
    if (l.exits.size() == 1)
      after = l.exits.front();
    else
      after = pd_.ipdom(l.header);
    if (!after)
      after = enclosing;

    inside_.push_back(&l);
    loop_follow_.push_back(after);
    std::vector<Shape> body = region(l.header, after);
    loop_follow_.pop_back();
    inside_.pop_back();

    Shape shape;
    shape.kind = ShapeKind::Loop;
    shape.block = l.header;
    shape.follow = after;
    shape.body = std::move(body);

    // A loop whose one way back is the last thing the body does is a
    // `do-while`: `if (cond) continue; break;` at the very end is exactly
    // `do { ... } while (cond);` -- the clause says both what goes round and
    // what stops, so it takes the place of both.
    //
    // Only when the loop has a single latch: a second back edge anywhere inside
    // would be a `continue` that skips the condition, which is not what that
    // clause means.
    if (l.latches.size() == 1 && !shape.body.empty()) {
      size_t end = shape.body.size();
      if (is_exit_jump(shape.body[end - 1], shape))
        --end;

      if (end >= 1) {
        const Shape &last = shape.body[end - 1];
        if (last.kind == ShapeKind::If && last.otherwise.empty() &&
            last.body.size() == 1 && is_back_jump(last.body.front(), shape)) {
          shape.do_while = true;
          shape.statement = last.statement;
          shape.body.erase(shape.body.begin() + (end - 1), shape.body.end());
        }
      }
    }

    // What is left of the back-jump, when it is the last thing the body does:
    // dropped rather than printed, because falling off the end of a `while (1)`
    // goes round anyway.
    //
    // Only the body's own last node. Deeper in, at the end of an arm of an `if`,
    // falling out of the arm is falling out of the `if` -- and what follows the
    // `if` is whatever the shape put there, which for a loop's exit is a
    // `break`. Dropping the jump there would send control past it.
    //
    // Only when the body says something else. A loop whose whole content is the
    // jump back -- a block that branches to itself, which is what a halt or a
    // spin lowers to -- would otherwise print as an empty pair of braces, and
    // the address of the one instruction in it would be nowhere.
    if (!shape.do_while && !shape.body.empty() &&
        is_back_jump(shape.body.back(), shape) &&
        says_anything(shape.body, shape.body.size() - 1))
      shape.body.pop_back();

    return shape;
  }

  std::vector<Shape> region(BlockId entry, std::optional<BlockId> follow) {
    std::vector<Shape> out;
    BlockId cur = entry;

    for (;;) {
      if (follow && cur == *follow) {
        arrived(out, follow);
        return out;
      }

      if (emitted(cur)) {
        out.push_back(jump(cur, nullptr, false));
        return out;
      }

      // A loop starts here. Checked before the block is printed, because a
      // loop's body *is* its header and everything round again -- printing the
      // header first and finding the loop afterwards would leave the header
      // outside its own body.
      if (const Loop *l = loops_.at_header(cur)) {
        if (std::find(inside_.begin(), inside_.end(), l) == inside_.end()) {
          out.push_back(loop(*l, follow));
          if (!out.back().follow)
            return out;
          cur = *out.back().follow;
          continue;
        }
      }

      const BasicBlock &raw = cfg_[cur];
      std::optional<BlockId> taken, fall;
      for (const Edge &edge : raw.succs)
        (edge.conditional ? taken : fall) = edge.target;

      const Statement *branch = branch_of(cur);
      const bool conditional =
          branch != nullptr && branch->kind == StatementKind::CondBranch;

      // Nowhere to go: a return, a tail call, the fall off the end. The
      // statement says so -- `goto 0x401136` is a call, however it is spelled
      // -- so all of it stays.
      if (!fall) {
        emit_statements(out, cur, nullptr);
        mark_emitted(cur);
        return out;
      }

      // An unconditional branch, or a block that just runs on: the jump is
      // the fallthrough, so we follow it and print no goto at all. If the
      // block it goes to has already been printed, the edge is a jump after
      // all -- and it is emitted here rather than left to the top of the walk
      // so that the branch goes with it. A jump the walk invents carries no
      // statement, and so no address: a `while (1) { }` where an instruction
      // sits is worse than a `continue` that says which one it was.
      if (!conditional) {
        emit_statements(out, cur, branch);
        mark_emitted(cur);
        if (!(follow && *fall == *follow) && emitted(*fall)) {
          out.push_back(jump(*fall, branch, false));
          return out;
        }
        cur = *fall;
        continue;
      }

      // The taken edge leaves the function. Only the statement can say where
      // it goes -- an address is not a block -- so it stays and the walk goes
      // on at the fallthrough.
      if (!taken) {
        emit_statements(out, cur, nullptr);
        mark_emitted(cur);
        cur = *fall;
        continue;
      }

      // Both edges to the same block: the branch decides nothing.
      if (*taken == *fall) {
        emit_statements(out, cur, branch);
        mark_emitted(cur);
        cur = *fall;
        continue;
      }

      // The fallthrough is where we are headed, so it is the else side and the
      // taken edge is the arm. No negating: `if (cond) goto taken` already
      // reads as the condition for taking it.
      if (follow && *fall == *follow) {
        emit_statements(out, cur, branch);
        mark_emitted(cur);

        Shape node;
        node.kind = ShapeKind::If;
        node.block = cur;
        node.statement = branch;
        node.body = region(*taken, follow);
        out.push_back(std::move(node));

        // Both edges of the branch end at the follow -- the arm by running out,
        // the fall by never being taken -- so control is there.
        arrived(out, follow);
        return out;
      }

      // The taken edge is where we are headed: an early way out of the region,
      // and the fallthrough carries on.
      if (follow && *taken == *follow) {
        emit_statements(out, cur, branch);
        mark_emitted(cur);
        out.push_back(jump(*follow, branch, true));
        cur = *fall;
        continue;
      }

      // A real join: the immediate postdominator of the branch, when it is
      // neither arm and the arms stay apart. `ipdom` is absent when the branch
      // leaves the function on every path, which is the two-return case and
      // has no join to continue at.
      const std::optional<BlockId> join = pd_.ipdom(cur);
      if (join && *join != *taken && *join != *fall &&
          arms_apart(*join, *taken, *fall)) {
        emit_statements(out, cur, branch);
        mark_emitted(cur);

        Shape node;
        node.kind = ShapeKind::If;
        node.block = cur;
        node.statement = branch;
        node.conditional = true;
        node.body = region(*taken, join);
        node.otherwise = region(*fall, join);
        out.push_back(std::move(node));

        cur = *join;
        continue;
      }

      // No shape to show: say where the taken edge goes and carry on with the
      // fallthrough.
      emit_statements(out, cur, branch);
      mark_emitted(cur);
      out.push_back(jump(*taken, branch, true));
      cur = *fall;
    }
  }

  // Every block a `goto` names. Walked over the finished tree rather than
  // collected during it, because a jump to a block printed *earlier* is a
  // backwards goto and the label was already printed there.
  //
  // `inner` is the loop this part is printed inside, carried down so a jump can
  // be told from a `break` and a `continue` -- neither of which names a block,
  // and both of which would otherwise leave a label behind for nothing.
  void collect(const Shape &shape, std::set<BlockId> &labels,
               const Shape *inner) const {
    if (shape.kind == ShapeKind::Jump &&
        jump_word(shape.block, inner) == JumpWord::Goto)
      labels.insert(shape.block);

    const Shape *inside = shape.kind == ShapeKind::Loop ? &shape : inner;
    for (const Shape &part : shape.body)
      collect(part, labels, inside);
    for (const Shape &part : shape.otherwise)
      collect(part, labels, inside);
  }

  const SsaFunction &fn_;
  const Cfg &cfg_;
  const Dominance &dom_;
  PostDom pd_;
  Loops loops_;

  std::map<BlockId, const HilBlock *> blocks_;
  std::vector<bool> emitted_;

  // The loops being walked through, innermost last, and where each of their
  // bodies was told control leaves. A stack rather than a set because the
  // innermost one is the one a `break` means, and a `break` is the question.
  std::vector<const Loop *> inside_;
  std::vector<std::optional<BlockId>> loop_follow_;

  // Blocks the sweep printed, which nothing jumps to but which need a label
  // anyway: at the top level there is nothing to fall in from.
  std::set<BlockId> forced_;
};

} // namespace

HilShapes structure(const Hil &hil, const SsaFunction &fn) {
  return Walk(hil, fn).run();
}

} // namespace ddd
