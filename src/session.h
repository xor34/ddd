// session.h -- one loaded image, and everything a front end asks of it.
//
// The front ends -- the JSON server, the Lua interfaces, the batch listing --
// want the same handful of answers: what functions are in here, what does this
// one look like, what refers to that address, what is stored there, and record
// that the user renamed something. None of that is presentation, and none of it
// belongs in a `main` that also parses flags.
//
// So it lives here, and answers in structures. A front end formats them: the
// server as JSON, a Lua plugin as tables, the terminal as text. Nothing in this
// file knows which.
#pragma once

#include "elf.h"
#include "hil.h"
#include "image.h"
#include "parallel.h"
#include "pass.h"
#include "project.h"
#include "regions.h"
#include "target.h"
#include "xrefs.h"

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <ostream>
#include <string>
#include <vector>

namespace ddd {

// One region, lifted. Heap-allocated because the SsaFunction built from it
// borrows the Cfg sitting next to it.
struct Lifted {
  // By value, not by pointer: regions are discovered as the analysis follows
  // references, so there is no stable container to point into.
  Region region;
  Cfg cfg;
};

// Sweeps a region from `entry` (or its beginning) and returns what decoded, or
// null if nothing did. With an image, the sweep stops at bytes that have been
// marked as data -- which is what makes "this is not code" mean something.
//
// `disassemble` is what a listing wants and what a sweep looking for extents
// and references does not: the text costs a second decode of every
// instruction, which is half the work of the two stages that only ever ask
// where things are.
std::unique_ptr<Lifted> lift(const Region &region, uint64_t entry,
                             int max_instructions,
                             const Image *image = nullptr,
                             bool disassemble = true);

struct FunctionInfo {
  uint64_t addr = 0;
  uint64_t end = 0;
  std::string name;   // what to show: the user's rename, else the symbol
  std::string symbol; // what the container called it
};

// What to run over a function, and what to get back.
struct ListingRequest {
  std::vector<std::string> passes; // empty: the session's default pipeline
  bool tokens = true;              // also produce the tokenised form
  bool machine = false;            // show the machine bookkeeping hil hides
  bool verbose = false;            // let the passes narrate
};

struct Listing {
  bool ok = false;
  std::string error;

  std::string name;
  std::string target; // the instruction set it was read with
  uint64_t addr = 0;
  uint64_t end = 0;

  std::string text;               // the listing as printed
  std::vector<TokenBlock> blocks; // the same listing, tokenised; empty in text
                                  // mode
};

// A word of data, read as what it is rather than as sixteen bytes to a row.
struct DataItem {
  uint64_t addr = 0;
  std::string kind; // "string" or "word"
  unsigned size = 0;
  std::string label; // a symbol here, if there is one

  std::string text;      // kind == "string"
  uint64_t value = 0;    // kind == "word"
  std::string points;    // what `value` lands in: "code", "data", "string"
  std::string target;    // and what it is called, or says
  std::vector<Xref> xrefs;
};

struct DataView {
  uint64_t addr = 0;
  uint64_t end = 0;
  bool code = false;
  std::vector<DataItem> items;
};

struct HexView {
  uint64_t addr = 0;
  bool code = false;
  std::vector<uint8_t> bytes;
  // Anything readable in there, by address: it is usually why you are looking
  // at raw bytes in the first place.
  std::vector<std::pair<uint64_t, std::string>> strings;
};

class Session {
public:
  // Borrows all three; they must outlive the session.
  Session(ElfInfo &elf, Image &image, TargetSet &targets);

  // ---- what was loaded --------------------------------------------------

  const ElfInfo &elf() const { return *elf_; }
  Image &image() { return *image_; }
  const Image &image() const { return *image_; }
  std::string describe() const { return elf_->describe(); }
  uint64_t entry() const { return elf_->entry; }

  // The convention in force where new functions are lifted, if one is known.
  // An interface offering to write a prototype needs the argument registers to
  // suggest.
  const CallingConvention *abi() const {
    return prototype_.target != nullptr ? prototype_.target->abi : nullptr;
  }

  // The regions to lift out of, and the one whose target new functions are
  // read with. Set once, at startup.
  void set_regions(std::vector<Region> regions);
  const std::vector<Region> &regions() const { return regions_; }
  const Region &prototype() const { return prototype_; }

  // The pipeline a listing runs when it is not told otherwise.
  void set_passes(std::vector<std::string> passes) {
    passes_ = std::move(passes);
  }
  const std::vector<std::string> &passes() const { return passes_; }

  void set_max_instructions(int max) { max_instructions_ = max; }
  int max_instructions() const { return max_instructions_; }

  // Where progress and diagnostics go. In server mode this is stderr, because
  // stdout carries the protocol and one stray line of prose corrupts it.
  void set_log(std::ostream *log) { log_ = log; }
  std::ostream &log() const;

  // ---- naming -----------------------------------------------------------

  // Anything that names a place: a symbol, or a number in any base.
  bool resolve(const std::string &what, uint64_t &out) const;

  std::vector<FunctionInfo> functions(const std::string &pattern = {}) const;
  const ElfRange *function_at(uint64_t address) const;
  std::string function_name_at(uint64_t address) const;

  // Where the functions are in a file that does not say.
  //
  // This matters far more than it sounds. A "function" that is really the whole
  // of .text glued together is not just untidy: every analysis in the pipeline
  // is per-function, so flags written in one function reach a read in the next,
  // nothing is dead, nothing folds, and the listing degenerates into the raw
  // flag arithmetic Sleigh emits. Bounding the functions correctly is what
  // makes `if (RAX == 0x403010)` out of eleven lines of CF/OF/SF/PF.
  //
  // The evidence that survives stripping is calls: something calls a function,
  // and the entry point is one. Each start is bounded by the next, which is
  // what a linear sweep can support without a full recovery pass.
  //
  // Costs a sweep of the image the first time, and is remembered.
  void discover_functions();
  bool discovered() const { return discovered_; }

  // ---- doing it a slice at a time, on as many threads as it can -----------
  //
  // Both of the above are sweeps of the whole image, and an interface that
  // calls one has no window until it returns. Two things are done about that,
  // and they are not alternatives: the work yields, and the work is spread.
  //
  // *Yielding* is what keeps the window answering. Each call does a bounded
  // amount of work and says where it got to; a caller runs it until
  // `finished`, on an idle handler, and stays answerable in between. That is
  // still true with threads: a step fans its slice out, joins, and returns.
  //
  // *Spreading* is what makes the work finish. Both stages are a decode and
  // nothing else -- what the bytes are, what they refer to, where control flow
  // stops -- and every answer either produces is an address. Addresses are
  // integers, so the results merge whichever thread found them, in the order
  // the batch went out, which is what keeps the index and the function list
  // identical to the ones a single thread would have built.
  //
  // What is *not* threaded is everything downstream of that: building SSA and
  // running the pipeline over one function. Passes are Lua as often as C++,
  // and that is one interpreter. It is also the part that does not need it --
  // it runs per function, on the function you are looking at, and the two
  // sweeps here are what you wait for on a binary of any size.
  //
  // The cost of a thread is a copy of the decoder, since a Sleigh caches the
  // instruction it last parsed and cannot be inside two sweeps at once. Those
  // are loaded in the background (see TargetSet::warm), so the analysis starts
  // on one thread and widens as they arrive rather than stopping to load them.
  struct AnalysisStep {
    std::string stage; // "references", "functions", "done"
    uint64_t done = 0;
    uint64_t total = 0; // 0 when the total is not known yet
    bool finished = false;
    int threads = 1;    // how many the step actually ran on
  };

  // `budget` is roughly the instructions to decode in one go, per thread.
  // Smaller is smoother. It bounds how much a step does, and deliberately not
  // where the sweeps are cut: those boundaries are fixed, so that what is
  // found does not depend on who asked or on how many threads answered.
  AnalysisStep analyse_step(int budget = 20000);

  // How many threads the sweeps may use. 0 decides from the size of the image:
  // an image with little enough code in it is not worth a decoder per thread.
  // 1 keeps everything on the calling thread.
  void set_threads(int threads) { threads_ = threads; }
  int threads() const { return threads_; }

  // Says the reference index is out of date, without throwing it away: an edit
  // that changes what is code changes what refers to what, but the answers
  // that are already there are better than none while the new ones are built.
  void invalidate_index();

  // Adds one, overriding whatever discovery decided. What a plugin that knows
  // better -- a signature, a prologue scan, a person -- calls.
  void define_function(uint64_t begin, uint64_t end, std::string name);

  // ---- correcting it ----------------------------------------------------
  //
  // Everything above is inference, and inference is wrong sometimes. These are
  // how a person overrules it; all three are recorded in the project, so the
  // correction survives the next run.

  // ---- the region tree --------------------------------------------------
  //
  // Everything the image is made of, at every scale at once: the image holds
  // code and data regions, a code region holds functions, a function holds
  // blocks, a data region holds items. All the same kind of thing, so all
  // answered by one structure -- and all undefinable the same way.

  RegionTree &regions_tree() { return tree_; }
  const RegionTree &regions_tree() const { return tree_; }

  // Undefines a region at `address`: the innermost one, or `levels` steps out
  // from it. Pressing undefine twice in the same place is how you say "not
  // that one, the thing it is in".
  //
  // Returns what was undefined -- "function", "block", "data" -- or an empty
  // string if there was nothing there to undefine.
  std::string undefine_at(uint64_t address, int levels = 0);

  // Not a function. Discovery will not put it back.
  void undefine_function(uint64_t address);

  // Not code. A jump table, a string, a blob of constants -- anything the
  // sweep walked into and disassembled as instructions. Marking it stops the
  // disassembler, so saying it changes the listing rather than only a table.
  void define_data(uint64_t begin, uint64_t end);

  // The other direction: this is code, whatever was said before.
  //
  // Code is blocks. Disassembling from an address tells you where the block
  // ends -- at the branch, the call or the return -- and that is what gets
  // marked, not a function: a function is a claim about an entry point, and
  // most code is not one. Returns the extent it decoded, or 0.
  uint64_t define_code(uint64_t address);

  // This is a function: the stronger claim. The extent comes from control flow
  // the way discovery works it out, and the name from the symbol table if it
  // has one to offer, because a name someone else already wrote down beats
  // `sub_401234`. Returns the end address, or 0.
  uint64_t define_function_at(uint64_t address);

  // A NUL-terminated string at `address`: marks it as data, names it after
  // what it says, and returns its length including the terminator. Zero if
  // there is nothing readable there.
  uint64_t define_string(uint64_t address);

  // Any region at all -- a jump table, an item inside a blob, a kind this tool
  // has never heard of. Recorded, so it is still there next time.
  int define_region(uint64_t address, uint64_t size, const std::string &kind,
                    const std::string &name);

  // A stretch of the image and the instruction set to read it with. What makes
  // a flat firmware image tractable: carve it once and the carving is kept.
  // Returns false if the spec will not load.
  bool add_region(uint64_t begin, uint64_t end, const std::string &spec,
                  const std::string &abi = {},
                  const std::string &stack_pointer = {});

  // Where bare spec names are resolved, for add_region.
  void set_spec_dir(std::string dir) { spec_dir_ = std::move(dir); }
  // The specs that are actually installed, for an interface offering a choice.
  std::vector<std::string> available_specs() const;

  // Applies what the project already said: data ranges, regions, and the
  // functions it says are not functions. Called by open_project.
  void apply_project();

  // The stretch to lift at an address. A symbol gives the exact extent;
  // without one -- a flat firmware image, which is where literal pools live --
  // there is still code there, so sweep from the address to the end of its
  // region.
  bool range_at(uint64_t address, ElfRange &out) const;

  // ---- what is there ----------------------------------------------------

  Listing listing(const ElfRange &range, const ListingRequest &request = {});
  // The function containing `address`, whatever it turns out to be.
  Listing listing_at(uint64_t address, const ListingRequest &request = {});

  // Costs a full sweep of every code region, so it is built on demand and
  // kept. Everything that reports references calls it first.
  void build_xrefs();
  bool have_xrefs() const { return xrefs_ != nullptr; }
  size_t xref_count() const { return xrefs_ != nullptr ? xrefs_->size() : 0; }
  const std::vector<Xref> &xrefs_to(uint64_t address);

  DataView data(uint64_t address, uint64_t count);
  HexView hex(uint64_t address, uint64_t length);

  // Shannon entropy in bits per byte, one figure per equal slice of the image.
  //
  // What it is for is seeing the shape of a file at a glance: instructions sit
  // in the middle of the range, padding and tables at the bottom, compressed
  // or encrypted blobs at the top. A map of the whole image drawn from this
  // says where the interesting parts are before anything has been analysed.
  std::vector<double> entropy(size_t buckets) const;

  // ---- what the user decided --------------------------------------------

  Project &project() { return project_; }
  const Project &project() const { return project_; }
  const std::string &project_path() const { return project_path_; }
  void open_project(std::string path);
  bool save_project();

private:
  ElfInfo *elf_ = nullptr;
  Image *image_ = nullptr;
  TargetSet *targets_ = nullptr;

  Region prototype_;
  std::vector<Region> regions_;
  std::vector<std::string> passes_;
  int max_instructions_ = 100000;

  Project project_;
  std::string project_path_;
  std::string spec_dir_ = "specs";

  std::unique_ptr<Xrefs> xrefs_;
  std::ostream *log_ = nullptr;

  // 0 until the first threaded step decides; the pool outlives the step, since
  // the steps arrive one after another and starting threads per step would
  // cost more than a step.
  int threads_ = 0;
  std::unique_ptr<Pool> pool_;
  int announced_threads_ = 1; // what the log has been told, to say it once

  // Functions worked out rather than read out of a symbol table, by start
  // address. Empty until discover_functions() has run. Mirrored into the tree,
  // and kept because a function's extent is asked for by pointer.
  std::map<uint64_t, ElfRange> found_;
  bool discovered_ = false;

  RegionTree tree_;

  // Re-indexing after an edit builds into this one, and it is swapped in when
  // it is finished. Dropping the index instead would be correct and unusable:
  // the next question about references would rebuild the whole thing on the
  // spot, which is a sweep of the image with the window waiting on it.
  std::unique_ptr<Xrefs> pending_xrefs_;

  // Where the slice-at-a-time analysis has got to.
  size_t index_region_ = 0;   // which code region is being indexed
  uint64_t index_at_ = 0;     // and where in it
  bool indexed_ = false;
  std::vector<uint64_t> starts_; // function starts, once they are known
  size_t start_at_ = 0;

  // A region to sweep from `address`, stopping at the end of whatever
  // instruction-set region it is in.
  bool sweep_region(uint64_t address, Region &out) const;

  // Drops everything that said a stretch was not code.
  void clear_data_over(uint64_t begin, uint64_t end);

  // Splitting a data region around code defined inside it, rather than losing
  // the whole region because one part of it was corrected.
  std::vector<std::pair<uint64_t, uint64_t>> data_over(uint64_t address) const;
  void mark_data_region(uint64_t begin, uint64_t end);
  void restore_data_around(
      const std::vector<std::pair<uint64_t, uint64_t>> &ranges, uint64_t begin,
      uint64_t end);

  // The two halves of discovery, so it can be done a piece at a time.
  void collect_starts();

  // One candidate start, worked out and not yet recorded. The working out is
  // what a worker does; recording it is the caller's, in batch order, because
  // that is what the region tree and the function map are ordered by.
  struct Bounded {
    bool ok = false;
    uint64_t address = 0;
    uint64_t end = 0;
    std::string name;
  };
  Bounded bound_start(size_t index, int slot) const;

  // How many threads this step may spread over, asking for the decoders it
  // needs on the way. At least one.
  int analysis_threads();

  // `body(index, slot)` for every index below `count`, on the pool if there is
  // one. `slot` is which decoder the body may use.
  void in_parallel(size_t count,
                   const std::function<void(size_t index, int slot)> &body);

  // Where the next function starts, which is where this one has to stop.
  uint64_t next_function_after(uint64_t address, uint64_t limit) const;
};

} // namespace ddd
