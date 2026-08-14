// main.cc -- load an image, decide what is in it, and lift the code.
//
//   sleigh_poc --sla=specs/AARCH64.sla --bytes=...
//   sleigh_poc --file=firmware.bin --extract
//   sleigh_poc --file=firmware.bin --region=0:0x400:x86-64
//   --region=0x400:0x800:riscv64
//   sleigh_poc --file=/bin/ls --ui=studio
//
// What happens between loading and printing is arranged by workflows written
// in Lua: which passes run, what an idiom means, and what the interface looks
// like. This file loads them before it resolves a single pass name, so a pass
// declared in a plugin is indistinguishable from one compiled in.
#include "annotations.h"
#include "cfg.h"
#include "elf.h"
#include "extract.h"
#include "hil.h"
#include "image.h"
#include "lua/lua_env.h"
#include "pass.h"
#include "project.h"
#include "script.h"
#include "server.h"
#include "session.h"
#include "ssa.h"
#include "target.h"

#include "error.hh"
#include "sleigh.hh"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <deque>
#include <fstream>
#include <iostream>
#include <limits>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/strings/numbers.h"
#include "absl/strings/string_view.h"

ABSL_FLAG(std::string, sla, "",
          "SLA file for the whole image (see --region for mixed images)");
ABSL_FLAG(std::string, bytes, "", "Hex bytes");
ABSL_FLAG(std::string, file, "",
          "Read the image from this file instead of --bytes");
ABSL_FLAG(uint64_t, base, 0, "Address the image is loaded at");
ABSL_FLAG(uint64_t, entry, 0,
          "Address to start disassembling from (default: --base)");
ABSL_FLAG(int, max, 100000, "Maximum instructions per region");
ABSL_FLAG(uint64_t, code_end, 0,
          "Stop disassembling here; the rest of the image is data");
ABSL_FLAG(std::vector<std::string>, ctx, {}, "Context variables NAME=VALUE");
ABSL_FLAG(std::string, abi, "",
          "Calling convention (default: guessed from the spec)");
ABSL_FLAG(std::string, sp, "",
          "Stack pointer register (default: from the calling convention)");
ABSL_FLAG(std::string, specs, "specs", "Directory to resolve spec names in");
ABSL_FLAG(std::vector<std::string>, function, {},
          "Comma-separated function names to analyse, each bounded by its "
          "symbol. Needs a container with a symbol table.");
ABSL_FLAG(bool, functions, false,
          "List the functions the container knows about, then exit");
ABSL_FLAG(int, follow, 8,
          "Also analyse up to this many functions reached from the ones asked "
          "for, by call or by function pointer. 0 analyses only what was asked "
          "for.");
ABSL_FLAG(bool, whole_segment, false,
          "Analyse entire executable segments rather than individual "
          "functions, even when symbols are available");
ABSL_FLAG(bool, raw, false,
          "Treat the file as a flat image even if it is a recognised container");

ABSL_FLAG(
    std::vector<std::string>, region, {},
    "Comma-separated BEGIN:END:SPEC[:ABI[:SP]] -- stretches of the image and "
    "how "
    "to read each. Every region is lifted with its own instruction set and "
    "calling convention, so one image can hold several. Note this is one "
    "comma-separated flag, not a repeated one.");

ABSL_FLAG(bool, extract, false,
          "Run extractors over the image and report what they find");
ABSL_FLAG(std::vector<std::string>, extractors, {},
          "Only run these extractors");
ABSL_FLAG(
    std::vector<std::string>, try_specs, {},
    "Restrict arch-detect to these specs (it tries every spec otherwise)");
ABSL_FLAG(std::string, transform, "",
          "Run the image through this script before analysing it (decryption, "
          "unpacking)");

ABSL_FLAG(bool, server, false,
          "Answer command lines on stdin with one line of JSON each; what the "
          "web interface talks to");
ABSL_FLAG(std::string, ui, "",
          "Open this interface. Interfaces are Lua plugins; `studio` is the "
          "window. --list_ui shows what is installed.");
ABSL_FLAG(bool, list_ui, false, "List the interfaces plugins registered");
ABSL_FLAG(std::string, script, "",
          "Run this Lua file against the loaded image instead of opening an "
          "interface. `ddd.session` is the whole API an interface has.");
ABSL_FLAG(std::string, lua, "",
          "Where the Lua library and plugins live (default: the `lua` "
          "directory found beside the binary or above the working directory, "
          "or $DDD_LUA)");
ABSL_FLAG(bool, plugins, true, "Load the plugins under <lua>/plugins");
ABSL_FLAG(std::string, project, "",
          "Where to keep names and comments (default: <file>.ddd)");
ABSL_FLAG(bool, show_machine_state, false,
          "Show stack-pointer updates and the return-address push a call "
          "performs, which the high-level listing hides");
ABSL_FLAG(bool, disasm, false, "Print disassembly before lifting");
ABSL_FLAG(bool, cfg, false, "Print the raw p-code CFG before lifting");
ABSL_FLAG(bool, list_passes, false,
          "List the registered passes and extractors, then exit");
ABSL_FLAG(std::vector<std::string>, passes, {},
          "Passes to run over each region, overriding the pipeline the "
          "workflow declares. End it in `hil` for the readable expression "
          "form, or `print-ssa` for one line per p-code op. py:<path> runs an "
          "external script.");
ABSL_FLAG(std::string, pipeline, "default",
          "Which pipeline a workflow declared to run (--list_passes shows the "
          "passes; the pipelines are in lua/plugins)");

namespace {

class AssemblyPrinter final : public ghidra::AssemblyEmit {
public:
  void dump(const ghidra::Address &addr, const std::string &mnem,
            const std::string &body) override {
    std::cout << "0x" << std::hex << addr.getOffset() << std::dec << ":\t"
              << mnem << ' ' << body << '\n';
  }
};

std::vector<uint8_t> parse_hex(absl::string_view input) {
  std::string clean;
  for (char c : input)
    if (std::isxdigit(static_cast<unsigned char>(c)))
      clean.push_back(c);
  if (clean.size() & 1)
    clean.pop_back();

  std::vector<uint8_t> result;
  result.reserve(clean.size() / 2);

  for (size_t i = 0; i < clean.size(); i += 2) {
    uint32_t value;
    if (!absl::SimpleHexAtoi(absl::string_view(clean).substr(i, 2), &value))
      continue;
    result.push_back(static_cast<uint8_t>(value));
  }

  return result;
}

std::vector<uint8_t> read_file(const std::string &path, bool &ok) {
  std::ifstream file(path, std::ios::binary);
  if (!file) {
    std::cerr << "cannot read " << path << '\n';
    ok = false;
    return {};
  }
  ok = true;
  return std::vector<uint8_t>(std::istreambuf_iterator<char>(file),
                              std::istreambuf_iterator<char>());
}

// A bare spec name resolves in the specs directory; a path is taken as given.
std::string resolve_spec(const std::string &spec, const std::string &spec_dir) {
  if (spec.size() >= 4 && spec.compare(spec.size() - 4, 4, ".sla") == 0)
    return spec;
  return spec_dir + "/" + spec + ".sla";
}

// ---- Lua ----------------------------------------------------------------

// Which interface was asked for, if any.
std::string wanted_ui() { return absl::GetFlag(FLAGS_ui); }

// Whether something is driving the session rather than printing one listing.
// All three want the whole image available to navigate, not the one function
// the batch path would have picked.
bool driving_a_session() {
  return !wanted_ui().empty() || !absl::GetFlag(FLAGS_script).empty() ||
         absl::GetFlag(FLAGS_server);
}

// The passes to run: what --passes says, or the pipeline the workflow declared.
//
// The order is a decision about how to read a binary -- everything that
// annotates has to run before whatever renders, and the naming passes after the
// analyses they overrule -- so it is declared in Lua beside the passes rather
// than duplicated as a default in this file.
std::vector<std::string> resolve_passes() {
  std::vector<std::string> passes = absl::GetFlag(FLAGS_passes);
  if (!passes.empty())
    return passes;

  passes = ddd::LuaEnv::instance().pipeline(absl::GetFlag(FLAGS_pipeline));
  if (passes.empty())
    std::cerr << "no pipeline called " << absl::GetFlag(FLAGS_pipeline)
              << "; --passes=a,b,c to say what to run\n";
  return passes;
}

// Starts the interpreter and loads the plugins. Everything this tool does
// above the engines is declared in there, so it happens before flags naming
// passes are resolved and before --list_passes prints anything.
//
// Diagnostics go to stderr: stdout may be carrying the protocol.
bool start_lua() {
  if (!absl::GetFlag(FLAGS_plugins))
    return true;

  std::string root = absl::GetFlag(FLAGS_lua);
  if (root.empty())
    root = ddd::default_lua_root();

  if (root.empty()) {
    std::cerr << "no lua directory found; --lua=DIR, or set DDD_LUA. The "
                 "passes and interfaces that live there will be missing.\n";
    return false;
  }

  ddd::LuaEnv &env = ddd::LuaEnv::instance();
  env.set_default_passes(absl::GetFlag(FLAGS_passes));

  std::string error;
  if (!env.load_plugins(root, error)) {
    std::cerr << error << "\n";
    return false;
  }
  return true;
}

int list_ui() {
  std::cout << "interfaces:\n";
  for (const ddd::UiEntry &entry : ddd::UiRegistry::instance().entries()) {
    std::cout << "  " << entry.name << "\t" << entry.description;
    if (!entry.workflow.empty())
      std::cout << "  (" << entry.workflow << ")";
    std::cout << "\n";
  }
  return 0;
}

// ---- listing what is registered -----------------------------------------

int list_functions(const ddd::ElfInfo &elf) {
  // A C++ function is registered under both its mangled and its demangled
  // spelling so either selects it, but listing both would double the output
  // and show the unreadable one for no reason.
  int shown = 0;
  for (const auto &entry : elf.functions) {
    if (entry.first != entry.second.name)
      continue;

    std::cout << "  0x" << std::hex << entry.second.begin << std::dec << "  "
              << (entry.second.end - entry.second.begin) << "\t" << entry.first
              << "\n";
    ++shown;
  }
  std::cout << shown << " function(s)\n";
  return 0;
}

int list_passes() {
  std::cout << "passes:\n";
  for (const ddd::PassRegistry::Entry &entry :
       ddd::PassRegistry::instance().entries())
    std::cout << "  " << entry.name << "\t" << entry.description << '\n';
  std::cout << "  py:<path>\trun an external script pass\n";

  std::cout << "extractors:\n";
  for (const ddd::ExtractorRegistry::Entry &entry :
       ddd::ExtractorRegistry::instance().entries())
    std::cout << "  " << entry.name << "\t" << entry.description << '\n';
  return 0;
}

void print_disassembly(ghidra::Sleigh &translator, uint64_t begin, uint64_t end,
                       int max) {
  AssemblyPrinter printer;
  ghidra::AddrSpace *code = translator.getDefaultCodeSpace();
  ghidra::Address addr(code, begin);
  ghidra::Address stop(code, end);

  for (int count = 0; addr < stop && count < max; ++count) {
    ghidra::int4 length = 1;
    try {
      length = translator.printAssembly(printer, addr);
    } catch (ghidra::LowlevelError &error) {
      std::cout << "0x" << std::hex << addr.getOffset() << std::dec << ":\t?? ("
                << error.explain << ")\n";
    }
    addr = addr + (length > 0 ? length : 1);
  }
}

int run_extractors(const ddd::Image &image) {
  ddd::ExtractContext ctx;
  ctx.spec_dir = absl::GetFlag(FLAGS_specs);
  ctx.candidate_specs = absl::GetFlag(FLAGS_try_specs);
  ctx.out = &std::cout;
  ctx.verbose = true;

  std::vector<ddd::Finding> findings =
      ddd::extract(image, ctx, absl::GetFlag(FLAGS_extractors));

  std::cout << "\n" << findings.size() << " finding(s)\n";
  for (const ddd::Finding &finding : findings)
    std::cout << "  " << ddd::to_string(finding) << '\n';
  return 0;
}

// ---- the batch listing --------------------------------------------------

// Which stretches of an ELF to lift.
//
// An executable segment is not a function -- it is every function in the
// binary laid end to end. Sweeping one linearly from the entry point produces
// a single "function" containing all of them, which is what happens without
// this. When the symbol table says where the functions are, use it.
//
// Returns empty (having explained why) when there is nothing to do.
std::vector<ddd::ElfRange> choose_ranges(ddd::ElfInfo &elf) {
  std::vector<ddd::ElfRange> executable_ranges;
  for (const ddd::ElfRange &range : elf.ranges)
    if (range.executable)
      executable_ranges.push_back(range);

  // An interface chooses functions as it goes; all it needs from here is
  // somewhere to hang the target, and none of the explaining.
  if (driving_a_session())
    return executable_ranges;

  const std::vector<std::string> wanted = absl::GetFlag(FLAGS_function);

  if (!wanted.empty()) {
    std::vector<ddd::ElfRange> chosen;
    for (const std::string &name : wanted) {
      auto it = elf.functions.find(name);
      if (it == elf.functions.end()) {
        std::cerr << "no sized function symbol named " << name
                  << " (--functions lists them)\n";
        return {};
      }
      chosen.push_back(it->second);
    }
    elf.entry = chosen.front().begin;
    return chosen;
  }

  const std::vector<ddd::ElfRange> &executable = executable_ranges;

  if (absl::GetFlag(FLAGS_whole_segment) || elf.functions.empty()) {
    if (executable.empty())
      std::cerr << "ELF has no executable range to analyse\n";
    return executable;
  }

  // No function named: the one execution starts in is the sensible default,
  // and the rest are a --function away.
  for (const auto &entry : elf.functions) {
    const ddd::ElfRange &range = entry.second;
    if (elf.entry < range.begin || elf.entry >= range.end)
      continue;

    std::cerr << elf.functions.size() << " functions; analysing " << entry.first
              << " at the entry point. --function=NAME for another, --functions "
                 "to list them, --whole_segment for the lot.\n";
    return {range};
  }

  std::cerr << elf.functions.size()
            << " functions, none containing the entry point; analysing the "
               "whole segment. --function=NAME picks one.\n";
  return executable;
}

// Addresses this code refers to that are the start of a known function:
// direct call destinations, and constants that land on one -- which is how a
// function pointer is passed.
//
// PLT stubs are skipped: a stub is three instructions of jump, and following
// every one of them would spend the whole budget on trampolines.
std::vector<uint64_t>
referenced_functions(const ddd::Cfg &cfg,
                     const std::map<uint64_t, const ddd::ElfRange *> &functions) {
  std::vector<uint64_t> found;

  auto consider = [&](uint64_t address) {
    auto it = functions.find(address);
    if (it == functions.end())
      return;
    if (address >= cfg.code_begin && address < cfg.code_end)
      return; // ourselves

    const std::string &name = it->second->name;
    if (name.size() > 4 && name.compare(name.size() - 4, 4, "@plt") == 0)
      return;
    found.push_back(address);
  };

  for (const ddd::BasicBlock &block : cfg.blocks) {
    for (const ddd::PcodeOp &op : block.ops) {
      if (op.opc == ghidra::CPUI_CALL && !op.inputs.empty())
        consider(op.inputs[0].offset);

      for (const ddd::VarnodeData &in : op.inputs)
        if (ddd::is_constant(in))
          consider(in.offset);
    }
  }

  return found;
}

// Each region gets a fresh Annotations: what one region's analysis concluded
// says nothing about another's.
void analyse(const ddd::Lifted &lifted, const ddd::Image &image,
             const ddd::PassManager &manager,
             const std::map<uint64_t, std::string> *symbols,
             const ddd::Project *project) {
  const ddd::Region &region = lifted.region;
  std::cout << "\n=== region 0x" << std::hex << region.begin << "-0x"
            << region.end << std::dec << "  " << region.name << " ===\n";

  if (absl::GetFlag(FLAGS_cfg))
    std::cout << ddd::to_string(lifted.cfg);

  // Phi placement is pruned by liveness, so it has to be told what the caller
  // still reads -- otherwise the function's own result looks dead at the exit.
  ddd::SsaOptions options;
  options.live_at_exit =
      ddd::observable_storage(region.target->abi, region.target->translator);

  ddd::SsaFunction fn = ddd::build_ssa(lifted.cfg, options);
  ddd::Annotations annotations;

  ddd::PassContext ctx;
  ctx.target = region.target;
  ctx.image = &image;
  ctx.annotations = &annotations;
  ctx.symbols = symbols;
  ctx.out = &std::cout;
  ctx.verbose = true;
  ctx.show_machine_state = absl::GetFlag(FLAGS_show_machine_state);
  ctx.project = project;
  manager.run(fn, ctx);
}

} // namespace

int main(int argc, char **argv) {
  absl::ParseCommandLine(argc, argv);

  // Before anything that names a pass or an interface: both registries are
  // filled by the plugins.
  start_lua();

  if (absl::GetFlag(FLAGS_list_passes))
    return list_passes();
  if (absl::GetFlag(FLAGS_list_ui))
    return list_ui();

  std::vector<uint8_t> bytes;
  const std::string path = absl::GetFlag(FLAGS_file);
  if (!path.empty()) {
    bool ok = false;
    bytes = read_file(path, ok);
    if (!ok)
      return 1;
  } else {
    bytes = parse_hex(absl::GetFlag(FLAGS_bytes));
  }

  if (bytes.empty()) {
    std::cerr
        << "usage: --sla=file.sla (--bytes=hex | --file=path) [--base=addr]\n"
           "       --region=BEGIN:END:SPEC repeated, for images with more than "
           "one\n"
           "       --extract to find out what is in an unknown image\n"
           "       --ui=studio to open it in a window\n";
    return 2;
  }

  // A transform runs before anything looks at the bytes, so the rest of the
  // pipeline analyses the decrypted or unpacked image without knowing that is
  // what happened.
  const std::string transform = absl::GetFlag(FLAGS_transform);
  if (!transform.empty()) {
    ddd::ScriptResult result =
        ddd::run_script(ddd::interpreter_for(transform), bytes);
    if (!result.ok) {
      std::cerr << "transform " << transform << " failed: " << result.error
                << '\n';
      return 1;
    }
    // Reporting, not an error: goes where the rest of the tool's output goes.
    std::cout << "transform " << transform << ": " << bytes.size() << " -> "
              << result.output.size() << " bytes\n";
    bytes = std::move(result.output);
  }

  ghidra::AttributeId::initialize();
  ghidra::ElementId::initialize();

  uint64_t base = absl::GetFlag(FLAGS_base);

  // A container knows what a flat image can only be told: where the code is,
  // what address it loads at, which architecture it is for, and where
  // execution starts. Ask it before falling back to the flags.
  ddd::ElfInfo elf;
  if (!absl::GetFlag(FLAGS_raw) && ddd::looks_like_elf(bytes)) {
    elf = ddd::parse_elf(bytes);
    if (!elf.ok) {
      std::cerr << "ELF: " << elf.error << " (use --raw to read it flat)\n";
      return 1;
    }
    // In server mode stdout carries the protocol and nothing else.
    (absl::GetFlag(FLAGS_server) ? std::cerr : std::cout) << elf.describe()
                                                          << "\n";
  }

  ddd::Image image =
      elf.ok ? ddd::load_elf(bytes, elf) : ddd::Image(base, std::move(bytes));
  if (elf.ok)
    base = image.base();

  if (absl::GetFlag(FLAGS_functions)) {
    if (!elf.ok) {
      std::cerr << "no container with a symbol table here\n";
      return 2;
    }
    return list_functions(elf);
  }

  if (absl::GetFlag(FLAGS_extract))
    return run_extractors(image);

  ddd::TargetSet targets(image);
  const std::string spec_dir = absl::GetFlag(FLAGS_specs);

  std::vector<ddd::Region> regions;
  for (const std::string &text : absl::GetFlag(FLAGS_region)) {
    ddd::Region region;
    if (!parse_region(text, targets, spec_dir, region))
      return 2;
    regions.push_back(region);
  }

  // An ELF's executable ranges are regions already, with the spec its
  // e_machine names -- so `--file=a.out` needs no other flags at all.
  if (regions.empty() && elf.ok) {
    const std::string spec =
        !absl::GetFlag(FLAGS_sla).empty() ? absl::GetFlag(FLAGS_sla) : elf.spec;
    if (spec.empty()) {
      std::cerr << "no spec known for this ELF machine; pass --sla or --region\n";
      return 2;
    }

    std::vector<ddd::ElfRange> wanted = choose_ranges(elf);
    if (wanted.empty())
      return 2;

    for (const ddd::ElfRange &range : wanted) {
      ddd::Region region;
      region.begin = range.begin;
      region.end = range.end;
      region.kind = ddd::RegionKind::Code;
      region.target = targets.acquire(
          resolve_spec(spec, spec_dir), absl::GetFlag(FLAGS_abi),
          absl::GetFlag(FLAGS_sp), absl::GetFlag(FLAGS_ctx));
      if (region.target == nullptr)
        return 1;
      region.name = range.name + " (" + region.target->name + ")";
      regions.push_back(region);
    }
  }

  // No container and no explicit regions: the whole image is one, with --sla.
  if (regions.empty()) {
    const std::string spec = absl::GetFlag(FLAGS_sla);
    if (spec.empty()) {
      std::cerr << "need --sla, or one or more --region\n";
      return 2;
    }

    ddd::Region region;
    region.begin = base;
    region.end = absl::GetFlag(FLAGS_code_end);
    if (region.end == 0 || region.end > image.limit())
      region.end = image.limit();
    region.kind = ddd::RegionKind::Code;
    // Through resolve_spec, like every other path: a bare name means a name
    // in --specs. A flat blob is exactly the case that has no container to
    // name its own architecture, so this is where --sla is most likely used.
    region.target = targets.acquire(resolve_spec(spec, spec_dir),
                                    absl::GetFlag(FLAGS_abi),
                                    absl::GetFlag(FLAGS_sp),
                                    absl::GetFlag(FLAGS_ctx));
    if (region.target == nullptr)
      return 1;
    region.name = region.target->name;
    regions.push_back(region);
  }

  image.set_big_endian(regions.front().target->translator->isBigEndian());

  // Names and comments the user chose live beside the binary, so a second run
  // starts where the first left off.
  std::string project_path = absl::GetFlag(FLAGS_project);
  if (project_path.empty() && !path.empty())
    project_path = path + ".ddd";

  const std::string ui = wanted_ui();
  const std::string script = absl::GetFlag(FLAGS_script);
  if (driving_a_session()) {
    ddd::Session session(elf, image, targets);
    session.set_regions(regions);
    session.set_passes(resolve_passes());
    session.set_spec_dir(spec_dir);
    session.set_max_instructions(absl::GetFlag(FLAGS_max));
    session.open_project(project_path);
    // stdout carries the protocol in server mode, and belongs to the interface
    // in every other: one stray line of prose corrupts either.
    if (absl::GetFlag(FLAGS_server))
      session.set_log(&std::cerr);

    if (absl::GetFlag(FLAGS_server))
      return ddd::serve(session, std::cin, std::cout);

    ddd::LuaEnv &env = ddd::LuaEnv::instance();
    env.set_session(&session);

    // A script gets exactly what an interface gets, which is the point: the
    // API is the same one, so anything the window can do can be done without
    // it -- and anything a script proves works, works there too.
    if (!script.empty()) {
      std::string failure;
      const bool ok = env.run_file(script, failure);
      if (!ok)
        std::cerr << failure << "\n";

      env.set_session(nullptr);
      session.save_project();
      return ok ? 0 : 1;
    }

    std::string error;
    if (!ddd::run_ui(env, ui, error)) {
      std::cerr << error << "\n";
      if (ddd::UiRegistry::instance().find(ui) == nullptr)
        list_ui();
      env.set_session(nullptr);
      return 1;
    }

    env.set_session(nullptr);
    session.save_project();
    return 0;
  }

  ddd::Project project;
  if (!project_path.empty())
    project.load(project_path);

  const std::vector<std::string> pipeline = resolve_passes();
  if (pipeline.empty())
    return 2;

  ddd::PassManager manager;
  for (const std::string &name : pipeline) {
    if (name.empty())
      continue;
    if (manager.add(name))
      continue;

    std::cerr << "unknown pass: " << name << '\n';
    list_passes();
    return 2;
  }

  // Sweep everything first. What the sweeps actually covered -- not what the
  // regions nominally span -- is the code range, and the rest of the image is
  // the data that data-refs resolves pointers into. A region bounded by --max
  // stops well short of its own end.
  uint64_t entry = absl::GetFlag(FLAGS_entry);
  if (entry == 0 && elf.ok && elf.entry != 0)
    entry = elf.entry;
  std::vector<std::unique_ptr<ddd::Lifted>> lifted;

  // Functions reachable from the ones asked for. A listing that mentions
  // `&main` and then never shows main is not much use, and following the
  // references is how the rest of the binary gets found -- the sweep inside a
  // function never leaves it.
  std::map<uint64_t, const ddd::ElfRange *> by_address;
  for (const auto &function : elf.functions)
    by_address.emplace(function.second.begin, &function.second);

  std::set<uint64_t> queued;
  for (const ddd::Region &region : regions)
    queued.insert(region.begin);

  int budget = absl::GetFlag(FLAGS_follow);
  std::deque<ddd::Region> pending(regions.begin(), regions.end());

  while (!pending.empty()) {
    const ddd::Region region = pending.front();
    pending.pop_front();

    if (region.kind == ddd::RegionKind::Data || region.target == nullptr)
      continue;

    // Start at the entry point when it falls inside this region; otherwise
    // sweep the region from its beginning.
    const bool has_entry = entry >= region.begin && entry < region.end;
    const uint64_t from = has_entry ? entry : region.begin;

    if (absl::GetFlag(FLAGS_disasm))
      print_disassembly(*region.target->translator, from, region.end,
                        absl::GetFlag(FLAGS_max));

    std::unique_ptr<ddd::Lifted> one =
        ddd::lift(region, from, absl::GetFlag(FLAGS_max));
    if (one == nullptr) {
      std::cout << "nothing could be disassembled in " << region.name << '\n';
      continue;
    }

    for (uint64_t target : referenced_functions(one->cfg, by_address)) {
      if (budget <= 0)
        break;
      if (!queued.insert(target).second)
        continue;

      const ddd::ElfRange &range = *by_address[target];
      ddd::Region next = region; // same target: same ISA and convention
      next.begin = range.begin;
      next.end = range.end;
      next.name = range.name + " (" + region.target->name + ")";
      pending.push_back(next);
      --budget;
    }

    lifted.push_back(std::move(one));
  }

  if (lifted.empty())
    return 1;

  uint64_t code_begin = lifted.front()->cfg.code_begin;
  uint64_t code_end = lifted.front()->cfg.code_end;
  for (const std::unique_ptr<ddd::Lifted> &one : lifted) {
    code_begin = std::min(code_begin, one->cfg.code_begin);
    code_end = std::max(code_end, one->cfg.code_end);
  }

  // When the container said which bytes are executable, believe it over the
  // sweep. Analysing one function does not make the rest of .text into data,
  // and calling a pointer to another function "data" invites data-refs to
  // read instructions as though they were a number.
  for (const ddd::ElfRange &range : elf.ranges) {
    if (!range.executable)
      continue;
    code_begin = std::min(code_begin, range.begin);
    code_end = std::max(code_end, range.end);
  }

  image.set_code_range(code_begin, code_end);

  // Symbols are the one naming in this tool that is not a guess, so they come
  // straight from the container when there was one.
  const std::map<uint64_t, std::string> *symbols =
      elf.ok ? &elf.symbols : nullptr;
  for (const std::unique_ptr<ddd::Lifted> &one : lifted)
    analyse(*one, image, manager, symbols, &project);

  return 0;
}
