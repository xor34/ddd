// elf.h -- the one container format worth teaching this tool.
//
// Everything else here works on a flat image and is told where the code is.
// An ELF already knows: which bytes are code, where they live in memory, what
// architecture they are for, where execution starts, and -- if it was not
// stripped -- what the functions are called. All of that is otherwise a guess.
//
// This is a reader, not a linker. It does not relocate, resolve, or follow
// dynamic linkage; it answers "what is in this file and where does it go".
#pragma once

#include "image.h"

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace ddd {

struct ElfRange {
  uint64_t begin = 0; // address, once loaded
  uint64_t end = 0;
  std::string name; // segment index, or section name
  bool executable = false;
};

struct ElfInfo {
  bool ok = false;
  std::string error;

  bool is64 = false;
  bool big_endian = false;
  uint16_t machine = 0;
  uint16_t type = 0; // ET_REL, ET_EXEC, ET_DYN, ...
  uint64_t entry = 0;

  // The spec this architecture wants, resolvable in the specs directory.
  // Empty when nothing here knows it.
  std::string spec;

  // Loadable ranges, in load order. For a relocatable object with no program
  // headers these come from the sections instead, addressed by file offset --
  // which is the only position a .o's code really has.
  std::vector<ElfRange> ranges;

  // Function addresses to names, from .symtab or .dynsym.
  std::map<uint64_t, std::string> symbols;

  // Name to extent, for the symbols that carried a size. This is what makes
  // analysing one function possible: a linear sweep has no idea where a
  // function ends, but the symbol table does.
  std::map<std::string, ElfRange> functions;

  std::string describe() const;
};

bool looks_like_elf(const std::vector<uint8_t> &file);

ElfInfo parse_elf(const std::vector<uint8_t> &file);

// Lays the file out the way it would be loaded: PT_LOAD segments at their
// virtual addresses, or -- for a relocatable object -- the file as it stands.
Image load_elf(const std::vector<uint8_t> &file, const ElfInfo &info);

} // namespace ddd
