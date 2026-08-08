#include "elf.h"

#include <algorithm>
#include <cstdlib>
#include <cxxabi.h>
#include <sstream>

namespace ddd {
namespace {

constexpr uint16_t ET_REL = 1;

constexpr uint32_t PT_LOAD = 1;
constexpr uint32_t PF_X = 1;

constexpr uint32_t SHT_REL = 9;
constexpr uint32_t SHT_RELA = 4;
constexpr uint32_t SHT_SYMTAB = 2;
constexpr uint32_t SHT_DYNSYM = 11;
constexpr uint64_t SHF_ALLOC = 2;
constexpr uint64_t SHF_EXECINSTR = 4;

constexpr uint8_t STT_FUNC = 2;

// Bounds-checked little/big endian reader. Every field in the file goes
// through this, so a truncated or hostile header fails a read rather than
// running off the end.
class Reader {
public:
  Reader(const std::vector<uint8_t> &bytes, bool big_endian)
      : bytes_(bytes), big_endian_(big_endian) {}

  bool ok() const { return ok_; }

  uint64_t at(size_t offset, unsigned size) {
    if (size == 0 || size > 8 || offset > bytes_.size() || bytes_.size() - offset < size) {
      ok_ = false;
      return 0;
    }

    uint64_t value = 0;
    if (big_endian_) {
      for (unsigned i = 0; i < size; ++i) value = (value << 8) | bytes_[offset + i];
    } else {
      for (unsigned i = size; i-- > 0;) value = (value << 8) | bytes_[offset + i];
    }
    return value;
  }

  // A NUL-terminated name out of a string table.
  std::string string_at(size_t table, size_t table_size, uint64_t index) {
    if (index >= table_size || table > bytes_.size() || bytes_.size() - table < table_size)
      return {};

    std::string text;
    for (size_t i = table + index; i < table + table_size && bytes_[i] != 0; ++i)
      text.push_back(static_cast<char>(bytes_[i]));
    return text;
  }

private:
  const std::vector<uint8_t> &bytes_;
  bool big_endian_ = false;
  bool ok_ = true;
};

// e_machine, plus endianness and word size, to a spec in specs/.
//
// Ghidra ships several variants per architecture; these pick the plain one,
// which decodes the common subset. A --region overrides it when the file needs
// a specific variant.
std::string spec_for(uint16_t machine, bool is64, bool big_endian) {
  switch (machine) {
  case 0x03: return "x86";                              // EM_386
  case 0x3e: return "x86-64";                           // EM_X86_64
  case 0x28: return big_endian ? "ARM7_be" : "ARM7_le"; // EM_ARM
  case 0xb7: return big_endian ? "AARCH64BE" : "AARCH64";
  case 0x08: // EM_MIPS
    if (is64) return big_endian ? "mips64be" : "mips64le";
    return big_endian ? "mips32be" : "mips32le";
  case 0x14: return big_endian ? "ppc_32_be" : "ppc_32_le";
  case 0x15: return big_endian ? "ppc_64_be" : "ppc_64_le";
  default: return {};
  }
}

const char *machine_name(uint16_t machine) {
  switch (machine) {
  case 0x03: return "i386";
  case 0x3e: return "x86-64";
  case 0x28: return "ARM";
  case 0xb7: return "AArch64";
  case 0x08: return "MIPS";
  case 0x14: return "PowerPC";
  case 0x15: return "PowerPC64";
  case 0xf3: return "RISC-V";
  default: return "unknown";
  }
}

// `_ZN6ghidraL7run_xmlERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE...`
// is not a name a person can read, and leaving the reader to demangle it in
// their head is the sort of thing that makes output feel like a debug dump.
//
// The parameter list goes too: it is usually longer than everything else on
// the line and says little at a call site. `ghidra::run_xml` is the useful
// part.
std::string demangle(const std::string &name) {
  if (name.size() < 3 || name[0] != '_' || name[1] != 'Z') return name;

  int status = 0;
  char *readable = abi::__cxa_demangle(name.c_str(), nullptr, nullptr, &status);
  if (status != 0 || readable == nullptr) {
    std::free(readable);
    return name;
  }

  std::string text(readable);
  std::free(readable);

  // Truncate at the argument list, ignoring parentheses inside template
  // arguments.
  int depth = 0;
  for (size_t i = 0; i < text.size(); ++i) {
    if (text[i] == '<') ++depth;
    else if (text[i] == '>') --depth;
    else if (text[i] == '(' && depth == 0) {
      text.resize(i);
      break;
    }
  }

  return text.empty() ? name : text;
}

struct Section {
  std::string name;
  uint32_t type = 0;
  uint64_t flags = 0;
  uint64_t addr = 0;
  uint64_t offset = 0;
  uint64_t size = 0;
  uint32_t link = 0;
  uint64_t entsize = 0;
  uint32_t name_index = 0;
};

std::vector<Section> read_sections(Reader &reader, const ElfInfo &info, uint64_t shoff,
                                   uint16_t shentsize, uint16_t shnum) {
  std::vector<Section> sections;
  const bool w = info.is64;

  for (uint16_t i = 0; i < shnum; ++i) {
    const size_t base = static_cast<size_t>(shoff) + static_cast<size_t>(i) * shentsize;

    Section section;
    section.name_index = static_cast<uint32_t>(reader.at(base + 0, 4));
    section.type = static_cast<uint32_t>(reader.at(base + 4, 4));
    section.flags = reader.at(base + 8, w ? 8 : 4);
    section.addr = reader.at(base + (w ? 16 : 12), w ? 8 : 4);
    section.offset = reader.at(base + (w ? 24 : 16), w ? 8 : 4);
    section.size = reader.at(base + (w ? 32 : 20), w ? 8 : 4);
    section.link = static_cast<uint32_t>(reader.at(base + (w ? 40 : 24), 4));
    section.entsize = reader.at(base + (w ? 56 : 36), w ? 8 : 4);
    if (!reader.ok()) break;

    sections.push_back(section);
  }

  return sections;
}

const Section *find_section(const std::vector<Section> &sections, const std::string &name) {
  for (const Section &section : sections)
    if (section.name == name) return &section;
  return nullptr;
}

// Names the PLT stubs from the relocations that fill them in.
//
// A call to an imported function does not go to the function -- it goes to a
// stub that jumps through a GOT slot the loader writes. Left alone, every
// call into a shared library reads as `call 0x400890`, which is the single
// most common unnamed thing in a dynamically linked binary.
//
// .rela.plt gives (GOT slot -> dynamic symbol) in stub order, so entry i
// belongs to stub i. Where the stubs live depends on the layout: with
// indirect-branch tracking the call sites target .plt.sec, which has no
// reserved first entry; the classic .plt reserves entry 0 for the resolver.
void read_plt(Reader &reader, ElfInfo &info, const std::vector<Section> &sections) {
  const Section *relocations = find_section(sections, ".rela.plt");
  bool rela = true;
  if (relocations == nullptr) {
    relocations = find_section(sections, ".rel.plt");
    rela = false;
  }
  if (relocations == nullptr) return;

  // Calls go to .plt.sec when it exists, and it has no reserved entry.
  const Section *plt = find_section(sections, ".plt.sec");
  uint64_t first_stub = 0;
  if (plt != nullptr) {
    first_stub = 0;
  } else {
    plt = find_section(sections, ".plt");
    first_stub = 1;
  }
  if (plt == nullptr || plt->size == 0) return;

  const uint64_t stub_size = plt->entsize != 0 ? plt->entsize : 16;
  if (relocations->link >= sections.size()) return;

  const Section &dynsym = sections[relocations->link];
  if (dynsym.link >= sections.size()) return;
  const Section &dynstr = sections[dynsym.link];

  const bool w = info.is64;
  const size_t reloc_size = rela ? (w ? 24 : 12) : (w ? 16 : 8);
  const size_t symbol_size = w ? 24 : 16;
  const uint64_t count = relocations->entsize != 0 ? relocations->size / relocations->entsize
                                                   : relocations->size / reloc_size;

  for (uint64_t i = 0; i < count; ++i) {
    const size_t base = static_cast<size_t>(relocations->offset) + static_cast<size_t>(i) * reloc_size;

    const uint64_t r_info = reader.at(base + (w ? 8 : 4), w ? 8 : 4);
    if (!reader.ok()) return;

    const uint64_t symbol_index = w ? (r_info >> 32) : (r_info >> 8);
    const size_t symbol = static_cast<size_t>(dynsym.offset) +
                          static_cast<size_t>(symbol_index) * symbol_size;

    const uint32_t name_index = static_cast<uint32_t>(reader.at(symbol, 4));
    if (!reader.ok()) return;

    std::string name = reader.string_at(static_cast<size_t>(dynstr.offset),
                                        static_cast<size_t>(dynstr.size), name_index);
    if (name.empty()) continue;

    // Version suffixes belong to the symbol table, not to a call site.
    const size_t at = name.find('@');
    if (at != std::string::npos) name.resize(at);

    const uint64_t stub = plt->addr + (i + first_stub) * stub_size;
    if (stub >= plt->addr + plt->size) continue;

    ElfRange extent;
    extent.begin = stub;
    extent.end = stub + stub_size;
    extent.name = name + "@plt";
    extent.executable = true;

    const std::string readable = demangle(name) + "@plt";
    extent.name = readable;

    info.symbols.emplace(stub, readable);
    info.functions.emplace(name + "@plt", extent);
    if (readable != name + "@plt") info.functions.emplace(readable, extent);
  }
}

void read_symbols(Reader &reader, ElfInfo &info, const std::vector<Section> &sections) {
  const bool w = info.is64;
  const size_t entry_size = w ? 24 : 16;

  for (const Section &section : sections) {
    if (section.type != SHT_SYMTAB && section.type != SHT_DYNSYM) continue;
    if (section.link >= sections.size()) continue;

    const Section &strings = sections[section.link];
    const uint64_t count = section.entsize != 0 ? section.size / section.entsize
                                                : section.size / entry_size;

    for (uint64_t i = 0; i < count; ++i) {
      const size_t base = static_cast<size_t>(section.offset) + static_cast<size_t>(i) * entry_size;

      const uint32_t name_index = static_cast<uint32_t>(reader.at(base, 4));
      const uint8_t sym_info = static_cast<uint8_t>(reader.at(base + (w ? 4 : 12), 1));
      const uint64_t value = reader.at(base + (w ? 8 : 4), w ? 8 : 4);
      const uint64_t size = reader.at(base + (w ? 16 : 8), w ? 8 : 4);
      if (!reader.ok()) return;

      // Only functions: data symbols would name addresses the disassembler is
      // never going to land on.
      if ((sym_info & 0xf) != STT_FUNC || value == 0) continue;

      std::string name = reader.string_at(static_cast<size_t>(strings.offset),
                                          static_cast<size_t>(strings.size), name_index);
      if (name.empty()) continue;

      const std::string readable = demangle(name);

      if (size != 0) {
        ElfRange extent;
        extent.begin = value;
        extent.end = value + size;
        extent.name = readable;
        extent.executable = true;

        // Both spellings select the function: the mangled one is what a tool
        // prints, the readable one is what a person types.
        info.functions.emplace(name, extent);
        if (readable != name) info.functions.emplace(readable, extent);
      }
      info.symbols.emplace(value, readable);
    }
  }
}

} // namespace

bool looks_like_elf(const std::vector<uint8_t> &file) {
  return file.size() >= 4 && file[0] == 0x7f && file[1] == 'E' && file[2] == 'L' &&
         file[3] == 'F';
}

ElfInfo parse_elf(const std::vector<uint8_t> &file) {
  ElfInfo info;

  if (!looks_like_elf(file)) {
    info.error = "not an ELF file";
    return info;
  }
  if (file.size() < 0x34) {
    info.error = "truncated ELF header";
    return info;
  }

  info.is64 = file[4] == 2;
  info.big_endian = file[5] == 2;

  Reader reader(file, info.big_endian);
  const bool w = info.is64;

  info.type = static_cast<uint16_t>(reader.at(16, 2));
  info.machine = static_cast<uint16_t>(reader.at(18, 2));
  info.entry = reader.at(24, w ? 8 : 4);

  const uint64_t phoff = reader.at(w ? 32 : 28, w ? 8 : 4);
  const uint64_t shoff = reader.at(w ? 40 : 32, w ? 8 : 4);
  const uint16_t phentsize = static_cast<uint16_t>(reader.at(w ? 54 : 42, 2));
  const uint16_t phnum = static_cast<uint16_t>(reader.at(w ? 56 : 44, 2));
  const uint16_t shentsize = static_cast<uint16_t>(reader.at(w ? 58 : 46, 2));
  const uint16_t shnum = static_cast<uint16_t>(reader.at(w ? 60 : 48, 2));
  const uint16_t shstrndx = static_cast<uint16_t>(reader.at(w ? 62 : 50, 2));

  if (!reader.ok()) {
    info.error = "truncated ELF header";
    return info;
  }

  info.spec = spec_for(info.machine, info.is64, info.big_endian);

  // Program headers describe the memory image, which is what a loaded
  // executable or shared object actually looks like.
  for (uint16_t i = 0; i < phnum && phoff != 0; ++i) {
    const size_t base = static_cast<size_t>(phoff) + static_cast<size_t>(i) * phentsize;

    const uint32_t type = static_cast<uint32_t>(reader.at(base, 4));
    const uint32_t flags = static_cast<uint32_t>(reader.at(base + (w ? 4 : 24), 4));
    const uint64_t vaddr = reader.at(base + (w ? 16 : 8), w ? 8 : 4);
    const uint64_t memsz = reader.at(base + (w ? 40 : 20), w ? 8 : 4);
    if (!reader.ok()) break;
    if (type != PT_LOAD || memsz == 0) continue;

    ElfRange range;
    range.begin = vaddr;
    range.end = vaddr + memsz;
    range.executable = (flags & PF_X) != 0;
    range.name = "segment" + std::to_string(i);
    info.ranges.push_back(range);
  }

  std::vector<Section> sections;
  if (shoff != 0 && shnum != 0) {
    sections = read_sections(reader, info, shoff, shentsize, shnum);

    if (shstrndx < sections.size()) {
      const Section names = sections[shstrndx];
      for (Section &section : sections)
        section.name = reader.string_at(static_cast<size_t>(names.offset),
                                        static_cast<size_t>(names.size), section.name_index);
    }

    read_symbols(reader, info, sections);
    read_plt(reader, info, sections);
  }

  // A relocatable object has no program headers: its code has no address at
  // all, so the file offsets are the only positions there are.
  if (info.ranges.empty() && !sections.empty()) {
    const Section *strings = shstrndx < sections.size() ? &sections[shstrndx] : nullptr;

    for (const Section &section : sections) {
      if ((section.flags & SHF_ALLOC) == 0 || section.size == 0) continue;

      ElfRange range;
      range.begin = section.offset;
      range.end = section.offset + section.size;
      range.executable = (section.flags & SHF_EXECINSTR) != 0;
      range.name = strings != nullptr
                       ? reader.string_at(static_cast<size_t>(strings->offset),
                                          static_cast<size_t>(strings->size),
                                          section.name_index)
                       : "";
      if (range.name.empty()) range.name = "section";
      info.ranges.push_back(range);
    }

    // Symbol values in a .o are section-relative; without relocation the only
    // honest thing is to leave the addresses alone, which for .text at offset
    // N means they are off by N. Rather than report wrong names, drop them.
    if (info.type == ET_REL) {
      info.symbols.clear();
      info.functions.clear();
    }
  }

  if (info.ranges.empty()) {
    info.error = "no loadable content";
    return info;
  }

  info.ok = true;
  return info;
}

Image load_elf(const std::vector<uint8_t> &file, const ElfInfo &info) {
  if (!info.ok || info.ranges.empty()) return Image();

  // A relocatable object is used as it sits on disk.
  if (info.type == ET_REL) {
    Image image(0, file, info.big_endian);
    return image;
  }

  uint64_t low = info.ranges.front().begin;
  uint64_t high = info.ranges.front().end;
  for (const ElfRange &range : info.ranges) {
    low = std::min(low, range.begin);
    high = std::max(high, range.end);
  }
  if (high <= low) return Image();

  // Anything a segment does not fill -- .bss, alignment padding -- stays zero,
  // which is what it would be at runtime.
  std::vector<uint8_t> memory(static_cast<size_t>(high - low), 0);

  Reader reader(file, info.big_endian);
  const bool w = info.is64;

  const uint64_t phoff = reader.at(w ? 32 : 28, w ? 8 : 4);
  const uint16_t phentsize = static_cast<uint16_t>(reader.at(w ? 54 : 42, 2));
  const uint16_t phnum = static_cast<uint16_t>(reader.at(w ? 56 : 44, 2));

  for (uint16_t i = 0; i < phnum; ++i) {
    const size_t base = static_cast<size_t>(phoff) + static_cast<size_t>(i) * phentsize;

    const uint32_t type = static_cast<uint32_t>(reader.at(base, 4));
    const uint64_t offset = reader.at(base + (w ? 8 : 4), w ? 8 : 4);
    const uint64_t vaddr = reader.at(base + (w ? 16 : 8), w ? 8 : 4);
    const uint64_t filesz = reader.at(base + (w ? 32 : 16), w ? 8 : 4);
    if (!reader.ok() || type != PT_LOAD || filesz == 0) continue;
    if (offset > file.size() || file.size() - offset < filesz) continue;
    if (vaddr < low || vaddr - low > memory.size() || memory.size() - (vaddr - low) < filesz)
      continue;

    std::copy(file.begin() + offset, file.begin() + offset + filesz,
              memory.begin() + (vaddr - low));
  }

  return Image(low, std::move(memory), info.big_endian);
}

std::string ElfInfo::describe() const {
  std::ostringstream os;
  // Every field below is a default when the parse never happened, and
  // "ELF 32-bit LE unknown" is a confident lie about a firmware blob.
  if (!ok) return "raw image, no container recognised";

  os << "ELF " << (is64 ? "64" : "32") << "-bit " << (big_endian ? "BE" : "LE") << " "
     << machine_name(machine);
  if (!spec.empty()) os << " (spec " << spec << ")";
  os << ", entry 0x" << std::hex << entry << std::dec << ", " << ranges.size()
     << " loadable range(s)";
  if (!symbols.empty()) os << ", " << symbols.size() << " function symbol(s)";
  return os.str();
}

} // namespace ddd
