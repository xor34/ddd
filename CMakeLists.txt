cmake_minimum_required(VERSION 3.16)

# Detect whether we're the top-level project (built standalone) or being
# pulled in via add_subdirectory() from a parent project.
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  set(SLEIGH_POC_STANDALONE ON)
else()
  set(SLEIGH_POC_STANDALONE OFF)
endif()

if(SLEIGH_POC_STANDALONE)
  project(sleigh_poc CXX)
endif()

option(SLEIGH_POC_BUILD_TOOLS
  "Build the sleigh_compile and sleigh_poc executables (off if you only want the 'sla' library target)"
  ${SLEIGH_POC_STANDALONE})

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(SLEIGH_POC_STANDALONE AND NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()


# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------

find_package(ZLIB REQUIRED)
find_package(absl REQUIRED)


set(SLEIGH_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/sleigh)


# ---------------------------------------------------------------------------
# sla: SLEIGH runtime library
# ---------------------------------------------------------------------------

set(LIBSLA_SOURCES

  # CORE
  ${SLEIGH_DIR}/xml.cc
  ${SLEIGH_DIR}/marshal.cc
  ${SLEIGH_DIR}/space.cc
  ${SLEIGH_DIR}/float.cc
  ${SLEIGH_DIR}/address.cc
  ${SLEIGH_DIR}/pcoderaw.cc
  ${SLEIGH_DIR}/translate.cc
  ${SLEIGH_DIR}/opcodes.cc
  ${SLEIGH_DIR}/globalcontext.cc

  # SLEIGH
  ${SLEIGH_DIR}/sleigh.cc
  ${SLEIGH_DIR}/pcodeparse.cc
  ${SLEIGH_DIR}/pcodecompile.cc
  ${SLEIGH_DIR}/sleighbase.cc
  ${SLEIGH_DIR}/slghsymbol.cc
  ${SLEIGH_DIR}/slghpatexpress.cc
  ${SLEIGH_DIR}/slghpattern.cc
  ${SLEIGH_DIR}/semantics.cc
  ${SLEIGH_DIR}/context.cc
  ${SLEIGH_DIR}/slaformat.cc
  ${SLEIGH_DIR}/compression.cc
  ${SLEIGH_DIR}/filemanage.cc

  # runtime pieces
  ${SLEIGH_DIR}/loadimage.cc
  ${SLEIGH_DIR}/memstate.cc
  ${SLEIGH_DIR}/emulate.cc
  ${SLEIGH_DIR}/opbehavior.cc
)


add_library(sla STATIC ${LIBSLA_SOURCES})

add_library(sla::sla ALIAS sla)


target_include_directories(sla
  PUBLIC
    $<BUILD_INTERFACE:${SLEIGH_DIR}>
)


target_link_libraries(sla
  PUBLIC
    ZLIB::ZLIB
)


target_compile_features(sla
  PUBLIC
    cxx_std_17
)


target_compile_options(sla
  PRIVATE
    -Wno-sign-compare
    -Wno-unused-parameter
)



# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

if(SLEIGH_POC_BUILD_TOOLS)


  # -------------------------------------------------------------------------
  # sleigh_compile
  # -------------------------------------------------------------------------

  set(SLEIGH_COMPILER_SOURCES
    ${LIBSLA_SOURCES}

    ${SLEIGH_DIR}/slgh_compile.cc
    ${SLEIGH_DIR}/slghparse.cc
    ${SLEIGH_DIR}/slghscan.cc
  )


  list(REMOVE_ITEM SLEIGH_COMPILER_SOURCES

    ${SLEIGH_DIR}/loadimage.cc
    ${SLEIGH_DIR}/memstate.cc
    ${SLEIGH_DIR}/emulate.cc
    ${SLEIGH_DIR}/opbehavior.cc

  )


  add_executable(
    sleigh_compile
    ${SLEIGH_COMPILER_SOURCES}
  )


  target_include_directories(
    sleigh_compile
    PRIVATE
      ${SLEIGH_DIR}
  )


  target_link_libraries(
    sleigh_compile
    PRIVATE
      ZLIB::ZLIB
  )


  target_compile_options(
    sleigh_compile
    PRIVATE
      -Wno-sign-compare
      -Wno-unused-parameter
  )



  # -------------------------------------------------------------------------
  # sleigh_poc
  # -------------------------------------------------------------------------

  add_executable(
    sleigh_poc
    src/main.cc
  )


  target_link_libraries(
    sleigh_poc
    PRIVATE

      sla::sla

      # Abseil
      absl::flags
      absl::flags_parse
      absl::strings
  )


endif()

