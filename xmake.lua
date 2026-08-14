set_project("sleigh_poc")
    set_version("1.0.0")

    set_languages("cxx17")

    add_rules("mode.debug", "mode.release")

    if is_mode("debug") then
        set_symbols("debug")
    else
        set_optimize("fastest")
    end

    add_requires("zlib")
    add_requires("abseil")

    -- Everything above the engines is written in Lua: the readability passes,
    -- the workflows that arrange them, and the whole interface.
    --
    -- The system's shared Lua, deliberately, rather than a private static one.
    -- The interface is Lua code calling GTK through lgi, and lgi is a C module
    -- built against the distribution's liblua -- it can only load into a
    -- process that has those exact symbols in it. Statically linking our own
    -- copy would give us two Lua runtimes and no interface.
    add_requires("pkgconfig::lua", {alias = "lua"})


local sleigh_dir = "third_party/sleigh"


local core_sources = {
    "xml.cc",
    "marshal.cc",
    "space.cc",
    "float.cc",
    "address.cc",
    "pcoderaw.cc",
    "translate.cc",
    "opcodes.cc",
    "globalcontext.cc",

    "sleigh.cc",
    "pcodeparse.cc",
    "pcodecompile.cc",
    "sleighbase.cc",
    "slghsymbol.cc",
    "slghpatexpress.cc",
    "slghpattern.cc",
    "semantics.cc",
    "context.cc",
    "slaformat.cc",
    "compression.cc",
    "filemanage.cc",
}


local runtime_sources = {
    "loadimage.cc",
    "memstate.cc",
    "emulate.cc",
    "opbehavior.cc",
}


local function sleigh_sources(files)
    local result = {}

    for _, file in ipairs(files) do
        table.insert(result, path.join(sleigh_dir, file))
    end

    return result
end


target("sla")
    set_kind("static")

    add_files(
        sleigh_sources(core_sources),
        sleigh_sources(runtime_sources)
    )

    add_includedirs(
        sleigh_dir,
        { public = true }
    )

    add_packages(
        "zlib",
        { public = true }
    )

    add_cxxflags(
        "-Wno-sign-compare",
        "-Wno-unused-parameter"
    )

target("sleigh_compile")
    set_kind("binary")

    add_files(
        sleigh_sources(core_sources),
        path.join(sleigh_dir, "slgh_compile.cc"),
        path.join(sleigh_dir, "slghparse.cc"),
        path.join(sleigh_dir, "slghscan.cc")
    )

    add_includedirs(sleigh_dir)

    add_packages("zlib")

    add_cxxflags(
        "-Wno-sign-compare",
        "-Wno-unused-parameter"
    )


target("sleigh_poc")
    set_kind("binary")

    add_files(
        "src/*.cc",
        "src/*.cpp",
        "src/lua/*.cpp",
        "src/passes/*.cpp",
        "src/extractors/*.cpp"
    )

    add_deps("sla")
    add_packages("abseil", "lua")

    -- So a Lua C module loaded at runtime -- lgi, and anything else a plugin
    -- requires -- resolves the interpreter's symbols against this process.
    add_ldflags("-rdynamic", {force = true})

-- `xmake check` -- build sleigh_poc, then run the lit-style suite in test/.
-- Extra arguments go through to the runner, e.g.
--   xmake check --only=loop --commands
-- (`verbose` and `diagnosis` are xmake's own option names, hence `commands`.)
task("check")
    set_category("plugin")

    set_menu {
        usage = "xmake check [options]",
        description = "Run the tests in test/",
        options = {
            {"o", "only", "kv", nil, "Only run tests matching this regex"},
            {"c", "commands", "k", nil, "Show the commands each test ran"}
        }
    }

    on_run(function()
        import("core.base.option")
        import("core.project.project")
        import("core.project.config")

        config.load()
        os.exec("xmake build sleigh_poc")

        local argv = {
            path.join(os.projectdir(), "test", "lit-lite.py"),
            "--sleigh-poc=" .. project.target("sleigh_poc"):targetfile(),
            "--specs=" .. path.join(os.projectdir(), "specs")
        }

        if option.get("only") then
            table.insert(argv, "--filter=" .. option.get("only"))
        end
        if option.get("commands") then
            table.insert(argv, "-v")
        end

        os.execv("python3", argv)
    end)


option("processors")
    set_default("x86,AARCH64,ARM,MIPS,PowerPC")
    set_showmenu(true)
    set_description("Comma-separated Ghidra processors to compile")


local ghidra_repo = "https://github.com/NationalSecurityAgency/ghidra.git"
local specs_dir = "specs"

target("sleigh_specs")
    set_kind("phony")

    -- Opt-in: this clones Ghidra and recompiles every .slaspec, so a plain
    -- `xmake` should not trigger it. Run `xmake build sleigh_specs`.
    set_default(false)

    add_deps("sleigh_compile")

    on_build(function(target)
        local processors = {}
        for proc in string.gmatch(get_config("processors"), "[^,]+") do
            table.insert(processors, proc)
        end

        local ghidra_checkout = path.join(target:targetdir(), "ghidra-src")

        if not os.isdir(path.join(ghidra_checkout, ".git")) then
            print("==> cloning Ghidra sparse checkout")

            os.execv("git", {
                "clone",
                "--filter=blob:none",
                "--sparse",
                "--depth",
                "1",
                ghidra_repo,
                ghidra_checkout
            })
        end


        local sparse_paths = {}

        for _, proc in ipairs(processors) do
            table.insert(
                sparse_paths,
                "Ghidra/Processors/" ..
                proc ..
                "/data/languages"
            )
        end


        print("==> sparse checkout:")
        for _, p in ipairs(sparse_paths) do
            print("    " .. p)
        end


        os.cd(ghidra_checkout)

        os.execv("git", {
            "sparse-checkout",
            "add",
            table.unpack(sparse_paths)
        })

        os.cd(os.projectdir())


        os.mkdir(specs_dir)

        import("core.project.project")

        local sleigh_compile =
            project.target("sleigh_compile"):targetfile()

        print("using:", sleigh_compile)

        for _, proc in ipairs(processors) do
            local lang_dir =
                path.join(
                    ghidra_checkout,
                    "Ghidra",
                    "Processors",
                    proc,
                    "data",
                    "languages"
                )

            if not os.isdir(lang_dir) then
                print(
                    "!! missing languages directory for "
                    .. proc
                )
            else
                for _, slaspec in ipairs(
                    os.files(
                        path.join(lang_dir, "*.slaspec")
                    )
                ) do
                    local name =
                        path.basename(
                            slaspec,
                            ".slaspec"
                        )

                    local out =
                        path.join(
                            specs_dir,
                            name .. ".sla"
                        )

                    print(
                        "==> compiling "
                        .. proc
                        .. "/"
                        .. name
                        .. ".slaspec"
                    )

                    os.execv(
                        sleigh_compile,
                        {
                            slaspec,
                            out
                        }
                    )
                end
            end
        end


        print("==> finished compiling specs")
    end)
