const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const mbedtls = b.dependency("mbedtls", .{
        .target = target,
        .optimize = optimize,
    });

    const manifest = Manifest.init(b);
    defer manifest.deinit(b.allocator);

    const options = b.addOptions();
    options.addOption([]const u8, "version", manifest.version);

    const exe = b.addExecutable(.{
        .name = "zoriand",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .link_libc = true,
            .target = target,
            .optimize = optimize,
        }),
    });

    exe.root_module.addOptions("config", options);
    exe.root_module.linkLibrary(mbedtls.artifact("mbedtls"));

    b.installArtifact(exe);

    const run_step = b.step("run", "Run the app");
    const run_cmd = b.addRunArtifact(exe);
    run_step.dependOn(&run_cmd.step);
    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const exe_tests = b.addTest(.{
        .root_module = exe.root_module,
    });
    const run_exe_tests = b.addRunArtifact(exe_tests);

    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_exe_tests.step);
}

const Manifest = struct {
    version: []const u8,

    fn init(b: *std.Build) Manifest {
        const input = @embedFile("build.zig.zon");

        var diagnostics: std.zon.parse.Diagnostics = .{};
        defer diagnostics.deinit(b.allocator);

        return std.zon.parse.fromSlice(Manifest, b.allocator, input, &diagnostics, .{
            .free_on_error = true,
            .ignore_unknown_fields = true,
        }) catch |err| {
            switch (err) {
                error.OutOfMemory => @panic("OOM"),
                error.ParseZon => {
                    std.debug.print("Parse diagnostics:\n{f}\n", .{diagnostics});
                    std.process.exit(1);
                },
            }
        };
    }

    fn deinit(self: Manifest, allocator: std.mem.Allocator) void {
        allocator.free(self.version);
    }
};
