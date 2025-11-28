const std = @import("std");
const posix = std.posix;
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const Cli = @import("cli.zig");
const Config = @import("config.zig");
const SigHandler = @import("sighandler.zig");

const stdx = @import("stdx.zig");
const network = @import("network.zig");
const backendZig = @import("backend/zig.zig");

const response_ok =
    "HTTP/1.1 200 OK\r\n" ++
    "Content-Type: application/octet-stream\r\n" ++
    "Content-Length: {d}\r\n" ++
    "Connection: close\r\n" ++
    "\r\n";

const response_not_found =
    "HTTP/1.1 404 Not Found\r\n" ++
    "Content-Length: 0\r\n" ++
    "Connection: close\r\n";

const response_bad_request =
    "HTTP/1.1 400 Bad Request\r\n" ++
    "Content-Length: 0\r\n" ++
    "Connection: close\r\n";

test {
    std.testing.refAllDecls(@This());
}

pub fn main() !void {
    var gpa_instance = std.heap.DebugAllocator(.{}){};
    defer _ = gpa_instance.deinit();
    const gpa = gpa_instance.allocator();

    var arena_instance = std.heap.ArenaAllocator.init(gpa);
    defer _ = arena_instance.deinit();
    const arena = arena_instance.allocator();

    var sighandler = SigHandler{ .arena = arena };
    try sighandler.install();

    // Load configuration
    var args = try std.process.argsWithAllocator(arena);
    defer args.deinit();

    const argv = Cli.parse(&args);

    const config = Config.parse(arena, argv.config) catch |err| {
        switch (err) {
            error.OutOfMemory => @panic("OOM"),
            else => {
                stdx.fatal("Unable to open configuration file: {}", .{err});
            },
        }
    };

    // Start server
    try network.Tls.globalInit();

    const server_fd = try posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0);
    defer posix.close(server_fd);

    const port = std.mem.bigToNative(u16, config.server.port);
    var addr = posix.sockaddr.in{ .family = posix.AF.INET, .addr = 0, .port = port };
    var addr_len: posix.socklen_t = @sizeOf(posix.sockaddr.in);

    try posix.bind(server_fd, @ptrCast(@alignCast(&addr)), addr_len);
    try posix.listen(server_fd, Config.max_pending_connections);

    const shutdown = struct {
        fn func(fd: posix.socket_t) void {
            posix.shutdown(fd, .recv) catch |err| {
                std.log.warn("Failed to terminate socket: {}", .{err});
            };
        }
    }.func;
    try sighandler.on(shutdown, .{server_fd});

    while (true) {
        const client_fd = posix.accept(server_fd, @ptrCast(@alignCast(&addr)), &addr_len, 0) catch |err| {
            switch (err) {
                // There's nothing you can do here, it just won't compile
                error.SocketNotListening => break,
                else => return err,
            }
        };
        defer posix.close(@intCast(client_fd));

        std.log.info("connection", .{});

        var req_buf: [Config.max_request_size]u8 = undefined;
        const read_bytes = try posix.read(@intCast(client_fd), &req_buf);

        var res_buf: [Config.max_response_size]u8 = undefined;

        const request = network.Request.parse(req_buf[0..read_bytes]) catch {
            _ = try posix.write(@intCast(client_fd), response_bad_request);
            continue;
        };

        const zigfile = stdx.cutPrefix(u8, request.path, "/") orelse {
            _ = try posix.write(@intCast(client_fd), response_not_found);
            continue;
        };

        const tarball = backendZig.Tarball.parse(zigfile) catch {
            _ = try posix.write(@intCast(client_fd), response_not_found);
            continue;
        };

        var buffer: [128:0]u8 = undefined;
        const uri = try std.Uri.parse(try tarball.getUpstreamUri(&buffer));

        const stat = std.fs.cwd().statFile(tarball.filename) catch |err| switch (err) {
            error.FileNotFound => blk: {
                const file = try std.fs.cwd().createFile(tarball.filename, .{ .exclusive = true });
                defer file.close();

                try download(uri, file);

                break :blk try std.fs.cwd().statFile(tarball.filename);
            },
            else => return err,
        };

        const file2 = try std.fs.cwd().openFile(tarball.filename, .{ .mode = .read_only });
        defer file2.close();

        const response = try std.fmt.bufPrintZ(&res_buf, response_ok, .{stat.size});
        const sent_bytes = try posix.write(@intCast(client_fd), response);
        if (sent_bytes < 0) {
            std.log.err("coudn't write all message", .{});
        }

        while (true) {
            var rbuf: [512:0]u8 = undefined;
            const n = try file2.read(&rbuf);
            if (n <= 0) break;

            const bytes = try posix.write(@intCast(client_fd), rbuf[0..@intCast(n)]);
            if (bytes < 0) {
                std.log.err("coudn't write all message", .{});
            }
        }
    }
}

pub fn download(uri: std.Uri, file: std.fs.File) !void {
    assert(std.mem.eql(u8, "https", uri.scheme));

    var pathbuf = std.mem.zeroes([64:0]u8);
    var hostbuf = std.mem.zeroes([64:0]u8);
    var portbuf = std.mem.zeroes([8:0]u8);

    const path = blk: {
        var writer = std.Io.Writer.fixed(&pathbuf);
        try uri.path.formatHost(&writer);
        break :blk writer.buffered();
    };
    const host = blk: {
        var writer = std.Io.Writer.fixed(&hostbuf);
        try uri.host.?.formatHost(&writer);
        break :blk writer.buffered();
    };
    {
        var writer = std.Io.Writer.fixed(&portbuf);
        try writer.print("{d}", .{uri.port orelse 443});
    }

    var socket: network.Tls = try .connect(&hostbuf, &portbuf);
    defer socket.close();

    { // send request
        const request =
            "GET {s} HTTP/1.1\r\n" ++
            "Host: {s}\r\n" ++
            "Connection: close\r\n" ++
            "\r\n";

        var req: [512:0]u8 = undefined;
        const buf = try std.fmt.bufPrintZ(&req, request, .{ path, host });

        _ = try socket.write(buf);
    }

    { // receive file content
        var buffer: [4096]u8 = undefined;

        var skipped = false;
        while (true) {
            const len = try socket.read(&buffer);
            if (len <= 0) break;

            if (skipped) {
                _ = try file.write(buffer[0..len]);
            } else {
                if (std.mem.indexOf(u8, buffer[0..len], "\r\n\r\n")) |pos| {
                    std.log.debug("Skipped: {d}!", .{pos});
                    _ = try file.write(buffer[pos + 4 .. len]);
                    skipped = true;
                }
            }
        }
    }
}
