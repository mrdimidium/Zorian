const std = @import("std");
const Uri = std.Uri;
const posix = std.posix;

pub const Status = std.http.Status;
pub const Version = std.http.Version;
pub const Connection = std.http.Connection;

const openssl = @cImport({
    @cInclude("openssl/bio.h");
    @cInclude("openssl/ssl.h");
    @cInclude("openssl/err.h");
});

/// HTTP defines a set of request methods to indicate the purpose
/// of the request and what is expected if the request is successful
///
/// https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods
pub const Method = enum {
    // requests a representation of the specified resource.
    // Requests using GET should only retrieve data and should not contain a request content.
    GET,

    // asks for a response identical to a GET request,
    // but without a response body.
    HEAD,

    // submits an entity to the specified resource,
    // often causing a change in state or side effects on the server.
    POST,

    // replaces all current representations of the target resource with the request content.
    PUT,

    // deletes the specified resource.
    DELETE,

    // establishes a tunnel to the server identified by the target resource.
    CONNECT,

    // describes the communication options for the target resource.
    OPTIONS,

    // performs a message loop-back test along the path to the target resource.
    TRACE,

    // applies partial modifications to a resource.
    PATCH,

    pub fn parse(str: []const u8) ?Method {
        const protocol_map = std.StaticStringMap(Method).initComptime(.{
            .{ "GET", .GET },
            .{ "HEAD", .HEAD },
            .{ "POST", .POST },
            .{ "PUT", .PUT },
            .{ "DELETE", .DELETE },
            .{ "CONNECT", .CONNECT },
            .{ "OPTIONS", .OPTIONS },
            .{ "TRACE", .TRACE },
            .{ "PATCH", .PATCH },
        });
        return protocol_map.get(str);
    }
};

pub const Protocol = enum {
    tcp,
    tls,

    fn port(protocol: Protocol) u16 {
        return switch (protocol) {
            .tcp => 80,
            .tls => 443,
        };
    }

    pub fn parse(scheme: []const u8) ?Protocol {
        const protocol_map = std.StaticStringMap(Protocol).initComptime(.{
            .{ "http", .tcp },
            .{ "https", .tls },
        });
        return protocol_map.get(scheme);
    }
};

pub const SocketTls = struct {
    bio: *openssl.BIO,

    ctx: *openssl.SSL_CTX,

    const ConnectError = error{
        TlsError,
        InvalidUri,
    };

    pub fn global_init() !void {
        _ = openssl.OPENSSL_init_crypto(openssl.OPENSSL_INIT_ADD_ALL_CIPHERS | openssl.OPENSSL_INIT_ADD_ALL_DIGESTS, null);
        _ = openssl.OPENSSL_init_ssl(openssl.OPENSSL_INIT_LOAD_SSL_STRINGS | openssl.OPENSSL_INIT_LOAD_CRYPTO_STRINGS, null);
    }

    pub fn connect(host: []const u8, port: u16) !SocketTls {
        var sni: [64:0]u8 = undefined;
        _ = try std.fmt.bufPrintZ(&sni, "{s}:{d}", .{ host, port });

        var socket = SocketTls{ .bio = undefined, .ctx = undefined };

        socket.ctx = openssl.SSL_CTX_new(openssl.TLS_client_method()) orelse
            return error.TlsError;

        socket.bio = openssl.BIO_new_ssl_connect(socket.ctx) orelse
            return error.TlsError;

        {
            var ssl: ?*openssl.SSL = null;
            _ = openssl.BIO_get_ssl(socket.bio, &ssl);
            if (ssl == null) {
                return error.TlsError;
            }

            _ = openssl.SSL_set_mode(ssl, openssl.SSL_MODE_AUTO_RETRY);
        }

        _ = openssl.BIO_ctrl(socket.bio, openssl.BIO_C_SET_CONNECT, 0, &sni[0]);
        if (openssl.BIO_do_connect(socket.bio) <= 0) {
            return error.TlsError;
        }

        if (openssl.BIO_do_handshake(socket.bio) <= 0) {
            return error.TlsError;
        }

        return socket;
    }

    pub fn close(s: *SocketTls) void {
        openssl.BIO_free_all(s.bio);
        openssl.SSL_CTX_free(s.ctx);
    }

    pub fn read(s: *SocketTls, buf: []u8) posix.ReadError!usize {
        const rc = openssl.BIO_read(s.bio, &buf[0], @intCast(buf.len));
        if (rc >= 0) { // success, return readed bytes
            return @intCast(rc);
        }

        if (rc == -1) {
            const err = openssl.ERR_get_error();
            std.log.err("OpenSSL error: {s}", .{openssl.ERR_reason_error_string(err)});
            return error.Unexpected;
        }

        unreachable;
    }

    pub fn write(s: *SocketTls, buf: []const u8) posix.WriteError!usize {
        const rc = openssl.BIO_write(s.bio, buf.ptr, @intCast(buf.len));
        if (rc >= 0) { // success, return readed bytes
            return @intCast(rc);
        }

        if (rc == -1) {
            const err = openssl.ERR_get_error();
            std.log.err("OpenSSL error: {s}", .{openssl.ERR_reason_error_string(err)});
            return error.Unexpected;
        }

        unreachable;
    }
};

pub const Request = struct {
    version: Version,
    method: Method,
    path: []const u8,
    body: ?[]const u8 = null,

    pub const ParseError = error{
        UnknownMethod,
        InvalidStartline,
    };

    pub fn parse(payload: []const u8) ParseError!Request {
        var step: enum { startline, headers, body } = .startline;
        var request = Request{ .version = undefined, .method = undefined, .path = "" };

        var it = std.mem.splitSequence(u8, payload, "\r\n");
        while (it.next()) |line| switch (step) {
            .startline => {
                var it2 = std.mem.splitSequence(u8, line, " ");
                if (it2.next()) |method| {
                    request.method =
                        Method.parse(method) orelse return error.UnknownMethod;
                } else {
                    return error.UnknownMethod;
                }

                if (it2.next()) |path| {
                    if (!std.mem.startsWith(u8, path, "/")) {
                        return error.InvalidStartline;
                    }

                    request.path = path;
                } else {
                    return error.InvalidStartline;
                }

                if (it2.next()) |version| {
                    request.version =
                        if (std.mem.eql(u8, "HTTP/1.0", version))
                            .@"HTTP/1.0"
                        else if (std.mem.eql(u8, "HTTP/1.1", version))
                            .@"HTTP/1.1"
                        else
                            return error.InvalidStartline;
                } else {
                    return error.InvalidStartline;
                }

                if (it2.next() != null) {
                    return error.InvalidStartline;
                }

                step = .headers;
            },
            .headers => {
                if (line.len == 0) {
                    step = .body;
                    continue;
                }
            },
            .body => {
                break;
            },
        };

        return request;
    }
};

pub const Response = struct {};
