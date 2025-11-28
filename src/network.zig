const std = @import("std");
const Uri = std.Uri;
const posix = std.posix;

pub const Status = std.http.Status;
pub const Version = std.http.Version;
pub const Connection = std.http.Connection;

const mbedtls = @cImport({
    @cInclude("mbedtls/ssl.h");
    @cInclude("mbedtls/entropy.h");
    @cInclude("mbedtls/net_sockets.h");

    @cInclude("mbedtls/debug.h");
    @cInclude("mbedtls/error.h");
    @cInclude("mbedtls/ctr_drbg.h");
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

fn mbedtlsPerror(func: []const u8, rc: c_int) void {
    var buffer: [128:0]u8 = undefined;
    mbedtls.mbedtls_strerror(rc, &buffer[0], @intCast(buffer.len));

    std.log.err("{s} returned: {s}", .{ func, buffer[0..] });
}

pub const Tls = struct {
    const pers: [:0]const u8 = "ssl_client1";

    var ssl: mbedtls.mbedtls_ssl_context = undefined;
    var conf: mbedtls.mbedtls_ssl_config = undefined;
    var cacert: mbedtls.mbedtls_x509_crt = undefined;
    var net_ctx: mbedtls.mbedtls_net_context = undefined;
    var entropy: mbedtls.mbedtls_entropy_context = undefined;
    var ctr_drbg: mbedtls.mbedtls_ctr_drbg_context = undefined;

    const ConnectError = error{
        TlsError,
        InvalidUri,
    };

    pub fn globalInit() !void {
        mbedtls.mbedtls_net_init(&net_ctx);

        mbedtls.mbedtls_ssl_init(&ssl);
        mbedtls.mbedtls_ssl_config_init(&conf);

        mbedtls.mbedtls_x509_crt_init(&cacert);
        mbedtls.mbedtls_ctr_drbg_init(&ctr_drbg);
        mbedtls.mbedtls_entropy_init(&entropy);

        const rc1 = mbedtls.mbedtls_ctr_drbg_seed(
            &ctr_drbg,
            mbedtls.mbedtls_entropy_func,
            &entropy,
            pers.ptr,
            pers.len,
        );
        if (rc1 != 0) {
            mbedtlsPerror("mbedtls_ctr_drbg_seed", rc1);
            return error.TlsError;
        }
    }

    pub fn connect(host: [:0]const u8, port: [:0]const u8) !Tls {
        const rc1 = mbedtls.mbedtls_net_connect(
            &net_ctx,
            host.ptr,
            port.ptr,
            mbedtls.MBEDTLS_NET_PROTO_TCP,
        );
        if (rc1 != 0) {
            mbedtlsPerror("mbedtls_net_connect", rc1);
            return error.TlsError;
        }

        const rc2 = mbedtls.mbedtls_ssl_config_defaults(
            &conf,
            mbedtls.MBEDTLS_SSL_IS_CLIENT,
            mbedtls.MBEDTLS_SSL_TRANSPORT_STREAM,
            mbedtls.MBEDTLS_SSL_PRESET_DEFAULT,
        );
        if (rc2 != 0) {
            mbedtlsPerror("mbedtls_ssl_config_defaults", rc2);
            return error.TlsError;
        }

        mbedtls.mbedtls_ssl_conf_authmode(&conf, mbedtls.MBEDTLS_SSL_VERIFY_OPTIONAL);
        mbedtls.mbedtls_ssl_conf_ca_chain(&conf, &cacert, null);
        mbedtls.mbedtls_ssl_conf_rng(&conf, mbedtls.mbedtls_ctr_drbg_random, &ctr_drbg);

        const rc3 = mbedtls.mbedtls_ssl_setup(&ssl, &conf);
        if (rc3 != 0) {
            mbedtlsPerror("mbedtls_ssl_setup", rc3);
            return error.TlsError;
        }

        const rc4 = mbedtls.mbedtls_ssl_set_hostname(&ssl, host.ptr);
        if (rc4 != 0) {
            mbedtlsPerror("mbedtls_ssl_set_hostname", rc4);
            return error.TlsError;
        }

        mbedtls.mbedtls_ssl_set_bio(&ssl, &net_ctx, mbedtls.mbedtls_net_send, mbedtls.mbedtls_net_recv, null);

        while (true) {
            const rc5 = mbedtls.mbedtls_ssl_handshake(&ssl);
            if (rc5 == 0) break;
            if (rc5 != mbedtls.MBEDTLS_ERR_SSL_WANT_READ and rc5 != mbedtls.MBEDTLS_ERR_SSL_WANT_WRITE) {
                mbedtlsPerror("mbedtls_ssl_handshake ", rc5);
                return error.TlsError;
            }
        }

        const socket = Tls{};
        return socket;
    }

    pub fn close(s: *Tls) void {
        _ = s;

        mbedtls.mbedtls_net_free(&net_ctx);
        mbedtls.mbedtls_ssl_free(&ssl);
        mbedtls.mbedtls_ssl_config_free(&conf);
        mbedtls.mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls.mbedtls_entropy_free(&entropy);
    }

    pub fn read(s: *Tls, buf: []u8) posix.ReadError!usize {
        _ = s;

        const rc = mbedtls.mbedtls_ssl_read(&ssl, &buf[0], @intCast(buf.len));
        if (rc >= 0) { // success, return readed bytes
            return @intCast(rc);
        }

        if (rc == mbedtls.MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
            // closed the connection first. We're ok with that
            return 0;
        }

        mbedtlsPerror("mbedtls_ssl_read", rc);
        return error.Unexpected;
    }

    pub fn write(s: *Tls, buf: []const u8) posix.WriteError!usize {
        _ = s;

        const rc = mbedtls.mbedtls_ssl_write(&ssl, buf.ptr, @intCast(buf.len));
        if (rc >= 0) { // success, return writed bytes
            return @intCast(rc);
        }

        mbedtlsPerror("mbedtls_ssl_write", rc);
        return error.Unexpected;
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
