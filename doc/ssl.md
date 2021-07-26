SSL/TLS
=======

```Lua
local ssl = require 'mbedtls.ssl'
```

### ssl.newconfig(mode, [cacert], [cert])
Returns a new configuration handle based on `mode` (a string) that can be one of the following:
- `tls-client`
- `tls-server`
- `dtls-client`
- `dtls-server`

If filename `cacert` is provided, a CA certificate chain in PEM format is loaded from that file, and peer verification is enabled.

If filename `cert` is provided, both peer certificate and private key in PEM format are loaded from that file. Otherwise in server mode, a built-in self-signed certificate is used by default.

### ssl.newcontext(cfg, rcb, wcb, [ref])
Returns a new I/O context handle based on configuration `cfg` and I/O callbacks that have the following signatures:

* `rcb([ref,] size) -> data`
* `wcb([ref,] data) -> size`

The callbacks are called each time data needs to be transferred through the underlying communication channel.

The read callback `rcb` is allowed to receive fewer bytes than requested. If performing non-blocking I/O, an empty string must be returned when the operation would block. In this case, the calling function returns a special error string `want-read` indicating that it has to be called again once data becomes available on the underlying transport. In case of DTLS, it is also important to check if a timeout must be observed while waiting for data (see `ctx:gettimeout()`).

The write callback `wcb` is allowed to send fewer bytes than requested. It must always return the number of bytes actually sent. If performing non-blocking I/O, zero must be returned when the operation would block. In this case, the calling function returns a special error string `want-write` indicating that it has to be called again once the underlying transport is ready to send data.

Callback exceptions are propagated to the calling function, hence it is possible to generate custom callback errors via standard `error()`.


Context Methods
---------------

### ctx:gettimeout()
_DTLS only:_ Returns a fractional timeout value in seconds within which the previous unfinished operation (the one that returned either `want-read` or `want-write`) must be invoked again. In case no timeout is active, returns `nil`.

### ctx:setbio(rcb, wcb, [ref])
Assigns new I/O callbacks and optional reference `ref` (see `ssl.newcontext()`).

### ctx:setpeerid(peerid)
_DTLS server only:_ Sets `peerid` as a peer's identity on the underlying transport, e.g. a string `address#port` for UDP. This identity is then used to verify a _ClientHello_ message as part of a DTLS handshake.

### ctx:handshake()
Performs a handshake and returns `true` when finished. On error, returns `nil` and the error message.

Except for DTLS server, it is not required to explicitly call this function before an I/O operation because a handshake is performed implicitly in that case.

_DTLS server only:_ Prior to calling, a peer's identity must be set on the context. In order to facilitate source address verification, this function operates in a two-step fashion. The first successful return signals that a verified _ClientHello_ message has been received. The second successful return indicates that the handshake has been completed. In other words, it is required to call this function at least once to make sure that either an ongoing session can proceed (successful return) or an unverified _ClientHello_ message has been received (fatal error).

### ctx:read(size)
Attempts to read at most `size` bytes from the secure channel and returns the data actually read. On error, returns `nil` and the error message.

### ctx:write(data, [pos], [len])
Attempts to write `data` bytes to the secure channel and returns the number of bytes actually written. On error, returns `nil` and the error message. Optional `pos` marks the beginning of data (default is 1). Optional `len` marks the size of data (default is `#data - pos + 1`).

### ctx:close()
Sends a _CloseNotify_ message to the peer indicating an intent to gracefully shut down the secure channel.

### ctx:reset()
Resets the context to make it suitable for a new session.


Context Errors
--------------

The following errors are non-fatal, i.e. they do not reset a context and are expected in the normal course of a secure session.

| Error               | Description                                              |
|---------------------|----------------------------------------------------------|
| `invalid operation` | Invalid arguments/configuration for the operation.       |
| `want-read`         | The underlying transport is not ready for reading.       |
| `want-write`        | The underlying transport is not ready for writing.       |
| `closed`            | A _CloseNotify_ message has been received from the peer. |

All other errors are fatal and implicitly reset a context thus making it suitable for a new session.


Cookie API
----------

The following functions are complementary and are most useful for raw UDP-based sessions. They serve the same purpose as source address verification in DTLS. See https://tools.ietf.org/html/rfc4347 for more information.

### ssl.getcookie(peerid)
Returns a "cookie" string for `peerid` (a peer's identity on the underlying transport, e.g. a string `address#port` for UDP).

### ssl.checkcookie(peerid, cookie)
Checks if `peerid` and `cookie` match and returns a boolean result.
