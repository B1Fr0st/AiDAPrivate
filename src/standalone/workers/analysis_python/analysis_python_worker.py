import argparse
import builtins
import hashlib
import hmac
import io
import json
import os
import struct
import sys
import traceback


BOOTSTRAP_MAGIC = 0x42575041
FRAME_MAGIC = 0x46575041
PROTOCOL_VERSION = 1
DIGEST_BYTES = 32
BOOTSTRAP_BYTES = 4 + 2 + 2 + DIGEST_BYTES + DIGEST_BYTES + DIGEST_BYTES
FRAME_PREFIX_BYTES = 4 + 2 + 2 + 8 + 4 + DIGEST_BYTES
FRAME_HEADER_BYTES = FRAME_PREFIX_BYTES + DIGEST_BYTES
MAX_FRAME_BYTES = 1024 * 1024


def read_exact(stream, size):
    data = bytearray()
    while len(data) < size:
        part = stream.read(size - len(data))
        if not part:
            raise RuntimeError("pipe read terminated")
        data.extend(part)
    return bytes(data)


def write_exact(stream, data):
    view = memoryview(data)
    while view:
        written = stream.write(view)
        if written is None:
            written = len(view)
        if written <= 0:
            raise RuntimeError("pipe write terminated")
        view = view[written:]
    stream.flush()


class Channel:
    def __init__(self, reader, writer, nonce_hash, key):
        self._reader = reader
        self._writer = writer
        self._nonce_hash = nonce_hash
        self._key = key
        self._send_sequence = 1
        self._receive_sequence = 1

    def send(self, message):
        payload = json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if len(payload) > MAX_FRAME_BYTES:
            raise RuntimeError("frame exceeds protocol limit")
        prefix = struct.pack("<IHHQI", FRAME_MAGIC, PROTOCOL_VERSION, 1, self._send_sequence, len(payload)) + self._nonce_hash
        tag = hmac.new(self._key, prefix + payload, hashlib.sha256).digest()
        write_exact(self._writer, prefix + tag + payload)
        self._send_sequence += 1

    def receive(self):
        header = read_exact(self._reader, FRAME_HEADER_BYTES)
        magic, version, kind, sequence, payload_size = struct.unpack("<IHHQI", header[:20])
        if magic != FRAME_MAGIC or version != PROTOCOL_VERSION or kind != 1 or sequence != self._receive_sequence:
            raise RuntimeError("frame header violates protocol")
        if payload_size > MAX_FRAME_BYTES or header[20:52] != self._nonce_hash:
            raise RuntimeError("frame metadata violates protocol")
        payload = read_exact(self._reader, payload_size)
        expected = hmac.new(self._key, header[:FRAME_PREFIX_BYTES] + payload, hashlib.sha256).digest()
        if not hmac.compare_digest(expected, header[FRAME_PREFIX_BYTES:]):
            raise RuntimeError("frame authentication failed")
        self._receive_sequence += 1
        value = json.loads(payload.decode("utf-8"))
        if not isinstance(value, dict):
            raise RuntimeError("frame payload must be an object")
        return value


class BoundedOutput(io.TextIOBase):
    def __init__(self, limit):
        self._limit = limit
        self._parts = []
        self._size = 0
        self._truncated = False

    def writable(self):
        return True

    def write(self, value):
        text = str(value)
        remaining = self._limit - self._size
        if remaining <= 0:
            self._truncated = True
            return len(text)
        encoded = text.encode("utf-8", errors="replace")
        if len(encoded) <= remaining:
            self._parts.append(text)
            self._size += len(encoded)
            return len(text)
        clipped = encoded[:remaining].decode("utf-8", errors="ignore")
        self._parts.append(clipped)
        self._size += len(clipped.encode("utf-8"))
        self._truncated = True
        return len(text)

    def value(self):
        return "".join(self._parts)

    @property
    def truncated(self):
        return self._truncated


class WorkspaceApi:
    def __init__(self, channel, maximum_requests):
        self._channel = channel
        self._maximum_requests = maximum_requests
        self._next_request_id = 1

    def _request(self, operation, arguments):
        if self._next_request_id > self._maximum_requests:
            raise RuntimeError("workspace API request limit exceeded")
        request_id = self._next_request_id
        self._next_request_id += 1
        self._channel.send({"type": "workspace_request", "request_id": request_id, "operation": operation, "arguments": arguments})
        response = self._channel.receive()
        if response.get("type") == "cancel":
            raise KeyboardInterrupt(response.get("reason", "cancelled"))
        if response.get("type") != "workspace_response" or response.get("request_id") != request_id:
            raise RuntimeError("workspace API response violates protocol")
        if response.get("success") is not True:
            raise RuntimeError(response.get("error_code", "WORKSPACE_API_REJECTED"))
        return response.get("data")

    def metadata(self):
        return self._request("metadata", {})

    def read_bytes(self, offset, size):
        return self._request("read_bytes", {"offset": offset, "size": size})

    def find(self, query, limit=100):
        return self._request("find", {"query": query, "limit": limit})

    def list_functions(self, offset=0, limit=100):
        return self._request("list_functions", {"offset": offset, "limit": limit})


def parse_args(argv):
    parser = argparse.ArgumentParser(allow_abbrev=False, add_help=False)
    parser.add_argument("--aida-analysis-python-worker", action="store_true")
    parser.add_argument("--read-handle", type=int, required=True)
    parser.add_argument("--write-handle", type=int, required=True)
    args = parser.parse_args(argv)
    if not args.aida_analysis_python_worker or args.read_handle <= 0 or args.write_handle <= 0:
        raise RuntimeError("worker arguments are invalid")
    return args


def receive_bootstrap(reader):
    data = read_exact(reader, BOOTSTRAP_BYTES)
    magic, version, reserved = struct.unpack("<IHH", data[:8])
    if magic != BOOTSTRAP_MAGIC or version != PROTOCOL_VERSION or reserved != 0:
        raise RuntimeError("bootstrap violates protocol")
    nonce = data[8:8 + DIGEST_BYTES]
    key = data[8 + DIGEST_BYTES:8 + 2 * DIGEST_BYTES]
    manifest_hash = data[8 + 2 * DIGEST_BYTES:]
    if len(manifest_hash) != DIGEST_BYTES:
        raise RuntimeError("bootstrap manifest is invalid")
    return hashlib.sha256(nonce).digest(), key, manifest_hash


def restricted_builtins(output):
    allowed = {
        "abs", "all", "any", "bool", "bytes", "dict", "enumerate", "Exception", "False", "float", "int", "isinstance",
        "len", "list", "max", "min", "None", "print", "range", "repr", "set", "slice", "str", "sum", "True", "tuple",
        "TypeError", "ValueError", "zip"
    }
    result = {name: getattr(builtins, name) for name in allowed if hasattr(builtins, name)}
    result["print"] = lambda *values, sep=" ", end="\n": output.write(sep.join(str(value) for value in values) + end)
    return result


def execute(channel, message):
    if not isinstance(message.get("job_id"), int) or message["job_id"] <= 0 or not isinstance(message.get("script"), str):
        raise RuntimeError("execution request is invalid")
    output_limit = message.get("max_output_bytes")
    request_limit = message.get("max_workspace_requests")
    if not isinstance(output_limit, int) or not isinstance(request_limit, int) or output_limit <= 0 or request_limit <= 0:
        raise RuntimeError("execution limits are invalid")
    stdout = BoundedOutput(output_limit)
    stderr = BoundedOutput(output_limit)
    workspace = WorkspaceApi(channel, request_limit)
    scope = {"__builtins__": restricted_builtins(stdout), "__name__": "__main__", "aida": workspace}
    status = "ok"
    result = "ok"
    error_code = ""
    previous_stdout = sys.stdout
    previous_stderr = sys.stderr
    try:
        sys.stdout = stdout
        sys.stderr = stderr
        code = compile(message["script"], "<aida-approved-script>", "exec", dont_inherit=True, optimize=2)
        exec(code, scope, scope)
    except KeyboardInterrupt:
        status = "cancelled"
        result = "cancelled"
        error_code = "PYTHON_WORKER_CANCELLED"
    except BaseException:
        status = "error"
        result = "script failed"
        error_code = "PYTHON_WORKER_SCRIPT_FAILED"
        stderr.write(traceback.format_exc())
    finally:
        sys.stdout = previous_stdout
        sys.stderr = previous_stderr
    if stdout.truncated or stderr.truncated:
        status = "error"
        result = "output limit exceeded"
        error_code = "PYTHON_WORKER_OUTPUT_LIMIT_EXCEEDED"
    channel.send({"type": "result", "job_id": message["job_id"], "status": status, "result": result,
                  "stdout": stdout.value(), "stderr": stderr.value(), "error_code": error_code})


def main(argv):
    sys.dont_write_bytecode = True
    args = parse_args(argv)
    reader = os.fdopen(msvcrt.open_osfhandle(args.read_handle, os.O_RDONLY), "rb", buffering=0)
    writer = os.fdopen(msvcrt.open_osfhandle(args.write_handle, os.O_WRONLY), "wb", buffering=0)
    nonce_hash, key, manifest_hash = receive_bootstrap(reader)
    channel = Channel(reader, writer, nonce_hash, key)
    channel.send({"type": "hello", "worker": "analysis_python", "manifest_hash": manifest_hash.hex()})
    message = channel.receive()
    if message.get("type") != "execute":
        raise RuntimeError("worker only accepts execute requests")
    execute(channel, message)


if __name__ == "__main__":
    import msvcrt
    try:
        main(sys.argv[1:])
    except BaseException:
        sys.exit(2)
