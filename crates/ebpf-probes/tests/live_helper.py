import ctypes
import mmap
import os
import select
import signal
import struct
import sys
import time

libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long


def sc(*arguments):
    return libc.syscall(*[ctypes.c_long(argument) for argument in arguments])


AT_FDCWD = -100
WRITE_CREATE = os.O_WRONLY | os.O_CREAT


def stat_line(fd):
    info = os.fstat(fd)
    kernel_device = (os.major(info.st_dev) << 20) | os.minor(info.st_dev)
    print("%d %d" % (kernel_device, info.st_ino))


def sys_open(syscall_number, path, flags, mode):
    raw = path.encode() + b"\0"
    buffer = ctypes.create_string_buffer(raw, len(raw))
    return sc(syscall_number, ctypes.addressof(buffer), flags, mode)


def mode_write(path, flags):
    fd = os.open(path, int(flags), 0o644)
    stat_line(fd)


def mode_opens(directory):
    names = ["e-open", "e-creat", "e-openat", "e-openat2"]
    paths = [os.path.join(directory, name) for name in names]
    buffers = [ctypes.create_string_buffer(path.encode() + b"\0") for path in paths]
    sc(2, ctypes.addressof(buffers[0]), WRITE_CREATE, 0o644)
    sc(85, ctypes.addressof(buffers[1]), 0o644)
    sc(257, AT_FDCWD, ctypes.addressof(buffers[2]), WRITE_CREATE, 0o644)
    how = struct.pack("QQQ", WRITE_CREATE, 0o644, 0)
    how_buffer = ctypes.create_string_buffer(how, len(how))
    sc(437, AT_FDCWD, ctypes.addressof(buffers[3]), ctypes.addressof(how_buffer), len(how))


def mode_uring(path):
    params = ctypes.create_string_buffer(120)
    ring = sc(425, 4, ctypes.addressof(params))
    if ring < 0:
        sys.exit(3)
    sq_off = struct.unpack_from("IIIIIIIIQ", params, 40)
    cq_off = struct.unpack_from("IIIIIIIIQ", params, 80)
    sq_entries = struct.unpack_from("I", params, 0)[0]
    sq_size = sq_off[6] + sq_entries * 4
    sq_ring = mmap.mmap(ring, sq_size, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE, offset=0)
    sqes = mmap.mmap(ring, sq_entries * 64, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE, offset=0x10000000)
    raw = path.encode() + b"\0"
    name = ctypes.create_string_buffer(raw, len(raw))
    entry = struct.pack("BBHiQQIIQ", 18, 0, 0, AT_FDCWD, 0, ctypes.addressof(name), 0o644, WRITE_CREATE, 0)
    sqes[0:64] = entry.ljust(64, b"\0")
    sq_ring[sq_off[6]:sq_off[6] + 4] = struct.pack("I", 0)
    tail = struct.unpack_from("I", sq_ring, sq_off[1])[0]
    sq_ring[sq_off[1]:sq_off[1] + 4] = struct.pack("I", tail + 1)
    done = sc(426, ring, 1, 1, 1, 0, 0)
    if done < 0:
        sys.exit(4)
    time.sleep(0.2)


def mode_race(directory, count):
    paths = [os.path.join(directory, "race-a").encode(), os.path.join(directory, "race-b").encode()]
    size = max(len(path) for path in paths) + 1
    paths = [path + b"\0" * (size - len(path)) for path in paths]
    shared = mmap.mmap(-1, 4096, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE)
    shared[0:size] = paths[0]
    address = ctypes.addressof(ctypes.c_char.from_buffer(shared))
    flipper = os.fork()
    if flipper == 0:
        first, second = paths
        for _ in range(50000000):
            shared[0:size] = first
            shared[0:size] = second
        os._exit(0)
    try:
        for _ in range(int(count)):
            fd = sc(257, AT_FDCWD, address, WRITE_CREATE, 0o644)
            if fd >= 0:
                print(os.readlink("/proc/self/fd/%d" % fd))
                os.close(fd)
    finally:
        os.kill(flipper, signal.SIGKILL)
        os.waitpid(flipper, 0)


def mode_filebacked(directory):
    target = os.path.join(directory, "fb-target")
    source = os.path.join(directory, "fb-source")
    with open(source, "wb") as handle:
        handle.write(target.encode() + b"\0")
        handle.truncate(4096)
    fd = os.open(source, os.O_RDONLY)
    page = mmap.mmap(fd, 4096, mmap.MAP_PRIVATE, mmap.PROT_READ | mmap.PROT_WRITE)
    address = ctypes.addressof(ctypes.c_char.from_buffer(page))
    result = sc(257, AT_FDCWD, address, WRITE_CREATE, 0o644)
    if result < 0:
        sys.exit(5)
    stat_line(result)


def mode_longname(directory, depth):
    os.chdir(directory)
    for _ in range(int(depth)):
        piece = "d" * 50
        os.mkdir(piece)
        os.chdir(piece)
    fd = os.open("leaf", WRITE_CREATE, 0o644)
    stat_line(fd)


def mode_tmpfile(directory):
    fd = os.open(directory, os.O_TMPFILE | os.O_WRONLY, 0o600)
    stat_line(fd)
    source = ("/proc/self/fd/%d" % fd).encode()
    destination = os.path.join(directory, "linked").encode()
    if libc.linkat(AT_FDCWD, source, AT_FDCWD, destination, 0x400) != 0:
        sys.exit(9)


def mode_chroot(directory):
    root = os.path.join(directory, "root")
    os.makedirs(root, exist_ok=True)
    os.chroot(root)
    os.chdir("/")
    fd = os.open("/inner", WRITE_CREATE, 0o644)
    stat_line(fd)


def mode_opentree(directory):
    raw = directory.encode() + b"\0"
    name = ctypes.create_string_buffer(raw, len(raw))
    tree = sc(428, AT_FDCWD, ctypes.addressof(name), 0x1 | 0o2000000)
    if tree < 0:
        sys.exit(6)
    fd = os.open("clone-file", WRITE_CREATE, 0o644, dir_fd=tree)
    stat_line(fd)


def mode_fanotify(denied, allowed, watched):
    fan = sc(300, 4, os.O_RDONLY | os.O_LARGEFILE)
    if fan < 0:
        sys.exit(7)
    raw = watched.encode() + b"\0"
    name = ctypes.create_string_buffer(raw, len(raw))
    if sc(301, fan, 0x1, 0x10000 | 0x08000000, AT_FDCWD, ctypes.addressof(name)) < 0:
        sys.exit(8)
    child = os.fork()
    if child == 0:
        for path in (denied, allowed):
            try:
                os.close(os.open(path, os.O_WRONLY))
                print("opened %s" % path)
            except OSError as error:
                print("refused %s %d" % (path, error.errno))
            sys.stdout.flush()
        os._exit(0)
    finished = False
    for _ in range(100000):
        if finished:
            break
        waited, _status = os.waitpid(child, os.WNOHANG)
        finished = waited != 0
        pending = os.read(fan, 4096) if _readable(fan) else b""
        offset = 0
        while offset + 24 <= len(pending):
            length, _version, _reserved, _meta, _mask, event_fd, event_pid = struct.unpack_from("IBBHQii", pending, offset)
            try:
                seen = os.readlink("/proc/self/fd/%d" % event_fd)
            except OSError:
                seen = ""
            verdict = 2 if seen == denied else 1
            os.write(fan, struct.pack("iI", event_fd, verdict))
            os.close(event_fd)
            offset += length


def _readable(fd):
    return bool(select.select([fd], [], [], 0.05)[0])


MODES = {
    "write": mode_write,
    "opens": mode_opens,
    "uring": mode_uring,
    "race": mode_race,
    "filebacked": mode_filebacked,
    "longname": mode_longname,
    "tmpfile": mode_tmpfile,
    "chroot": mode_chroot,
    "opentree": mode_opentree,
    "fanotify": mode_fanotify,
}

signal.alarm(120)
MODES[sys.argv[1]](*sys.argv[2:])
