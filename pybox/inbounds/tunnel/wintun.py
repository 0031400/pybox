import ctypes
from ctypes import wintypes
from pathlib import Path
from queue import Queue
from typing import Final

HANDLE = wintypes.HANDLE
DWORD = wintypes.DWORD
BYTE = ctypes.c_ubyte
LPBYTE = ctypes.POINTER(BYTE)
WINTUN_ADAPTER_HANDLE = HANDLE
WINTUN_SESSION_HANDLE = HANDLE
ERROR_NO_MORE_ITEMS: Final = 259
ERROR_HANDLE_EOF: Final = 38
ERROR_OPERATION_ABORTED: Final = 995
NET_LUID = ctypes.c_uint64


class WinTun:
    DEFAULT_RING_CAPACITY = 0x400000

    def __init__(
        self,
        name: str,
        *,
        tunnel_type: str | None = None,
        dll_path: str | None = None,
        ring_capacity: int = DEFAULT_RING_CAPACITY,
    ) -> None:
        self.name = name
        self.tunnel_type = tunnel_type or "WinTun"
        self.ring_capacity = ring_capacity
        self._adapter: HANDLE | None = None
        self._session: HANDLE | None = None
        self._dll = self._load_dll(dll_path)
        self._load_functions()
        self.queue: Queue[bytes] = Queue()

    def start(self):
        self.create_adapter()
        self.start_session()
        self.event = self.get_read_wait_event()

    @staticmethod
    def _load_dll(dll_path: str | None) -> ctypes.WinDLL:
        if not dll_path:
            return ctypes.WinDLL(
                str(Path("wintun.dll").resolve()),
                use_last_error=True,
            )
        path = Path(dll_path)
        if not path.exists():
            raise RuntimeError("dll path not found")
        return ctypes.WinDLL(
            str(path),
            use_last_error=True,
        )

    def _load_functions(self):
        self._dll.WintunCreateAdapter.argtypes = [
            wintypes.LPCWSTR,
            wintypes.LPCWSTR,
            ctypes.c_void_p,
        ]
        self._dll.WintunCreateAdapter.restype = WINTUN_ADAPTER_HANDLE
        self._dll.WintunOpenAdapter.argtypes = [wintypes.LPCWSTR]
        self._dll.WintunOpenAdapter.restype = WINTUN_ADAPTER_HANDLE
        self._dll.WintunStartSession.argtypes = [WINTUN_ADAPTER_HANDLE, DWORD]
        self._dll.WintunStartSession.restype = WINTUN_SESSION_HANDLE

        self._dll.WintunGetAdapterLUID.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_ulonglong),
        ]
        self._dll.WintunGetAdapterLUID.restype = None
        self._dll.WintunEndSession.argtypes = [WINTUN_SESSION_HANDLE]
        self._dll.WintunEndSession.restype = None
        self._dll.WintunGetReadWaitEvent.argtypes = [WINTUN_SESSION_HANDLE]
        self._dll.WintunGetReadWaitEvent.restype = HANDLE
        self._dll.WintunReceivePacket.argtypes = [
            WINTUN_SESSION_HANDLE,
            ctypes.POINTER(DWORD),
        ]
        self._dll.WintunReceivePacket.restype = LPBYTE
        self._dll.WintunReleaseReceivePacket.argtypes = [
            WINTUN_SESSION_HANDLE,
            LPBYTE,
        ]
        self._dll.WintunReleaseReceivePacket.restype = None
        self._dll.WintunAllocateSendPacket.argtypes = [
            WINTUN_SESSION_HANDLE,
            DWORD,
        ]
        self._dll.WintunAllocateSendPacket.restype = LPBYTE
        self._dll.WintunSendPacket.argtypes = [
            WINTUN_SESSION_HANDLE,
            LPBYTE,
        ]
        self._dll.WintunSendPacket.restype = None

    @staticmethod
    def _last_error() -> int:
        return ctypes.get_last_error()

    @classmethod
    def _raise_last_error(cls, message: str):
        error = cls._last_error()
        raise RuntimeError(error, message)

    def get_luid(self):
        luid = ctypes.c_ulonglong(0)
        self._dll.WintunGetAdapterLUID(self._adapter, ctypes.byref(luid))
        if not luid.value:
            raise RuntimeError("get luid fail")
        return luid.value

    def create_adapter(self):
        if self._adapter:
            raise RuntimeError("adapter already exist")
        adapter = self._dll.WintunCreateAdapter(self.name, self.tunnel_type, None)
        if not adapter:
            self._raise_last_error("fail to create adapter")
        self._adapter = adapter

    def open_adapter(self):
        if self._adapter:
            raise RuntimeError("adapter already exist")
        adapter = self._dll.WintunOpenAdapter(self.name)
        if not adapter:
            self._raise_last_error("fail to open adapter")
        self._adapter = adapter

    def close_adapter(self):
        if self._adapter:
            self._dll.WintunCloseAdapter(self._adapter)

    def start_session(self):
        if not self._adapter:
            raise RuntimeError("adapter is not open")
        if self._session:
            raise RuntimeError("session already started")
        session = self._dll.WintunStartSession(
            self._adapter,
            self.ring_capacity,
        )
        if not session:
            self._raise_last_error("fail to start session")
        self._session = session

    def end_session(self):
        if self._session:
            self._dll.WintunEndSession(
                self._session,
            )
            self._session = None

    def get_read_wait_event(self):
        if not self._session:
            raise RuntimeError("session is not started")
        event = self._dll.WintunGetReadWaitEvent(
            self._session,
        )
        if not event:
            self._raise_last_error("fail to get read wait event")
        return int(event)

    def receive(self) -> bytes | None:
        if not self._session:
            raise RuntimeError("session is not started")
        packet_size = DWORD()
        packet = self._dll.WintunReceivePacket(
            self._session,
            ctypes.byref(packet_size),
        )
        if not packet:
            error = ctypes.get_last_error()
            if error == ERROR_NO_MORE_ITEMS:
                return None
            raise RuntimeError(error, "fail to receive")
        try:
            return ctypes.string_at(packet, packet_size.value)
        finally:
            self._dll.WintunReleaseReceivePacket(self._session, packet)

    def send(self, packet: bytes):
        if not self._session:
            raise RuntimeError("session is not started")
        data = memoryview(packet)
        if len(data) == 0:
            raise RuntimeError("packet cannot be empty")
        if len(data) > 0xFFFFFFFF:
            raise RuntimeError("packet too big")
        buffer = self._dll.WintunAllocateSendPacket(
            self._session,
            len(data),
        )
        if not buffer:
            self._raise_last_error("fail to allocate send packet")
        ctypes.memmove(buffer, data.tobytes(), len(data))

        self._dll.WintunSendPacket(
            self._session,
            buffer,
        )

    def receive_worker(self):
        if not self.event:
            raise RuntimeError("event not prepared")
        while True:
            result = ctypes.windll.kernel32.WaitForSingleObject(self.event, 1000)
            if result == 0x102:
                continue
            while True:
                data = self.receive()
                if data:
                    self.queue.put(data)
                else:
                    break

    def get_packet(self):
        return self.queue.get()

    def stop(self):
        self.end_session()
        self.close_adapter()
