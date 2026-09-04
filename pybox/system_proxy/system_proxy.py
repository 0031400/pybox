import sys

if sys.platform == "win32":
    from .windows import WindowsProxy


class SystemProxy:
    def __init__(self, server: str) -> None:
        self.server = server
        if sys.platform == "win32":
            self.proxy = WindowsProxy(self.server)

    def enable(self):
        if sys.platform == "win32":
            self.proxy.enable()

    def disable(self):
        if sys.platform == "win32":
            self.proxy.disable()
