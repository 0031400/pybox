import winreg


class WindowsProxy:
    def __init__(self, server: str) -> None:
        self.server = server
        self.key: winreg.HKEYType | None = None

    def open_key(self) -> None:
        self.key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            0,
            winreg.KEY_SET_VALUE,
        )

    def close_key(self):
        if self.key:
            winreg.CloseKey(self.key)

    def enable(self):
        self.open_key()
        if self.key:
            winreg.SetValueEx(self.key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(self.key, "ProxyServer", 0, winreg.REG_SZ, self.server)
        self.close_key()

    def disable(self):
        self.open_key()
        if self.key:
            winreg.SetValueEx(self.key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
        self.close_key()
