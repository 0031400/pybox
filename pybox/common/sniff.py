def sniff_tls_hostname(data: bytes) -> str | None:
    if len(data) < 5:
        return None
    if data[0] != 0x16:
        return None
    if len(data) < 9:
        return None
    if data[5] != 0x01:
        return None
    pos = 9
    if len(data) < pos + 34:
        return None
    pos += 2 + 32
    if pos >= len(data):
        return None
    session_id_len = data[pos]
    pos += 1 + session_id_len
    if pos + 2 > len(data):
        return None
    cipher_suites_len = int.from_bytes(data[pos:pos + 2], "big")
    pos += 2 + cipher_suites_len
    if pos >= len(data):
        return None
    compression_methods_len = data[pos]
    pos += 1 + compression_methods_len
    if pos + 2 > len(data):
        return None
    extensions_len = int.from_bytes(data[pos:pos + 2], "big")
    pos += 2
    extensions_end = pos + extensions_len
    if extensions_end > len(data):
        return None
    while pos + 4 <= extensions_end:
        extension_type = int.from_bytes(data[pos:pos + 2], "big")
        extension_len = int.from_bytes(data[pos + 2:pos + 4], "big")
        pos += 4
        if pos + extension_len > extensions_end:
            return None
        if extension_type == 0:
            extension_data = data[pos:pos + extension_len]
            if len(extension_data) < 5:
                return None
            name_type = extension_data[2]
            if name_type != 0:
                return None
            name_len = int.from_bytes(
                extension_data[3:5],
                "big",
            )
            if 5 + name_len > len(extension_data):
                return None
            return extension_data[5:5 + name_len].decode("ascii")
        pos += extension_len
    return None