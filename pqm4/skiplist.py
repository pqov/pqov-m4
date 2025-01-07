skip_list = [
    # These do not work on the Nucleo, but they work in qemu
    # Determining actual memory usage is currently not possible automatically
    {'scheme': 'ov-Is', 'implementation':'ref', 'estmemory': 1048576},
    {'scheme': 'ov-Is-pkc', 'implementation':'ref', 'estmemory': 1048576},
    {'scheme': 'ov-Is-pkc-aes4', 'implementation':'ref', 'estmemory': 1048576},
    {'scheme': 'ov-Is-pkc-skc', 'implementation':'ref', 'estmemory': 1048576},
    {'scheme': 'ov-Is-pkc-skc-aes4', 'implementation':'ref', 'estmemory': 1048576},
]
