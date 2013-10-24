import netifaces


def get_xtr_id():
    watermark = 110930286722065861025335556600219303936L

    # Find the first available usable MAC address
    for if_name in netifaces.interfaces():  # @UndefinedVariable
        link_addrs = netifaces.ifaddresses(if_name).get(netifaces.AF_LINK, [])  # @UndefinedVariable
        for link_addr in link_addrs:
            mac = link_addr['addr']

            # We don't want multicast addresses (they shouldn't be on an interface!)
            is_multicast = int(mac[:2], 16) & 1
            if is_multicast:
                continue

            # Convert the MAC address to an integer
            macint = 0
            for part in mac.split(':'):
                macint <<= 8
                macint += int(part, 16)

            # MAC address zero is useless
            if macint == 0:
                continue

            # Watermark the xTR-ID, just for fun :-)
            return macint | watermark

    # No xTR-ID then...
    return 0
