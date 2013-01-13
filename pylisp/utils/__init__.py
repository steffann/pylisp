from IPy import IP


def make_prefix(address, prefix_len):
    if prefix_len is None:
        return address

    if isinstance(address, IP):
        # Convert address to prefix
        prefix = address.make_net(prefix_len)

        # Check that we didn't clear bits in the address
        if prefix.ip != address.ip:
            raise ValueError("invalid prefix length %s for %r"
                             % (address._prefixlen, address))

        return prefix
    else:
        raise ValueError('Need an IP address to make a prefix')
