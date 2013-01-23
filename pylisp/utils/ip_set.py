'''
Created on 23 jan. 2013

This class is an extension to the IPy module. The IPy module might include this
extension one day, so we try to import it. If that fails then we define our
own implementation.

@author: sander
'''

__all__ = ['IPSet']

try:
    from IPy import IPSet
except ImportError:
    from IPy import IP
    import collections

    class IPSet(collections.MutableSet):
        def __init__(self, iterable=[]):
            # Make sure it's iterable
            if not isinstance(iterable, collections.Iterable):
                raise TypeError("'%s' object is not iterable"
                                % type(iterable).__name__)

            # Make sure we only accept IP objects
            for prefix in iterable:
                if not isinstance(prefix, IP):
                    raise ValueError('Only IP objects can be added '
                                     'to an IPSet')

            # Store and optimize
            self.prefixes = iterable[:]
            self.optimize()

        def __contains__(self, ip):
            for prefix in self.prefixes:
                if ip in prefix:
                    return True

            return False

        def __iter__(self):
            for prefix in self.prefixes[:]:
                yield prefix

        def __len__(self):
            return reduce(lambda total, prefix: total + len(prefix),
                          self.prefixes, 0)

        def __add__(self, other):
            return IPSet(self.prefixes + other.prefixes)

        def __sub__(self, other):
            new = IPSet(self.prefixes)
            for prefix in other:
                new.discard(prefix)
            return new

        def __repr__(self):
            return ('%s([' % self.__class__.__name__ +
                    ', '.join(map(repr, self.prefixes)) + '])')

        def add(self, value):
            # Make sure it's iterable, otherwise wrap
            if not isinstance(value, collections.Iterable):
                value = [value]

            # Check type
            for prefix in value:
                if not isinstance(prefix, IP):
                    raise ValueError('Only IP objects can be added '
                                     'to an IPSet')

            # Append and optimize
            self.prefixes.extend(value)
            self.optimize()

        def discard(self, value):
            # Make sure it's iterable, otherwise wrap
            if not isinstance(value, collections.Iterable):
                value = [value]

            # This is much faster than iterating over the addresses
            if isinstance(value, IPSet):
                value = value.prefixes

            # Remove
            for del_prefix in value:
                if not isinstance(del_prefix, IP):
                    raise ValueError('Only IP objects can be removed '
                                     'from an IPSet')

                # First check if this prefix contains anything in our list
                found = False
                for i in range(len(self.prefixes)):
                    if self.prefixes[i] in del_prefix:
                        self.prefixes[i] = None
                        found = True

                if found:
                    # Filter None values
                    self.prefixes = filter(lambda a: a is not None,
                                           self.prefixes)

                    # If the prefix was bigger than an existing prefix, then
                    # it's certainly not a subset of one, so skip the rest
                    continue

                # Maybe one of our prefixes contains this prefix
                found = False
                for i in range(len(self.prefixes)):
                    if del_prefix in self.prefixes[i]:
                        left = _remove_subprefix(self.prefixes[i], del_prefix)
                        self.prefixes[i:i + 1] = left
                        break

            self.optimize()

        def optimize(self):
            # The algorithm below *depends* on the sort order
            self.prefixes.sort()

            # First eliminate all values that are a subset of other values
            addrlen = len(self.prefixes)
            i = 0
            while i < addrlen:
                # Everything that might be inside this prefix follows
                # directly behind it
                j = i + 1
                while j < addrlen and self.prefixes[j] in self.prefixes[i]:
                    # Mark for deletion by overwriting with None
                    self.prefixes[j] = None
                    j += 1

                # Continue where we left off
                i = j

            # Try to merge as many prefixes as possible
            run_again = True
            while run_again:
                # Filter None values. This happens when a subset is eliminated
                # above, or when two prefixes are merged below
                self.prefixes = filter(lambda a: a is not None, self.prefixes)

                # We'll set run_again to True when we make changes that require
                # re-evaluation of the whole list
                run_again = False

                # We can merge two prefixes that have the same version, same
                # prefix length and differ only on the last bit of the prefix
                addrlen = len(self.prefixes)
                i = 0
                while i < addrlen - 1:
                    j = i + 1

                    try:
                        # The next line will throw an exception when merging
                        # is not possible
                        self.prefixes[i] += self.prefixes[j]
                        self.prefixes[j] = None
                        i = j + 1
                        run_again = True
                    except ValueError:
                        # Can't be merged, see if position j can be merged
                        i = j

    def _remove_subprefix(prefix, subprefix):
        if prefix in subprefix:
            # Nothing left
            return IPSet()

        if subprefix not in prefix:
            # That prefix isn't even in here
            return IPSet([IP(prefix)])

        # Start cutting in half, recursively
        prefixes = [
            IP('%s/%d' % (prefix[0], prefix._prefixlen + 1)),
            IP('%s/%d' % (prefix[prefix.len() / 2], prefix._prefixlen + 1)),
        ]
        if subprefix in prefixes[0]:
            return _remove_subprefix(prefixes[0], subprefix) \
                + IPSet([prefixes[1]])
        else:
            return IPSet([prefixes[0]]) + \
                _remove_subprefix(prefixes[1], subprefix)
