#

from itertools import zip_longest, islice


def decode_e212(e):
    nval = ''
    for a, b in zip_longest(islice(str(e), 0, None, 2), islice(str(e), 1, None, 2), fillvalue='f'):
        nval += b + a
    return nval