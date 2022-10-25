import pprint

from ping import Pinger, Reply


class FormatPrinter(pprint.PrettyPrinter):

    def __init__(self, formats):
        super(FormatPrinter, self).__init__()
        self.formats = formats

    def format(self, obj, ctx, maxlvl, lvl):
        if type(obj) in self.formats:
            return self.formats[type(obj)] % obj, 1, 0
        return pprint.PrettyPrinter.format(self, obj, ctx, maxlvl, lvl)


pinger = Pinger()
formatter = FormatPrinter({Reply: 'Reply(seq=%d, time=%.3f)'})

formatter.pprint(
    pinger.ping([
        'baidu.com',
        'google.com',
        'google.com',
        'google.com',
        'localhost',
        'localhost',
        'localhost',
        '127.0.0.1',
        '192.168.124.1',
        '192.168.124.17',
        '39.156.66.10',
        'fe80::58d3:2796:5f36:5c83',
        '172.27.240.1',
        'fe80::3da8:8868:f6e0:e758',
        '192.168.177.1',
        'fe80::b8aa:1fe6:f2f2:59ff',
        'fe80::b8aa:1fe6:f2f2:59ff%22',
        '192.168.79.1',
        'fe80::dc27:c06:fe73:6d3d',
        '192.168.124.9',
        '192.1.1.1',
        'fe80::b8aa:1fe6:f2f2:59fe',
        ], timeout=0.1, interval=0.1, count=2)
    )

formatter.pprint(
    pinger.ping_ipv4([
        '127.0.0.1',
        '192.168.124.1',
        '192.168.124.17',
        '39.156.66.10',
        '172.27.240.1',
        '192.168.177.1',
        '192.168.79.1',
        '192.168.124.9',
        '192.1.1.1',
        ], timeout=1, interval=0.1, count=1)
    )

formatter.pprint(
    pinger.ping_ipv6([
        'fe80::58d3:2796:5f36:5c83',
        'fe80::3da8:8868:f6e0:e758',
        'fe80::b8aa:1fe6:f2f2:59ff',
        'fe80::b8aa:1fe6:f2f2:59ff',
        'fe80::dc27:c06:fe73:6d3d',
        'fe80::b8aa:1fe6:f2f2:59fe',
        ], timeout=1, interval=0.1, count=1)
    )

