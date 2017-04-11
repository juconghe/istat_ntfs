import datetime
import struct
import math

def as_signed_le(bs):
    signed_format = {1: 'b', 2: 'h', 4: 'l', 8: 'q'}
    if len(bs) <= 0 or len(bs) > 8:
        raise ValueError()

    fill = '\x00'
    if ((bs[-1] & 0x80) >> 7) == 1:
        fill = '\xFF'

    while len(bs) not in signed_format:
        bs = bs + fill
    result = struct.unpack('<' + signed_format[len(bs)], bs)[0]
    return result

def get_sector_size(f):
    boot_sector = get_boot_sector(f)
    return as_signed_le(boot_sector[11:13])

def get_sector_per_cluster(f):
    boot_sector = get_boot_sector(f)
    return as_signed_le(boot_sector[13:14])

def get_total_sectors(f):
    boot_sector = get_boot_sector(f)
    return as_signed_le(boot_sector[40:48])

def get_cluster_size(f):
    return get_sector_size(f)*get_sector_per_cluster(f)

def get_mft_address(f):
    boot_sector = get_boot_sector(f)
    mft_cluster_address = as_signed_le(boot_sector[48:56])
    return mft_cluster_address*get_cluster_size(f)

def get_index_record_size(f):
    boot_sector = get_boot_sector(f)
    # return boot_sector[64]
    return as_signed_le(boot_sector[68:69])

def get_mft_entry_size(f):
    boot_sector = get_boot_sector(f)
    value = as_signed_le(boot_sector[64:65])
    if value < 0:
        return int(math.pow(2,abs(value)))
    else:
        return value*get_cluster_size(f)

def get_boot_sector(f,sector_size=512):
    return f[:sector_size]

def get_entry(f,address):
    entry_bytes = f[get_mft_address(f):get_mft_address(f)*get_mft_entry_size(f)]
    return entry_bytes

def get_attribute(entry_bytes,offset):
    return entry_bytes[offset:]

def istat_ntfs(f, address, sector_size=512, offset=0):
    data = f.read()
    print('Bytes Per Sector {}'.format(get_sector_size(data)))
    print('Sector per Cluster {}'.format(get_sector_per_cluster(data)))
    print('Cluster Size {}'.format(get_cluster_size(data)))
    print('Entry Size {}'.format(get_mft_entry_size(data)))
    print('Index record Size {}'.format(get_index_record_size(data)))
    # print('Entry Byte {}'.format(get_entry(data,0)[:16]))
    entry_bytes = get_entry(data,address)
    attr_offset = as_signed_le(entry_bytes[4:6])
    first_attr = get_attribute(entry_bytes,attr_offset)
    print('First attribute is {}'.format(first_attr[:16]))


def into_localtime_string(windows_timestamp):
    """
    Convert a windows timestamp into istat-compatible output.

    Assumes your local host is in the EDT timezone.

    :param windows_timestamp: the struct.decoded 8-byte windows timestamp
    :return: an istat-compatible string representation of this time in EDT
    """
    dt = datetime.datetime.fromtimestamp((windows_timestamp - 116444736000000000) / 10000000)
    hms = dt.strftime('%Y-%m-%d %H:%M:%S')
    fraction = windows_timestamp % 10000000
    return hms + '.' + str(fraction) + '00 (EDT)'


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Display details of a meta-data structure (i.e. inode).')
    parser.add_argument('-o', type=int, default=0, metavar='imgoffset',
                        help='The offset of the file system in the image (in sectors)')
    parser.add_argument('-b', type=int, default=512, metavar='dev_sector_size',
                        help='The size (in bytes) of the device sectors')
    parser.add_argument('image', help='Path to an NTFS raw (dd) image')
    parser.add_argument('address', type=int, help='Meta-data number to display stats on')
    args = parser.parse_args()
    with open(args.image, 'rb') as f:
        result = istat_ntfs(f, args.address, args.b, args.o)
        for line in result:
            print(line.strip())
