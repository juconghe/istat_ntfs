import datetime
import struct
import math

def as_signed_le(bs):
    signed_format = {1: 'b', 2: 'h', 4: 'l', 8: 'q'}
    if len(bs) <= 0 or len(bs) > 8:
        raise ValueError()

    fill = b'\x00'
    if ((bs[-1] & 0x80) >> 7) == 1:
        fill = b'\xFF'

    while len(bs) not in signed_format:
        bs = bs + fill
    result = struct.unpack('<' + signed_format[len(bs)], bs)[0]
    return result

def get_attribute_type(identifier):
    dic = {16:'$STANDARD_INFORMATION',48:'$FILE_NAME',128:'$DATA', 32:'$ATTRIBUTE_LIST', \
    64:'$OBJECT_ID',192:'$REPARSE_POINT',144:'$INDEX_ROOT',160:'$INDEX_ALLOCATION', \
    176:'$BITMAP'}
    return dic[identifier]

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
    entry_bytes = f[get_mft_address(f)+address*get_mft_entry_size(f): \
    get_mft_address(f)+address*get_mft_entry_size(f)+get_mft_entry_size(f)]
    return entry_bytes

def get_attribute(entry_bytes,offset):
    return entry_bytes[offset:]

def get_attr_flag(flag):
    dic = {0x0001:'Read Only',0x0002:'Hidden',0x0004:'System',0x0020:'Archive',\
    0x0040:'Device',0x0080:'#Normal',0x0100:'Temporary',0x0200:'Sparse file',\
    0x0400:'Reparse file',0x0800:'Compressed',0x1000:'Offline',\
    0x2000:'Content is not being indexed for faster searches',0x4000:'Encrypted'}
    return dic[as_signed_le(flag)]

def parse_standard_info(content):
    flags = get_attr_flag(content[32:36])
    print('Flags: {}'.format(flags))
    owner_id = 0
    print('Owner ID: {}'.format(owner_id))
    create_time = into_localtime_string(as_signed_le(content[:8]))
    modified_time = into_localtime_string(as_signed_le(content[8:16]))
    mft_modified_time = into_localtime_string(as_signed_le(content[16:24]))
    accessed_time = into_localtime_string(as_signed_le(content[24:32]))
    print('Created:    {}'.format(create_time))
    print('File Modified:  {}'.format(modified_time))
    print('MFT Modified:   {}'.format(mft_modified_time))
    print('Accessed:   {}'.format(accessed_time))

def parse_file_name(content):
    flags = get_attr_flag(content[56:60])
    name = content[66:].decode('ascii').strip()
    parent_mft_entry = as_signed_le(content[0:6])
    sequence_number = as_signed_le(content[6:8])
    allocated_size = as_signed_le(content[40:48])
    actual_size = as_signed_le(content[48:56])
    print('Flags: {}'.format(flags))
    print('Name: {}'.format(name))
    print('Parent MFT Entry: {}     Sequence: {}'.format(parent_mft_entry,sequence_number))
    print('Allocated Size: {}      Actual Size: {}'.format(allocated_size,actual_size))
    create_time = into_localtime_string(as_signed_le(content[8:16]))
    modified_time = into_localtime_string(as_signed_le(content[16:24]))
    mft_modified_time = into_localtime_string(as_signed_le(content[24:32]))
    accessed_time = into_localtime_string(as_signed_le(content[32:40]))
    print('Created:    {}'.format(create_time))
    print('File Modified:  {}'.format(modified_time))
    print('MFT Modified:   {}'.format(mft_modified_time))
    print('Accessed:   {}'.format(accessed_time))


def istat_ntfs(f, address, sector_size=512, offset=0):
    data = f.read()
    # print('Bytes Per Sector {}'.format(get_sector_size(data)))
    # print('Sector per Cluster {}'.format(get_sector_per_cluster(data)))
    # print('Cluster Size {}'.format(get_cluster_size(data)))
    # print('Entry Size {}'.format(get_mft_entry_size(data)))
    # print('Index record Size {}'.format(get_index_record_size(data)))
    # print('Entry Byte {}'.format(get_entry(data,address)[:16]))
    entry_bytes = get_entry(data,address)
    log_file_sequence_num = as_signed_le(entry_bytes[8:16])
    sequence_value = as_signed_le(entry_bytes[16:18])
    link_count = as_signed_le(entry_bytes[18:20])
    print('MFT Entry Header Values:')
    print('Entry: {}        Sequence: {}'.format(address,sequence_value))
    print('$LogFile Sequence Number: {}'.format(log_file_sequence_num))
    print('Allocated File')
    print('Links: {}'.format(link_count))
    attr_offset = as_signed_le(entry_bytes[20:22])
    # print('Offset is {}'.format(attr_offset))
    attr_bytes = get_attribute(entry_bytes,attr_offset)
    attr_index = 0
    while True:
        attr_header = attr_bytes[attr_index:attr_index+16]
        attr_size = as_signed_le(attr_header[4:8])
        # print(hex(attr_size))
        if attr_size == 0xffffffff:
            break
        attr_identifier = get_attribute_type(as_signed_le(attr_header[:4]))
        print('{} Attribute Values:'.format(attr_identifier))
        name_len = as_signed_le(attr_header[9:10])
        non_resident_flag = 'Resident' if as_signed_le(attr_header[8:9])==0 else 'Non-resident'
        attr = attr_bytes[attr_index:attr_index+attr_size]
        content_size = as_signed_le(attr[16:20]) if non_resident_flag=='Resident' else as_signed_le(attr[48:56])
        content_offset = as_signed_le(attr[20:22])
        # print('Name {}'.format(name_len))
        # print(non_resident_flag)
        # print('Size {}'.format(content_size))
        # print('Offset to Content {}'.format(content_offset))
        content = attr[content_offset:content_offset+content_size]
        if attr_identifier == '$STANDARD_INFORMATION':
            parse_standard_info(content)
        elif attr_identifier == '$FILE_NAME':
            parse_file_name(content)
        print('\n')
        attr_index += attr_size


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
