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
    dic = {16:('$STANDARD_INFORMATION','(16-0)'),48:('$FILE_NAME','(48-3)'),128:('$DATA','(128-2)')}
    if identifier in dic:
        return dic[identifier]
    else:
        return None

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

def get_attr_flag(flag):
    dic = {0x0001:'Read Only',0x0002:'Hidden',0x0004:'System',0x0020:'Archive',\
    0x0040:'Device',0x0080:'#Normal',0x0100:'Temporary',0x0200:'Sparse file',\
    0x0400:'Reparse file',0x0800:'Compressed',0x1000:'Offline',\
    0x2000:'Content is not being indexed for faster searches',0x4000:'Encrypted'}
    return dic[as_signed_le(flag)]

def parse_standard_info(content,attr_identifier):
    flags = get_attr_flag(content[32:36])
    info_list = []
    info_list.append('{} Attribute Values:'.format(attr_identifier))
    info_list.append('Flags: {}'.format(flags))
    owner_id = 0
    info_list.append('Owner ID: {}'.format(owner_id))
    create_time = into_localtime_string(as_signed_le(content[:8]))
    modified_time = into_localtime_string(as_signed_le(content[8:16]))
    mft_modified_time = into_localtime_string(as_signed_le(content[16:24]))
    accessed_time = into_localtime_string(as_signed_le(content[24:32]))
    info_list.append('Created:	{}'.format(create_time))
    info_list.append('File Modified:	{}'.format(modified_time))
    info_list.append('MFT Modified:	{}'.format(mft_modified_time))
    info_list.append('Accessed:	{}\n'.format(accessed_time))
    info_list.append('')
    return info_list

def parse_file_name(content,attr_identifier):
    flags = get_attr_flag(content[56:60])
    info_list = []
    name = content[66:].decode('utf-16le').strip()
    parent_mft_entry = as_signed_le(content[0:6])
    sequence_number = as_signed_le(content[6:8])
    allocated_size = as_signed_le(content[40:48])
    actual_size = as_signed_le(content[48:56])
    info_list.append('{} Attribute Values:'.format(attr_identifier))
    info_list.append('Flags: {}'.format(flags))
    info_list.append('Name: {}'.format(name))
    info_list.append('Parent MFT Entry: {} \tSequence: {}'.format(parent_mft_entry,sequence_number))
    info_list.append('Allocated Size: {}   \tActual Size: {}'.format(allocated_size,actual_size))
    create_time = into_localtime_string(as_signed_le(content[8:16]))
    modified_time = into_localtime_string(as_signed_le(content[16:24]))
    mft_modified_time = into_localtime_string(as_signed_le(content[24:32]))
    accessed_time = into_localtime_string(as_signed_le(content[32:40]))
    info_list.append('Created:	{}'.format(create_time))
    info_list.append('File Modified:	{}'.format(modified_time))
    info_list.append('MFT Modified:	{}'.format(mft_modified_time))
    info_list.append('Accessed:	{}'.format(accessed_time))
    info_list.append('')
    return info_list

def parse_data_attr(f,attr_bytes):
    # print(get_attribute_type(as_signed_le(attr_bytes[:4])))
    start_vcn = as_signed_le(attr_bytes[16:24])
    end_vcn = as_signed_le(attr_bytes[24:32])
    # print(end_vcn)
    runlist_offset = as_signed_le(attr_bytes[32:34])
    run_header_value = attr_bytes[runlist_offset]
    length_mask = 0x0f
    previous_cluster = 0
    info_list = []
    while run_header_value != 0:
        temp_run_offset = as_signed_le(bytes([run_header_value>>4]))
        temp_run_length = as_signed_le(bytes([run_header_value&length_mask]))
        runlist_offset += 1
        cluster_run_length = as_signed_le(attr_bytes[runlist_offset:runlist_offset+temp_run_length])
        cluster_offset = as_signed_le(attr_bytes[runlist_offset+temp_run_length:\
        runlist_offset+temp_run_length+temp_run_offset])
        current_cluster = previous_cluster + cluster_offset
        for i in range(0,cluster_run_length):
            info_list.append(current_cluster+i)
        previous_cluster = current_cluster
        runlist_offset += temp_run_length+temp_run_offset
        run_header_value = attr_bytes[runlist_offset]
    temp = ''
    count = 0
    str_list = []
    for i in range(0,len(info_list)):
        # print(info_list[i])
        if count == 8:
            str_list.append(temp)
            temp = str(info_list[i])+' '
            count = 1
        else:
            temp += str(info_list[i])+' '
            count += 1
    str_list.append(temp)
    return str_list

def istat_ntfs(f, address, sector_size=512, offset=0):
    f.seek(offset)
    data = f.read()
    info_list = []
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
    info_list.append('MFT Entry Header Values:')
    info_list.append('Entry: {}        Sequence: {}'.format(address,sequence_value))
    info_list.append('$LogFile Sequence Number: {}'.format(log_file_sequence_num))
    info_list.append('Allocated File')
    info_list.append('Links: {}'.format(link_count))
    info_list.append('')
    attr_offset = as_signed_le(entry_bytes[20:22])
    # print('Offset is {}'.format(attr_offset))
    attr_list = []
    while True:
        # print(attr_offset)\
        attr_header = entry_bytes[attr_offset:attr_offset+16]
        # print(attr_header.hex())
        if attr_header[:4] == b'\xff\xff\xff\xff':
            break
        attr_size = as_signed_le(attr_header[4:8])
        # print(hex(attr_size))
        attr_identifier = get_attribute_type(as_signed_le(attr_header[:4]))
        if attr_identifier != None:
            name_len = as_signed_le(attr_header[9:10])
            non_resident_flag = 'Resident' if as_signed_le(attr_header[8:9])==0 else 'Non-Resident'
            attr = entry_bytes[attr_offset:attr_offset+attr_size]
            content_size = as_signed_le(attr[16:20]) if non_resident_flag=='Resident' else as_signed_le(attr[48:56])
            attr_str = 'Type: {} {}   Name: N/A   {}   size: {}'.format(attr_identifier[0],\
            attr_identifier[1],non_resident_flag,content_size) if non_resident_flag=='Resident' else \
            'Type: {} {}   Name: N/A   {}   size: {}  init_size: {}'.format(attr_identifier[0],\
            attr_identifier[1],non_resident_flag,content_size,as_signed_le(attr[56:64]))
            attr_list.append(attr_str)
            content_offset = as_signed_le(attr[20:22])
            # print('Name {}'.format(name_len))
            # print(non_resident_flag)
            # print('Size {}'.format(content_size))
            # print('Offset to Content {}'.format(content_offset))
            content = attr[content_offset:content_offset+content_size]
            if attr_identifier[0] == '$STANDARD_INFORMATION':
                info_list.extend(parse_standard_info(content,attr_identifier[0]))
            elif attr_identifier[0] == '$FILE_NAME':
                info_list.extend(parse_file_name(content,attr_identifier[0]))
            else:
                if non_resident_flag == 'Non-Resident':
                    attr_list.extend(parse_data_attr(data,content))
        attr_offset += attr_size
    info_list.append('Attributes:')
    info_list.extend(attr_list)
    return info_list


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
            pass
