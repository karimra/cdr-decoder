#!/usr/bin/env python3

import os
import sys
import argparse
from cdr.cdr import CdrFile


def main():

    parser = argparse.ArgumentParser(description='CDR Decoder')
    parser.add_argument('file', nargs='?', type=str, action='store', default='', help='File to decode')
    parser.add_argument('-p', '--print', action='store_true', default=False, help='print decoded cdrs to prompt')
    parser.add_argument('-d', '--details', action='store_true', default=False, help='show more details')
    parser.add_argument('-f', '--format', nargs='?', choices=['json', 'simple'], default='simple', action='store', help='output format')
    parser.add_argument('-src', '--source', action='store', default='raw_cdrs', help='raw cdr file or directory to fetch raw cdr files')
    parser.add_argument('-dst', '--destination', action='store', default='decoded_cdrs', help='directory where to write decoded cdr files')
    parser.add_argument('--inonefile', action='store_true', default=False, help='write decoded cdrs into a single file')
    dargs = vars(parser.parse_args())

    cdr_files = []
    if dargs['file']:
        print('File name given: {}'.format(dargs['file']))
        cdr_files.append(dargs['file'])
    else:
        if os.path.isdir(dargs['source']):
            print('No CDR file given, checking in directory {}'.format(dargs['source']))
            for file in os.listdir(dargs['source']):
                if file.endswith('.cdr') and 'decoded' not in file:
                    cdr_files.append(os.path.join(dargs['source'], file))
            if not cdr_files:
                print('No files found in {}'.format(dargs['source']))
                parser.print_help()
                sys.exit(1)
        else:
            print('No file specified and no default directory found')
            parser.print_help()
            sys.exit(1)

    print('Found {} file(s):'.format(len(cdr_files)))
    print('\n'.join(['\t- '+fname for fname in cdr_files]))

    for i, cdr_file in enumerate(cdr_files):
        print('\n[{}] Starting with file {}'.format(i, cdr_file))
        ff = CdrFile(path=cdr_file)

        print('[{}] Found {} CDRs'.format(i, ff.nr_records))

        if dargs['print']:
            for decoded_header, index, decoded_cdr in ff.decodeit(dargs):
                print(decoded_header)
                print('cdr_{} from file {}'.format(str(index), ff.name))
                print(decoded_cdr)
        else:
            os.makedirs(dargs['destination'], exist_ok=True)
            if dargs['inonefile']:
                destination_file = os.path.join(dargs['destination'], ff.name + '_decoded')
                for decoded_header, index, decoded_cdr in ff.decodeit(dargs):
                    decoded_header += '\n'
                    decoded_cdr += '\n'
                    with open(destination_file, 'a') as f:
                        if decoded_header:
                            f.write(decoded_header)
                        f.write(decoded_cdr)
                    if index % 1000 == 0:
                        print('[{}] {} CDRs done'.format(i, index))
            else:
                for decoded_header, index, decoded_cdr in ff.decodeit(dargs):
                    destination_file = os.path.join(dargs['destination'], 'file_header_'+ff.name+'_decoded')
                    with open(destination_file, 'w') as f:
                        f.write(decoded_header)
                    cdr_destination_file = os.path.join(dargs['destination'], 'cdr_index_'+str(index)+'_'+ff.name+'_decoded')
                    with open(cdr_destination_file, 'w') as f:
                        f.write(decoded_cdr)
        print('[{}] Done with file {}'.format(i, cdr_file))

if __name__ == '__main__':
    main()
