# cdr-decoder
simple PGW cdr decoder



usage: cdr_decoder.py [-h] [-p] [-d] [-f [{json,simple}]] [-src SOURCE]
                      [-dst DESTINATION] [--inonefile]
                      [file]

CDR Decoder

positional arguments:
  file                  File to decode

optional arguments:
  -h, --help            show this help message and exit
  -p, --print           print decoded cdrs to prompt
  -d, --details         show more details
  -f [{json,simple}], --format [{json,simple}]
                        output format
  -src SOURCE, --source SOURCE
                        raw cdr file or directory to fetch raw cdr files
  -dst DESTINATION, --destination DESTINATION
                        directory where to write decoded cdr files
  --inonefile           write decoded cdrs into a single file
