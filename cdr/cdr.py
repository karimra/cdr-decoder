#!/usr/bin/env python3

import os
import ipaddress
import binascii
import json
from utils.objects import DefaultOrderedDict
from utils.funcs import clean_output
from cdr.funcs import decode_e212
from cdr.cdr_data import *
from asn1.asn1_ber import Asn1Tag
from asn1.asn1_data import *


class CdrFile(object):
    def __init__(self, path):
        self.path = path
        self.name = os.path.split(self.path)[1]
        self.content = self.open()
        self.length = int(self.content[:8], 16)
        self.header_length = int(self.content[8:16], 16)
        self.hri = ReleaseID[int(self.content[16:18], 16) >> 5]
        self.lri = ReleaseID[int(self.content[18:20], 16) >> 5]

        self.opening_timestamp = self.decode_timestamp(self.content[20:28])
        self.last_cdr_append_timestamp = self.decode_timestamp(self.content[28:36])
        self.header = self.content[:self.header_length * 2]
        self.records = self.content[self.header_length * 2:]
        self.nr_records = int(self.content[36:44], 16)
        self.seq_num = int(self.content[44:52], 16)
        self.closure_trigger_reason = FileClosureTriggerReasons[int(self.header[52:54])]
        self.src_ip = ipaddress.IPv4Address(int(self.header[54:94][-8:], 16)).compressed
        self.lost_cdr = self.lost_cdrs()
        self.length_of_CDR_routeing_filter = int(self.content[96:100], 16)
        self.CDR_routeing_filter = self.content[100: 100 + self.length_of_CDR_routeing_filter *2]

        self.length_of_private_extension = int(self.content[100 + self.length_of_CDR_routeing_filter *2: 100 + self.length_of_CDR_routeing_filter *2 + 2], 16)

        self.private_extension = ''
        if self.length_of_private_extension:
            self.private_extension = self.content[100 + self.length_of_CDR_routeing_filter *2 + 2: 100 + self.length_of_CDR_routeing_filter *2 + 2 + self.length_of_private_extension]

        if self.hri == 'Beyond Rel-9':
            hri_ext_hex = self.content[100 + self.length_of_CDR_routeing_filter *2 + 2 + self.length_of_private_extension + 2 : 100 + self.length_of_CDR_routeing_filter *2 + 2 + self.length_of_private_extension + 4]
            self.hri_ext = ReleaseIDExt[int(hri_ext_hex, 16)]
        if self.lri == 'Beyond Rel-9':
            lri_ext_hex = self.content[100 + self.length_of_CDR_routeing_filter *2 + 2 + self.length_of_private_extension + 4 : 100 + self.length_of_CDR_routeing_filter *2 + 2 + self.length_of_private_extension + 6]
            self.lri_ext = ReleaseIDExt[int(lri_ext_hex, 16)]

        hrelease = 'Rel-11'
        lrelease = 'Rel-11'
        if self.hri == 'Beyond Rel-9':
            hrelease = self.hri_ext
        if self.lri == 'Beyond Rel-9':
            lrelease = self.lri_ext
        self.hvi = TSNumber[hrelease][int(self.content[16:18], 16) & 31]
        self.lvi = TSNumber[lrelease][int(self.content[18:20], 16) & 31]

        self.high_release_encoding = ' '.join(['TS'+self.hvi, hrelease,])
        self.low_release_encoding = ' '.join(['TS ' + self.lvi, lrelease,])

    def open(self):
        with open(self.path, 'rb') as cdrfile:
            file = binascii.hexlify(cdrfile.read()).decode()
        return file

    def decode_header(self):
        d = DefaultOrderedDict()
        d['name'] = self.name
        d['opening_timestamp'] = self.opening_timestamp
        d['last_cdr_append_timestamp'] = self.last_cdr_append_timestamp
        d['nr_records'] = self.nr_records
        d['seq_num'] = self.seq_num
        d['closure_trigger_reason'] = self.closure_trigger_reason
        d['src_ip'] = self.src_ip
        d['high_release_encoding'] = self.high_release_encoding
        d['low_release_encoding'] = self.low_release_encoding
        return d

    @staticmethod
    def decode_timestamp(timestamp):
        '''
        - The first four binary bits indicate the month (1 .. 12), according to the CGF's local time zone;
        - The next five binary bits contain the date (1 :: 31), according to the CGF's local time zone;
        - The next five binary bits contain the hour (0 .. 23), according to the CGF's local time zone;
        - The next six binary bits contain the minute (0 .. 59), according to the CGF's local time zone;
        - The next bit indicates the sign of the local time differential from UTC (bit set to "1" expresses "+" or bit set to "0" expresses "-" time deviation),
                  in case the time differential to UTC is 0 then the sign may be arbitrarily set to "+" or "-";
        - The next five binary bits contain the hour (0 .. 23) deviation of the local time towards UTC, according to the CGF's local time zone;
        - The next six binary bits contain the minute (0 .. 59) deviation of the local time towards UTC, according to the CGF's local time zone;
        :return:
        '''
        t = int(timestamp, 16)
        mm = str(t >> 28)
        dd = str((t >> 23) & 31)
        hh = str((t >> 18) & 31)
        mn = str((t >> 12) & 63)
        dev = '-'
        if (t >> 11) & 1:
            dev = '+'
        dev = 'UTC'+dev
        tdhh = str((t >> 6) & 31).zfill(2)
        tdmn = str(t & 63).zfill(2)
        return mm + '-' + dd + ' '+ hh + ':' + mn + ' ' + dev + tdhh + ':' + tdmn

    def lost_cdrs(self):
        data = self.content[94:96]
        result = ''
        if data == '00':
            result = 0
        elif int(data, 16) >> 7:
            # MSB =1
            if int(data, 16) << 1 == 127:
                # all 1
                result = '127 or more'
            elif int(data, 16) << 1:
                # not all  0
                result = int(data, 16) << 1
            else:
                # all 0
                result = 'Unknown'
        else:
            # MSB = 0
            if int(data, 16) < 127:
                result = str(int(data, 16) << 1) +' or more'
            else:
                result = '127 or more'

        return result

    def get_cdrs(self):
        records = self.records
        while records:
            cdr_length = int(records[:4], 16)
            cdr_header = records[:5 * 2]
            cdr = records[5 * 2: (5 + cdr_length) * 2]
            yield cdr_length, cdr_header, cdr
            records = records[(5 + cdr_length) * 2:]

    def decodeit(self, dargs):
        i = 1
        decoded_header = json.dumps(self.decode_header(), indent=4)
        for cdr_length, cdr_header, cdr in self.get_cdrs():
            c_cdr = Cdr(raw=cdr)
            if dargs['details']:
                decoded_cdr = json.dumps(c_cdr.to_json(), indent=4)
            else:
                decoded_cdr = json.dumps(c_cdr.to_simple_json(), indent=4)

            if dargs['format'] == 'simple':
                decoded_header = clean_output(decoded_header)
                decoded_cdr = clean_output(decoded_cdr)

            if i == 1:
                yield decoded_header, i, decoded_cdr
            else:
                yield '', i, decoded_cdr
            i += 1


class Cdr(Asn1Tag):
    def __init__(self, raw, parent=[]):
        Asn1Tag.__init__(self, raw, parent=parent)

    def get_children(self):
        chl = []
        if self.type == 1:
            d = self.data
            while d:
                ch = Cdr(raw=d, parent=self)
                chl.append(ch)
                d = d[(ch.tag[1] + ch.length[0] + ch.length[1]) * 2 :]
        return chl

    @staticmethod
    def decode_val(name, t, v, vt):
        if vt == 'RecordType':
            #
            dv = records_types[int(v, 16)]
        elif vt in ['IMSI', 'PLMN-Id', 'MSISDN']:
            dv = decode_e212(v)
            dv = dv.replace('f', '')
            if vt in ['MSISDN']:
                dv = dv[2:]
        elif vt == 'IPAddress':
            #
            dv = ipaddress.IPv4Address(int(v[:8], 16)).compressed
        elif vt == 'ChargingID':
            # convert to decimal ???????
            dv = v
        elif vt in ['AccessPointNameNI', 'NodeID']:
            #
            dv = str(binascii.unhexlify(v))[2:-1]
        elif vt == 'PDPType':
            # 3GPP TS 29.060 version 12.6.0 Release 12, 7.7.27 End User Address
            pdp_org = v[:2].replace('f', '')
            pdp_type = v[2:]
            if pdp_org == '1':
                pdp_org = 'IETF'
            elif pdp_org == '0':
                pdp_org = 'ETSI'

            if pdp_type == '21':
                pdp_type = 'IPv4'
            elif pdp_type == '57':
                pdp_type = 'IPv6'
            elif pdp_type == '8d':
                pdp_type = 'IPv4v6'
            dv = ' '.join([pdp_org, pdp_type])
        elif vt == 'DynamicAddressFlag':
            dv = 'False'
            if v == '01':
                dv = 'True'
        elif vt == 'TimeStamp':
            yyyy = '20' + v[:2]
            mmdd = v[2:4] + '-' + v[4:6]
            hhmmss = ':'.join([v[i:i + 2] for i in range(6, 12, 2)])
            tz = chr(int(v[-6:-4], 16)) + v[-4:]
            dv = yyyy + '-' + mmdd + ' ' + hhmmss + ' ' + tz
        elif vt in ['CallDuration', 'DataVolumeGPRS', 'INTEGER', 'LocalSequenceNumber', 'RatingGroupId',
                    'ChargingCharacteristics']:
            #
            dv = int(v, 16)
        elif vt == 'MSTimeZone':
            #
            dv = 'GMT+' + str(int(v[:2], 16) // 4)
        elif vt == 'ChChSelectionMode':
            #
            dv = ChChSelectionModes[int(v, 16)]
        elif vt == 'APNSelectionMode':
            #
            dv = APNSelectionModes[int(v, 16)]
        elif vt == 'ServiceConditionChange':
            list_of_change_conditions = []
            for k in ServiceConditionChanges.keys():
                if (1 << k) & int(v, 16) != 0:
                    list_of_change_conditions.append(ServiceConditionChanges[k])
            dv = list_of_change_conditions
        elif vt == 'ENUMERATED' and name == 'servingNodeType':
            #
            dv = servingNodeTypes[int(v, 16)]
        elif vt == 'RATType':
            #
            dv = ratypes[int(v, 16)]
        elif vt == 'CauseForRecClosing':
            #
            dv = RecordClosingCause[int(v, 16)]
        elif name == 'userLocationInformation':
            dv = v[2:]
            if len(dv) == 24:
                tai = dv[:10]
                ecgi= dv[10:]

                tai_mcc_mnc = decode_e212(tai[:6]).replace('f', '')
                tac = tai[6:]

                ecgi_mcc_mnc = decode_e212(ecgi[:6]).replace('f', '')
                cgi = int(ecgi[6:], 16)
                enbid = cgi // 256
                cellid = cgi % 256

                dv = 'tai: (mcc_mnc: ' + str(tai_mcc_mnc) + ', tac:' + str(tac) + \
                     '), ecgi: (mcc_mnc: ' + str(ecgi_mcc_mnc) + \
                     ', enbid: ' + str(enbid) + ', cellId:' + str(cellid) + ')'
            elif len(dv) == 14:
                mcc_mnc = decode_e212(dv[:6]).replace('f', '')
                lac = int(dv[6:10], 16)
                sac = int(dv[10:], 16)
                dv = 'mcc_mnc: ' + str(mcc_mnc) + ', lac: ' + str(lac) + ', sac: ' + str(sac)
            else:
                dv = v
        else:
            #
            dv = v
        return dv

    def to_json(self, defs=records_defs['pGWRecord']):
        d = DefaultOrderedDict()
        d['Name'] = defs[self.tag[0]]['name']
        d['Class'] = asn1_classes[self.cla]
        d['Type'] = asn1_types[self.type]
        d['Tag'] = self.tag[0]
        d['Tag_list'] = self.tag_list
        d['Data_Type'] = defs[self.tag[0]]['type']
        d['Data_Raw'] = self.data
        d['Data_Decoded'] = self.decode_val(d['Name'], d['Type'], d['Data_Raw'], d['Data_Type'])
        if self.children:
            d['Children'] = []
            for c in self.children:
                d['Children'].append(c.to_json(defs=defs[c.parent.tag[0]]['children']))
        return d

    def to_simple_json(self, defs=records_defs['pGWRecord']):
        d = DefaultOrderedDict()
        if asn1_types[self.type] == 'primitive':
            d[defs[self.tag[0]]['name']] = self.decode_val(defs[self.tag[0]]['name'], asn1_types[self.type], self.data, defs[self.tag[0]]['type'])
        else:
            d[defs[self.tag[0]]['name']] = []
            for c in self.children:
                d[defs[self.tag[0]]['name']].append(c.to_simple_json(defs=defs[c.parent.tag[0]]['children']))

        return d
