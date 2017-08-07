

class Asn1Tag(object):
    def __init__(self, raw, parent=[]):
        self.raw = raw
        self.cla = self.get_cla()
        self.type = self.get_type()
        self.tag = self.get_tag()  # tuple:     tag and len_tag
        self.length = self.get_length()  # tuple:    length and len_length_field
        self.data = self.get_data()
        self.parent = parent
        self.children = self.get_children()
        self.tag_list = self.get_taglist()

    def get_cla(self):
        return int(self.raw[0], 16) >> 2

    def get_type(self):
        return (int(self.raw[0], 16) & 0b0010) >> 1

    def get_tag(self):
        obj_tag = int(self.raw[:2], 16) & 0b00011111
        tag_len = 1

        if obj_tag == 0b11111:  # if the remaining 5 bits of the first byte are all 1s
            obj_tag = int(self.raw[2:4], 16) & 0b01111111  # the object tag is the next byte,... or more
            if (int(self.raw[2:4],16) & 0b10000000) == 0b1:  # next byte ( minus leading bit) is included in the tag if its leading bit is a 1
                for i in range(4, len(self.raw[4:]), 2):
                    obj_tag = (obj_tag << 7) | (int(self.raw[i:i + 2], 16) & 0b01111111)  # Concatenate bytes as bits after droping leading bit
                    if int(self.raw[i:i + 2], 16) >> 7 == 0b0:
                        tag_len = i - 1
                        break
            else:
                tag_len = 2
        return obj_tag, tag_len

    def get_length(self):
        lc = self.raw[(self.get_tag()[1]) * 2:]
        if int(lc[:2], 16) == 128:
            return 'NA', 'NA'

        elif int(lc[:2], 16) < 128:
            len_length = 0
            length = int(lc[len_length:2], 16)
            len_length_field = len_length + 1

        elif int(lc[:2], 16) > 128:
            len_length = int(lc[:2], 16) - 128
            length = int(lc[2:2+len_length*2], 16)
            len_length_field = len_length + 1
        else:
            return 'Could not determine this value\'s range {}'.format(int(lc[:2], 16))
        return length, len_length_field

    def get_data(self):
        if self.length != ('NA', 'NA'):
            return self.raw[(self.tag[1] + self.length[1]) * 2: (self.tag[1] + self.length[1] + self.length[0]) * 2]
        else:
            pass

    def get_children(self):
        chl = []
        if self.type == 1:
            d = self.data
            while d:
                ch = Asn1Tag(raw=d, parent=self)
                chl.append(ch)
                d = d[(ch.tag[1] + ch.length[0] + ch.length[1]) * 2 :]
        return chl

    def get_taglist(self):
        l = str(self.tag[0])
        if self.parent:
            l = self.parent.get_taglist() + '_' + l
        return l

    def decode_vals(self):
        return self.data

    def printit_rec(self, indent=0, sep='\t', defs=dict):
        print( indent      * sep, 'Tag:', self.tag)
        #print( indent      * sep, 'Tag_list:', self.tag_list)
        print( indent      * sep, 'TagName:', defs[self.tag[0]]['name'])
        print((indent + 1) * sep, 'Data:', self.data)
        for c in self.children:
            c.printit_rec(indent=len(self.tag_list.split('_')), defs=defs[c.parent.tag[0]]['children'])