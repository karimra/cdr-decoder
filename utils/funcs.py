import re

def clean_output(s):
    for c in ['{', '}', '[', ']', ',', '"']:
        s = s.replace(c, '')
    s = re.sub(r'\s*\n', '\n', s)
    return s