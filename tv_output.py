def chunk(h):
    h = str(h, 'utf-8')
    return '0x' + ', 0x'.join([h[i:i+2] for i in range(0, len(h), 2)])
