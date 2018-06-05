from binascii import hexlify


def chunk(h):
    h = str(h, 'utf-8')
    return '0x' + ', 0x'.join([h[i:i+2] for i in range(0, len(h), 2)])

def tv_bytes_rust(name, value, pad):
    print('''%s%s: [
    %s%s
%s],''' % (
        pad,
        name,
        pad,
        chunk(hexlify(value)),
        pad,
    ))

def tv_int_rust(name, value, pad):
    print('%s%s: %d,' % (pad, name, value))

def tv_part_rust(name, value, indent=3):
    pad = '    ' * indent
    if type(value) == bytes:
        tv_bytes_rust(name, value, pad)
    elif type(value) == int:
        tv_int_rust(name, value, pad)
    else:
        raise ValueError('Invalid type(%s): %s' % (name, type(value)))

def tv_rust(filename, parts, vectors):
    print('        struct TestVector {')
    [print('            %s: %s,' % p) for p in parts]
    print('''        };

        // From https://github.com/zcash-hackworks/zcash-test-vectors/blob/master/%s.py''' % (
            filename,
        ))
    if type(vectors) == type({}):
        print('        let test_vector = TestVector {')
        [tv_part_rust(p[0], vectors[p[0]]) for p in parts]
        print('        };')
    elif type(vectors) == type([]):
        print('        let test_vectors = vec![')
        for vector in vectors:
            print('            TestVector {')
            [tv_part_rust(p[0], vector[p[0]], 4) for p in parts]
            print('            },')
        print('        ];')
    else:
        raise ValueError('Invalid type(vectors)')
