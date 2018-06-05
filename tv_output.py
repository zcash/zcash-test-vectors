from binascii import hexlify


def chunk(h):
    h = str(h, 'utf-8')
    return '0x' + ', 0x'.join([h[i:i+2] for i in range(0, len(h), 2)])

def tv_part_rust(name, value):
    print('''            %s: [
                %s
            ],''' % (
                name,
                chunk(hexlify(value))
            ))

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
    else:
        raise ValueError('Invalid type(vectors)')
