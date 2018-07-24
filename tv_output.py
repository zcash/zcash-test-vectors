import argparse
from binascii import hexlify
import json


def chunk(h):
    hstr = str(h, 'utf-8')
    return '0x' + ', 0x'.join([hstr[i:i+2] for i in range(0, len(hstr), 2)])


#
# JSON (with string comments)
# If bitcoin_flavoured == True, 32-byte values are reversed
#

def tv_value_json(value, bitcoin_flavoured):
    if type(value) == bytes:
        if bitcoin_flavoured and len(value) == 32:
            value = value[::-1]
        value = hexlify(value).decode()
    return value

def tv_json(filename, parts, vectors, bitcoin_flavoured):
    if type(vectors) == type({}):
        vectors = [vectors]

    print('''[
    ["From https://github.com/zcash-hackworks/zcash-test-vectors/blob/master/%s.py"],
    ["%s"],''' % (
        filename,
        ', '.join([p[0] for p in parts])
    ))
    print('    ' + ',\n    '.join([
        json.dumps([tv_value_json(v[p[0]], bitcoin_flavoured) for p in parts]) for v in vectors
    ]))
    print(']')


#
# Rust
#

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


#
# Rendering functions
#

def render_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', choices=['zcash', 'rust'], default='rust')
    return parser.parse_args()

def render_tv(args, filename, parts, vectors):
    if args.target == 'rust':
        tv_rust(filename, parts, vectors)
    elif args.target == 'zcash':
        tv_json(filename, parts, vectors, True)
