#!/usr/bin/env python3
import sys; assert sys.version_info[0] >= 3, "Python 3 required."

import argparse
from binascii import hexlify
import json
import os
import subprocess


def chunk(h):
    hstr = str(h, 'utf-8')
    hstr = ', 0x'.join([hstr[i:i+2] for i in range(0, len(hstr), 2)])
    return '0x' + hstr if hstr else ''

class Some(object):
    def __init__(self, thing):
       self.thing = thing

def option(x):
    return Some(x) if x else None

#
# JSON (with string comments)
# If bitcoin_flavoured == True, 32-byte values are reversed
#

def tv_value_json(value, bitcoin_flavoured):
    if isinstance(value, Some):
        value = value.thing

    def bitcoinify(value):
        if type(value) == tuple:
            return tuple((bitcoinify(v) for v in value))

        if type(value) == list:
            return [bitcoinify(v) for v in value]

        if type(value) == str:
            return value

        if type(value) == bytes:
            if bitcoin_flavoured and len(value) == 32:
                value = value[::-1]
            value = hexlify(value).decode()
        return value

    return bitcoinify(value)

def tv_json(source_path, parts, vectors, bitcoin_flavoured, file=sys.stdout):
    if type(vectors) == type({}):
        vectors = [vectors]

    print('''[
    ["From https://github.com/zcash/zcash-test-vectors/blob/master/%s.py"],
    ["%s"],''' % (
        source_path,
        ', '.join([p[0] for p in parts])
    ), file=file)
    print('    ' + ',\n    '.join([
        json.dumps([tv_value_json(v[p[0]], p[1].get('bitcoin_flavoured', bitcoin_flavoured)) for p in parts]) for v in vectors
    ]), file=file)
    print(']', file=file)


#
# Rust
#

def tv_bytes_rust(name, value, pad, kind="", file=sys.stdout):
    print('''%s%s: %s[
    %s%s
%s],''' % (
        pad,
        name,
        kind,
        pad,
        chunk(hexlify(value)),
        pad,
    ), file=file)

def tv_slice_bool_rust(name, value, pad, file=sys.stdout):
    print('''%s%s: &[
    %s%s
%s],''' % (
        pad,
        name,
        pad,
        ', '.join(['true' if x else 'false' for x in value]),
        pad,
    ), file=file)

def tv_tuple_int_bytes_rust(name, value, pad, file=sys.stdout):
    print("%s%s: &[" % (pad, name), file=file)
    for (i, t) in value:
        print("%s    (%d, &[%s])," % (pad, i, chunk(hexlify(t))), file=file)

    print("%s]," % (pad,), file=file)

def tv_str_rust(name, value, pad, file=sys.stdout):
    print('''%s%s: "%s",''' % (
        pad,
        name,
        value,
    ), file=file)

def tv_option_bytes_rust(name, value, pad, kind="", file=sys.stdout):
    if value:
        print('''%s%s: Some(%s[
    %s%s
%s]),''' % (
            pad,
            name,
            kind,
            pad,
            chunk(hexlify(value.thing)),
            pad,
        ), file=file)
    else:
        print('%s%s: None,' % (pad, name), file=file)

def tv_int_rust(name, value, pad, file=sys.stdout):
    print('%s%s: %d,' % (pad, name, value), file=file)

def tv_option_int_rust(name, value, pad, file=sys.stdout):
    if value:
        print('%s%s: Some(%d),' % (pad, name, value.thing), file=file)
    else:
        print('%s%s: None,' % (pad, name), file=file)

def tv_part_rust(name, value, config, indent=3, file=sys.stdout):
    if 'rust_fmt' in config:
        value = config['rust_fmt'](value)
    elif config['rust_type'].startswith('Option<') and not (value is None or isinstance(value, Some)):
        value = Some(value)

    pad = '    ' * indent
    if config['rust_type'] == 'Option<&\'static [u8]>':
        tv_option_bytes_rust(name, value, pad, kind="&", file=file)
    elif config['rust_type'] == '&\'static [u8]':
        tv_bytes_rust(name, value, pad, kind="&", file=file)
    elif config['rust_type'] == '&\'static [bool]':
        tv_slice_bool_rust(name, value, pad, file=file)
    elif config['rust_type'] == '&\'static [(u32, &\'static [u8])]':
        tv_tuple_int_bytes_rust(name, value, pad, file=file)
    elif config['rust_type'] == '&\'static str':
        tv_str_rust(name, value, pad, file=file)
    elif config['rust_type'].startswith('Option<[u8'):
        tv_option_bytes_rust(name, value, pad, file=file)
    elif type(value) == bytes:
        tv_bytes_rust(name, value, pad, file=file)
    elif config['rust_type'].startswith('Option<'):
        tv_option_int_rust(name, value, pad, file=file)
    elif type(value) == int:
        tv_int_rust(name, value, pad, file=file)
    elif type(value) == list:
        rust_type = config['rust_type']
        if rust_type.startswith('&'):
            print('''%s%s: &[''' % (pad, name), file=file)
        else:
            print('''%s%s: [''' % (pad, name), file=file)
        for item in value:
            if '&\'static [u8]' in rust_type:
                print('''%s&[
    %s%s
%s],''' % (
                    '    ' * (indent + 1),
                    '    ' * (indent + 1),
                    chunk(hexlify(item)),
                    '    ' * (indent + 1),
                ), file=file)
            elif type(item) == bytes:
                print('''%s[%s],''' % (
                    '    ' * (indent + 1),
                    chunk(hexlify(item)),
                ), file=file)
            elif type(item) == int:
                print('%s%d,' % ('    ' * (indent + 1), item), file=file)
            elif type(item) == list:
                print('''%s[''' % (
                    '    ' * (indent + 1)
                ), file=file)
                for subitem in item:
                    if type(subitem) == bytes:
                        print('''%s[%s],''' % (
                            '    ' * (indent + 2),
                            chunk(hexlify(subitem)),
                        ), file=file)
                    else:
                        raise ValueError('Invalid sublist type(%s): %s' % (name, type(subitem)))
                print('''%s],''' % (
                    '    ' * (indent + 1)
                ), file=file)
            else:
                raise ValueError('Invalid list type(%s): %s' % (name, type(item)))
        print('''%s],''' % (
                pad,
            ), file=file)
    else:
        raise ValueError('Invalid type(%s): %s' % (name, type(value)))

def tv_rust(source_path, parts, vectors, file=sys.stdout):
    print('// From https://github.com/zcash/zcash-test-vectors/blob/master/%s.py' % (
        source_path,
    ), file=file)
    print('', file=file)
    visibility = 'pub(crate) '
    print(visibility + 'struct TestVector {', file=file)
    for [name, config] in parts:
        print('    %s%s: %s,' % (visibility, name, config['rust_type']), file=file)
    print('}', file=file)
    print('', file=file)
    if type(vectors) == type({}):
        print(visibility + 'const TEST_VECTOR: TestVector = TestVector {', file=file)
        for p in parts: tv_part_rust(p[0], vectors[p[0]], p[1], 1, file=file)
        print('};', file=file)
    elif type(vectors) == type([]):
        print(visibility + 'const TEST_VECTORS: &[TestVector] = &[', file=file)
        for vector in vectors:
            print('    TestVector {', file=file)
            for p in parts: tv_part_rust(p[0], vector[p[0]], p[1], 2, file=file)
            print('    },', file=file)
        print('];', file=file)
    else:
        raise ValueError('Invalid type(vectors)')


#
# Rendering functions
#

def render_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', choices=['zcash', 'json', 'rust'], default=None)
    parser.add_argument('-o', '--output-dir',
        help='Write all formats (rust, json, zcash) to files under this directory.')
    parser.add_argument('-n', '--name',
        help='Base name for output files (required with -o).')
    args = parser.parse_args()
    if args.output_dir:
        if args.target is not None:
            parser.error('-t/--target and -o/--output-dir are mutually exclusive')
        if args.name is None:
            parser.error('-n/--name is required when using -o/--output-dir')
    else:
        if args.name is not None:
            parser.error('-n/--name requires -o/--output-dir')
        if args.target is None:
            args.target = 'rust'
    return args

def render_to_stream(target, source_path, parts, vectors, file):
    """Render test vectors in the given format to a stream.

    For rust output, the stream is piped through rustfmt.
    """
    if target == 'rust':
        proc = subprocess.Popen(
            ['rustfmt', '--edition', '2021'],
            stdin=subprocess.PIPE, stdout=file, text=True
        )
        tv_rust(source_path, parts, vectors, file=proc.stdin)
        proc.stdin.close()
        if proc.wait() != 0:
            raise subprocess.CalledProcessError(proc.returncode, 'rustfmt')
    elif target == 'zcash':
        tv_json(source_path, parts, vectors, True, file=file)
    elif target == 'json':
        tv_json(source_path, parts, vectors, False, file=file)

def render_tv(args, source_path, parts, vectors):
    # Convert older format
    parts = [(p[0], p[1] if type(p[1]) == type({}) else {'rust_type': p[1]}) for p in parts]

    if args.output_dir:
        for (target, ext) in [('rust', 'rs'), ('json', 'json'), ('zcash', 'json')]:
            outdir = os.path.join(args.output_dir, target)
            os.makedirs(outdir, exist_ok=True)
            outpath = os.path.join(outdir, '%s.%s' % (args.name, ext))
            with open(outpath, 'w') as f:
                render_to_stream(target, source_path, parts, vectors, f)
    else:
        render_to_stream(args.target, source_path, parts, vectors, sys.stdout)
