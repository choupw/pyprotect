#!/usr/bin/env python

import argparse
import os
import shutil
from string import Template
from Crypto.Cipher import AES


PYPROTECT_KEY = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff"
PYPROTECT_IV = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
PYPROTECT_EXT_NAME = ".pye"


def wrap_entrance(root, modname, entrance_func):
    content = Template('''#!/usr/bin/env python
import libdaiwentest
from _${modname} import ${entrance_func}

if __name__ == '__main__':
    ${entrance_func}()

''').substitute(modname=modname, entrance_func=entrance_func)

    wrap_file = os.path.join(root, modname + '.py')
    with open(wrap_file, 'w') as f:
        f.write(content)
    print('Entry point "%s:%s"' % (wrap_file, entrance_func))


def encrypt_file(root, outroot, fname, enc_fname):
    fpath = os.path.join(root, fname)
    with open(fpath, 'rb') as f:
        content = bytearray(f.read())
    padding = 16 - len(content) % 16
    content.extend(padding * [padding])

    cryptor = AES.new(PYPROTECT_KEY, AES.MODE_CBC, PYPROTECT_IV)

    encrypted = cryptor.encrypt(bytes(content))
    foutpath = os.path.join(outroot, enc_fname)
    with open(foutpath, 'wb') as f:
        f.write(encrypted)
    print('Encrypt "%s" -> "%s"' % (fpath, foutpath))


def encrypt_tree(srcroot, entrances, destroot, excludes):
    for e, _ in entrances:
        if not os.path.exists(e):
            print('Entry point file "%s" not found' % e)
            exit(-1)

    for root, _, files in os.walk(str(srcroot)):
        outroot = os.path.normpath(os.path.join(destroot, os.path.relpath(root, srcroot)))
        for f in files:
            if f.endswith('py'):
                fpath = os.path.normpath(os.path.join(os.getcwd(), root, f))

                if not os.path.exists(outroot):
                    print('Makedir "%s"' % outroot)
                    os.mkdir(outroot)

                if fpath in excludes:
                    shutil.copyfile(fpath, os.path.join(outroot, f))
                    print('Ignore "%s"' % fpath)
                    continue

                modname = f[:f.find('.')]
                enc_fname = modname + PYPROTECT_EXT_NAME

                encrypt_file(root, outroot, f, enc_fname)

                for efile, efunc in entrances:
                    if efile == fpath:
                        # rename app.py to _app.py
                        os.rename(os.path.join(outroot, enc_fname), os.path.join(outroot, '_' + enc_fname))
                        wrap_entrance(outroot, modname, efunc)
                        break


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', help='Python源码根目录', required=True)
    parser.add_argument('-e', help='Python工程入口,格式例如 "test.py:main,test2.py:main,..."', required=True)
    parser.add_argument('-o', help='加密后输入根目录，默认当前路径daiwen_out', default='daiwen_out')
    parser.add_argument('--exclude', help='需要忽略加密的文件,格式样例 "a.py,b.py"',)
    args = parser.parse_args()

    srcroot = os.path.join(os.getcwd(), args.s)
    entrances = [(os.path.normpath(os.path.join(srcroot, e.split(':')[0])), e.split(':')[1]) for e in args.e.split(',')]

    if args.exclude:
        excludes = [os.path.normpath(os.path.join(srcroot, e)) for e in args.exclude.split(',')]
    else:
        excludes = []

    destroot = os.path.join(os.getcwd(), args.o)

    encrypt_tree(srcroot, entrances, destroot, excludes)


if __name__ == '__main__':
    main()
