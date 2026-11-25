#!/usr/bin/env python3
"""Stream a PostgreSQL custom dump to a GnuPG encrypted, integrity-protected file.

This is a building block, NOT an automatic production backup system. The
recipient fingerprint and public key must be verified out of band. A private
key must be kept separately; this command never creates one.
"""
import argparse
import os
import pathlib
import re
import shutil
import stat
import subprocess
import sys
import tempfile


def fail(message):
    raise SystemExit(message)


def main():
    parser = argparse.ArgumentParser(description='Encrypt a PostgreSQL backup to a pre-verified public key.')
    parser.add_argument('--recipient', required=True, help='Full, out-of-band verified 40- or 64-character hex fingerprint')
    parser.add_argument('--output', required=True, help='New .gpg file in a private directory; never overwritten')
    args = parser.parse_args()
    fingerprint = args.recipient.upper()
    if not re.fullmatch(r'(?:[0-9A-F]{40}|[0-9A-F]{64})', fingerprint):
        fail('A full public-key fingerprint is required')
    for key in ('PGHOST', 'PGPORT', 'PGDATABASE', 'PGUSER', 'GNUPGHOME'):
        if not os.environ.get(key):
            fail('Explicit PGHOST, PGPORT, PGDATABASE, PGUSER and GNUPGHOME are required')
    if not re.fullmatch(r'[A-Za-z0-9_]{1,63}', os.environ['PGDATABASE']):
        fail('Invalid database name')
    if not re.fullmatch(r'[0-9]{1,5}', os.environ['PGPORT']) or not 1 <= int(os.environ['PGPORT']) <= 65535:
        fail('Invalid database port')
    for command in ('pg_dump', 'gpg'):
        if not shutil.which(command):
            fail('Required backup tools are unavailable')
    target = pathlib.Path(args.output).absolute()
    if target.suffix != '.gpg' or target.name in ('.gpg', '..gpg'):
        fail('Output must be a new .gpg file')
    try:
        parent = target.parent.resolve(strict=True)
        info = parent.stat()
    except OSError:
        fail('Backup directory is unavailable')
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        fail('Backup directory must be owned by this user and inaccessible to group and others')
    target = parent / target.name
    # The temporary file contains ciphertext only; atomically link it into its
    # final name after both processes succeed. Existing names are never replaced.
    if os.path.lexists(target):
        fail('Refusing to replace an existing backup')
    fd, temporary = tempfile.mkstemp(prefix='.sobralis-encrypted-', dir=parent)
    dump = encrypt = None
    published = False
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'wb') as output:
            dump = subprocess.Popen(['pg_dump', '--format=custom', '--no-password', '--host', os.environ['PGHOST'], '--port', os.environ['PGPORT'], '--username', os.environ['PGUSER'], '--dbname', os.environ['PGDATABASE']], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            gpg_env = os.environ.copy()
            # The public-key encryption process has no need for DB credentials.
            gpg_env.pop('PGPASSWORD', None)
            encrypt = subprocess.Popen(['gpg', '--no-options', '--batch', '--no-tty', '--trust-model', 'always', '--cipher-algo', 'AES256', '--force-mdc', '--compress-algo', 'none', '--encrypt', '--recipient', fingerprint], stdin=dump.stdout, stdout=output, stderr=subprocess.DEVNULL, env=gpg_env)
            assert dump.stdout is not None
            dump.stdout.close()
            encrypted_status = encrypt.wait()
            dump_status = dump.wait()
            output.flush()
            os.fsync(output.fileno())
            if encrypted_status != 0 or dump_status != 0 or output.tell() == 0:
                fail('Backup failed; no completed backup was published')
        try:
            os.link(temporary, target)
            published = True
        except FileExistsError:
            fail('Refusing to replace an existing backup')
        # Make publication durable as far as the filesystem supports directory fsync.
        directory_fd = os.open(parent, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        print('Encrypted backup created; verify decryption and an isolated restore.')
    except (OSError, subprocess.SubprocessError):
        fail('Backup was created, but durability could not be confirmed; verify it' if published else 'Backup failed; no completed backup was published')
    finally:
        for process in (encrypt, dump):
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


if __name__ == '__main__':
    main()
