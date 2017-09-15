#!/usr/bin/python3

from argparse import ArgumentParser
from getpass import getpass
from subprocess import check_output, Popen, PIPE, STDOUT
from os import listdir, remove, getcwd, mkdir, makedirs, walk, stat
from os.path import join, basename, dirname, relpath, isfile, isdir, abspath, expanduser, getmtime, splitext
from socket import socket, AF_INET, SOCK_STREAM
from re import compile
from datetime import datetime
import hashlib as hash
import gnupg
import io

GPG_BACKUP_HOME = join(expanduser("~"), '.gpg_backup')
BLOCKSIZE = 65536
VERBOSE=False

def ssh_available(url, port=22):
    s = socket(AF_INET, SOCK_STREAM)
    available = None
    try:
        s.connect((url, port))
        available = True
    except error as e:
        available = False
    finally:
        s.close()
    return available


def random_filename(length=32):
    cmd = "cat /dev/urandom | env LC_CTYPE=C tr -cd 'a-f0-9' | head -c {0}".format(length)
    output = check_output(cmd, shell=True)
    return str(output, "utf-8") + '.gpg'


def hash_file(src_file_path):
    sha = hash.sha256()
    with open(src_file_path, 'rb') as hashed_file:
        file_buffer = hashed_file.read(BLOCKSIZE)
        while len(file_buffer) > 0:
            sha.update(file_buffer)
            file_buffer = hashed_file.read(BLOCKSIZE)
    hashed_file.close()
    return sha.hexdigest() + '.gpg'


def oldest_file_in_tree(rootfolder, extension=".gpg"):
    return min(files_in_tree(rootfolder, extension),
        key=lambda fn: stat(fn).st_mtime)


def files_in_tree(rootfolder, extension=".gpg"):
    return [join(dirname, filename)
        for dirname, dirnames, filenames in walk(rootfolder)
        for filename in filenames
        if filename.endswith(extension)]

def encrypt_file(src_file_path, dst_file_path, passphrase):
    # Run the GPG command to make a symmetrically encrypted version of the file at the destination
    print('ENCRYPTING FILE:\n\tSRC: {0}\n\tDST:{1}'.format(src_file_path, dst_file_path))
    makedirs(dirname(dst_file_path), exist_ok=True)
    with open(src_file_path, "rb") as stream:
        status = gpg.encrypt_file(stream, None, passphrase=passphrase, symmetric='AES256', output=dst_file_path, armor=False)
        stream.close()
    #cmd = ['gpg', '--yes', '--passphrase-fd', '0', '--output', dst_file_path, '--symmetric', src_file_path]
    #process = Popen(cmd, stdout=PIPE, stdin=PIPE, stderr=PIPE)
    #gpg_stdout = process.communicate(input=passphrase)[0]
    #process.stdin.close()


def decrypt_file(src_file_path, dst_file_path, passphrase):
    # Run the GPG command to decrypt a symmetrically encrypted file and write the results to a destination
    print('DECRYPTING FILE:\n\tSRC: {0}\n\tDST:{1}'.format(src_file_path, dst_file_path))
    stream = open(src_file_path, "rb")
    gpg.decrypt(stream, passphrase=passphrase, output=dst_file_path)
    stream.close()
    #cmd = ['gpg', '--yes', '--passphrase-fd', '0', '--output', dst_file_path, '--decrypt', src_file_path]
    #process = Popen(cmd, stdout=PIPE, stdin=PIPE, stderr=PIPE)
    #gpg_stdout = process.communicate(input=passphrase)[0]
    #process.stdin.close()


def transfer_encrypted_file(file_path, remote_user, remote_url, remote_port,
                            dst_dir):
    # Run RSync over SSH to transfer the file over to the backup server.
    # This function assumes that you have SSH access to the machine via private
    # key. It will not work otherwise.
    dst_file_path = join(dst_dir, basename(file_path))
    dst_str = dst_file_path
    dst_str = remote_url + ':' + dst_str if remote_url else dst_str
    dst_str = remote_user + '@' + dst_str if remote_user else dst_str
    print('TRANSFERRING FILE:\n\tSRC: {0}\n\tDST: {1}'.format(file_path, dst_str))
    cmd = ['rsync', '--progress', '-Parvzy', file_path, '-e',
           'ssh -p {0}'.format(remote_port), dst_str]
    process = Popen(cmd, stdout=PIPE, stdin=PIPE, stderr=PIPE)
    rsync_stdout = process.communicate()[0]
    process.stdin.close()


def load_encrypted_backup(dst_dir, remote_user, remote_url, remote_port, remote_dir):
        src_str = remote_dir
        src_str = remote_url + ':' + src_str if remote_url else src_str
        src_str = remote_user + '@' + src_str if remote_user else src_str
        print('DOWNLOADING ECNRYPTED FILES:\n\tSRC: {0}\n\tDST: {1}'.format(file_path, dst_dir))
        cmd = ['rsync', '--progress', '-Parvzy', '-e',
               'ssh -p {0}'.format(remote_port), src_str, dst_dir]
        process = Popen(cmd, stdout=PIPE, stdin=PIPE, stderr=PIPE)
        rsync_stdout = process.communicate()[0]
        process.stdin.close()

def clean_cache(source_dir, cache_dir):
    filelist = [relpath(f,source_dir) for f in files_in_tree(source_dir, "")]
    if VERBOSE:
        print("Original filelist: %s" % (filelist))   
    #oldest_src = oldest_file_in_tree(source_dir, "")
    #oldest_src_mtime = getmtime(oldest_src)
    for dirname, dirnames, filenames in walk(cache_dir):
        for filename in filenames:
            filepath = join(dirname, filename)
            relativeFile = splitext(filepath)[0].replace(cache_dir, "")
            relativeFile = relpath(splitext(filepath)[0], cache_dir)
            if not relativeFile in filelist:
                print("Not in list: Remove {0}\n".format(relativeFile) )
                remove(filepath)


def sync_encrypt_cache(local_dir, remote_user, remote_url, remote_port, dst_dir):
    # Run RSync over SSH to transfer the file over to the backup server.
    # This function assumes that you have SSH access to the machine via private
    # key. It will not work otherwise.
    dst_str = dst_dir
    dst_str = remote_url + ':' + dst_str if remote_url else dst_str
    dst_str = remote_user + '@' + dst_str if remote_user else dst_str
    local_str = abspath(local_dir)+'/'
    print('SYNC FOLDERS:\n\tSRC: {0}\n\tDST: {1}'.format(local_str, dst_str))
    cmd = ['rsync', '--progress', '--delete', '-Parvzy', local_str, '-e',
           'ssh -p {0}'.format(remote_port), dst_str]
    if VERBOSE:
        print (cmd)
    process = Popen(cmd, stdout=PIPE, stdin=PIPE, stderr=PIPE)
    rsync_stdout = process.communicate()[0]
    process.stdin.close()

def process_decrypt_directory(encrypted_entries, temp_dir, dst_dir):
    pass


def process_encrypt_directory(src_base, dir_path, remote_user, remote_url, remote_port,
                              remote_dir, passphrase, delete=True, 
                              cached_sync=False, temp_dir=None, 
                              filename_obfuscation=True):
    temp_dir = temp_dir if temp_dir else '/tmp'
    for f in listdir(dir_path):
        full_path = join(dir_path, f)
        if isfile(full_path):
            # r_filename = random_filename()
            if filename_obfuscation:
                r_filename = hash_file( full_path )
            else:
                r_filename = relpath(full_path, src_base) + '.gpg'
            encrypted_dst_path = join(temp_dir, r_filename)
            if not cached_sync or not isfile(encrypted_dst_path) or ( getmtime( full_path ) > getmtime( encrypted_dst_path ) ):
                encrypt_file(full_path, encrypted_dst_path, passphrase)
            
            yield (full_path, r_filename)
            if not cached_sync:
                transfer_encrypted_file(encrypted_dst_path, remote_user, remote_url,
                                    remote_port, remote_dir)
            if delete and not cached_sync:
                print('DELETING: {0}'.format(encrypted_dst_path))
                remove(encrypted_dst_path)
        elif isdir(full_path):
            for src_path, r_filename in process_encrypt_directory(src_base,
                                                                  full_path,
                                                                  remote_user,
                                                                  remote_url,
                                                                  remote_port,
                                                                  remote_dir,
                                                                  passphrase,
                                                                  delete,
                                                                  cached_sync,
                                                                  temp_dir,
                                                                  filename_obfuscation):
                yield (src_path, r_filename)


def main():
    # Parse the arguments and run the appropriate functions
    parser = ArgumentParser()
    parser.add_argument('source_dir', metavar='SOURCE-DIRECTORY', type=str,
                        help='The source directory that is to be backed up.')
    parser.add_argument('destination', metavar='DESTINATION', type=str,
                        help='The destination (remote) directory where the '
                             'backup will be placed.')
    parser.add_argument('--no-delete', action='store_true',
                        help='Do not delete local temporary encrypted files.')
    parser.add_argument('--cached-sync', action='store_true',
                        help='Sync the generated encrypted files all at once, deleting distant files if necessary. WARNING: Will first generate all encrypted files, so respective disk space is needed (in ~/.gpg_packup/cache), before sync.')
    parser.add_argument('--keep-filename', action='store_true',
                        help='Keep original filename to encrypted files, only add gpg extension.')
    parser.add_argument('-t', '--temp-dir', type=str,
                        help='Specify the temp directory for encrypted files.')
    parser.add_argument('-l', '--logfile', type=str,
                        help='Specify a logfile to be used to record files and '
                             'their randomized names')

    # Parse the arguments
    arguments = parser.parse_args()
    
    # lib bugfix: create an empty gpg.conf file if none
    #conf_file= join(GPG_BACKUP_HOME, 'gpg.conf')
    #if not isfile(conf_file):
    #    c = open(conf_file,'a')
    #    c.close()
    
    if isdir(arguments.source_dir):
        url_pattern = compile(r'(.*)?\@(.+):(\d*)(\/.*|~\/.*)')
        url_match = url_pattern.match(arguments.destination)
        if url_match:
            print(url_match.groups())
            remote_user = url_match.group(1) if url_match.group(1) else None
            remote_url = url_match.group(2)
            remote_port = url_match.group(3) if url_match.group(3) else 22
            dst_dir = url_match.group(4)
            if not ssh_available(remote_url, remote_port):
                print("Connection unavailable!")
                parser.print_help()
                exit()
        elif isdir(arguments.destination):
            remote_user = None
            remote_url = None
            remote_port = None
            dst_dir = arguments.destination
        else:
            print("Invalid destination")
            parser.print_help()
            exit()
        temp_dir = arguments.temp_dir
        delete = not arguments.no_delete
        cached_sync = arguments.cached_sync
        filename_obfuscation = not arguments.keep_filename

        if cached_sync:
            temp_dir = join(GPG_BACKUP_HOME, 'cache')
            delete = False
            if not isdir(temp_dir):
                mkdir(temp_dir, 0o700)
        
        # Create a logfile:
        if arguments.logfile:
            logfile = arguments.logfile
        else:
            time_str = str(datetime.now()).replace(' ','_')
            logfile = join(getcwd(), '{0}_gpg-backup.log'.format(time_str))

        passfile = join(GPG_BACKUP_HOME, 'passphrase')

        with open(logfile,'a+') as log:
            # autogenerate pass: check gpg._make_passphrase(length, file)
            with io.open(passfile,'a+', encoding='utf-8') as fpass:
                fpass.seek(0)
                passphrase = fpass.read()
                if not passphrase:
                    # Prompt the user for a password
                    # The author of this software strongly discourages modifying this
                    # program to take a password as a commandline parameter.
                    passphrase = getpass('Password: ')
                    fpass.write(passphrase)
                fpass.close()

            # Execute recursive call to backup the directory
            for entry in process_encrypt_directory(arguments.source_dir, arguments.source_dir,
                                      remote_user, remote_url, remote_port, dst_dir,
                                      passphrase, delete, cached_sync, temp_dir, 
                                      filename_obfuscation):
                log.write(('{0} {1}\n'.format(entry[1], abspath(entry[0]))))
            log.close()
            if cached_sync:
                clean_cache(arguments.source_dir, temp_dir)
                sync_encrypt_cache(temp_dir,remote_user, remote_url, remote_port, 
                                        dst_dir)                
    else:
        print("Invalid source directory")
        parser.print_help()
        exit()

if __name__ == "__main__":
    try:
        gpg = gnupg.GPG(gnupghome=GPG_BACKUP_HOME, verbose=VERBOSE)
        # check gnupg lib:
        if not "encrypt_file" in dir(gpg):
            raise Exception('Incorrect gnupg library')
    except:
        print("You are not using the correct gnupg library : pip3 uninstall gnupg && pip3 install python-gnupg")
        exit()
    main()
