"""
Season II US Cyber Open CTF
Greys Anatomy (Crypto) challenge - by BenderBot
Solution script mostly by TJ OConnor;
https://github.com/tj-oconnor/cyber-open-2022/blob/main/crypto/greys/solver.py
https://ctftime.org/writeup/34632 by v10l3nt (https://www.tjoconnor.org/)
Writeup and annotations written by Nick Stegman (@LenceOfTheOrder), 
Writeup reviewed by Justin Applegate (@Legoclones), Chance Harrison (@ChanceHarrison), and John Nguyen (@Magicks52)

Problem:
Can you compromise the medical records of Seattle Grace Hospital? We've obtained a set of credentials (mgrey/1515) but haven't figured out how to bypass the second factor authentication.

Upon connecting to the service (via e.g. nc), we get the following:
Welcome to the Seattle Grace Hospital EMR Terminal Access Program
Please enter your credentials to access patient records.
Username:
mgrey # using the provided creds
Password:
1515 # using the provided creds

Due to increased security concerns around patient health records, we have recently implemented two-factor authentication.
Please enter the series of 15 3-digit codes found on your 2 factor enabled device.
UPDATE: Due to complaints, we have implemented a custom "trust" meter which will allow you to re-enter a code if you mistype.
Your trust goes down more if it looks like you are randomly guessing.
Enter Code #1 (Trust: 1000): ...

___

One (heuristic) way to determine if a submission is an attempt to correct a typo in a previous submission would be to check the Hamming distance between the two words. The Hamming distance between two "code words" is a measure of how "close" they are; in other words, it tells us how many bits of word A need to be flipped to transform it into word B. For example, given two words: A = 34, B = 51, the Hamming distance between them is 2 because we need to flip 2 bits from A == 100010 to get to B == 110011 and vice versa.

Hamming distance is an important concept in coding theory, as it is used in the creation and analysis of error detection and error correction algorithms. To apply this knowledge to abuse the trust that Seattle Grace has given us, we can use another topic from coding theory: Gray Codes. The (Reflected Binary) Gray Code is a sequence of binary strings (or "code words") where each bitstring has a Hamming distance of 1 from the elements immediately preceeding and succeeding it in the sequence. Gray codes are also frequently used in error prevention.


0.cloud.chals.io:11444
"""

from typing import List, Dict, Union, Optional, Any, AnyStr
import math as m
import pwn

from pwn import *

if args.REMOTE:
	p = remote('0.cloud.chals.io', 11444) # pwn.remote == pwnlib.tubes.remote.remote; subcls of tubes.tube
else:
	p = process('./chal.py', stdin=PTY) # pwn.process == pwnlib.tubes.process.process; subcls of tubes.tube

def gen_codes() -> List[int]:
	# to represent 999 (the highest possible code for this chall) in binary, we need 10 bits
    n = 10
    gray_codes = []
    for i in range(0, 1 << n):
        gray = i ^ (i >> 1)
        if gray < 1000:
            gray_codes.append(gray)
    info("Generated Gray Codes")
    return gray_codes

def login(
	user: AnyStr = b'mgrey',
	passwd: AnyStr = b'1515',
	user_prompt: AnyStr = b'Username:',
	pswd_promt: AnyStr = b'Password:',
	proc: tube = p
):
	"""
	Heavily adapted (made this function reusable for other challenges); see above
	Authenticate to the given process with the given credentials upon encountering a username and password prompt
	"""
	proc.recvuntil(user_prompt)
	proc.sendline(user)
	proc.recvuntil(pswd_promt)
	proc.sendline(passwd)
	info('Sent username and password')


def send_code(
	code: AnyStr,
	proc: tube = p
) -> bool:
	"""
	Send the given code str to the given process
	"""
	proc.recvuntil(b'Enter Code')
	c = str(code).zfill(3).encode()
	# send the code to the process
	proc.sendline(c)
	proc.recvline()
	r = proc.recvline()
	if b"Correct" in r:
		info(f"CORRECT CODE FOUND: {c}")
		return True
	else:
		return False


def main():
	gray_codes = gen_codes()
	login()
	codes_cracked = 0
	while codes_cracked < 15:
		for i in gray_codes:
			if send_code(i):
				codes_cracked += 1
				# get us out of the inner (brute forcing) loop
				break
	p.interactive()

# call the function!
if __name__ == '__main__':
	main()