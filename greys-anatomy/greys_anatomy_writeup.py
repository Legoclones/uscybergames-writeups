"""
Season II US Cyber Open CTF
Greys Anatomy (Crypto) challenge - by BenderBot
Writeup/Solution by LenceOfTheOrder with certain (labeled) parts taken from
https://github.com/tj-oconnor/cyber-open-2022/blob/main/crypto/greys/solver.py
https://ctftime.org/writeup/34632 by v10l3nt (https://www.tjoconnor.org/)

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

## Begin parts taken/adapted from TJ OConnor's writeup (see this module's docstring); Annotations, comments, and docstrings by LenceOfTheOrder
from pwn import *

if args.REMOTE:
    p = remote('0.cloud.chals.io', 11444) # pwn.remote == pwnlib.tubes.remote.remote; subcls of tubes.tube
else:
    p = process('./chal.py', stdin=PTY) # pwn.process == pwnlib.tubes.process.process; subcls of tubes.tube

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
    p.recvuntil(user_prompt)
    p.sendline(user)
    p.recvuntil(pswd_promt)
    p.sendline(passwd)
    info('Sent username and password')


def send_code(code):
    p.recvuntil(b'Enter Code')
    c = str(code).zfill(3).encode()
    p.sendline(c)
    p.recvline()
    r = p.recvline()
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
                break
    p.interactive()

## End parts taken from TJ OConnor' writeup


def num_to_gray(num: int) -> str:
	"""
	Returns the binary reflected gray code representation of the given integer number
	Adapted from the C function, "BinaryToGray" on the page with permalink https://en.wikipedia.org/w/index.php?title=Gray_code&oldid=1100063670#Converting_to_and_from_Gray_code
	"""
	return num ^ (num >> 1)

def get_n_bit_bitstrings(
	n: int,
	remove_prefix: bool = True,
	pad_length: bool = True
) -> List[str]:
	"""
	Returns a list of all the integers that can be represented in binary with n bits
	:param n: the number of bits to use
	:param remove_prefix: If True (default), removes the '0b' prefix that the bin() function prepends to the returned string when converting a decimal int to binary
	"""
	bstrs = [f"{i:b}" for i in range(1<<n)] 
	
	if pad_length:
		bstrs = ['{0:>0{width}}'.format(i, width=n) for i in bstrs]
	
	return bstrs

def gen_gray_codes(
	n: int,
	maximum: int = None
) -> List[str]:
	"""
	Generate a list of numbers up to n bits encoded in Reflected Binary Gray Code (RGBC)
	"""
	gray_nums = []
	if maximum is not None:
		for i in range(maximum):
			gray_nums.append(f"{num_to_gray(i):0{n}b}")
	else:
		# left-shifting 1 by n gives us the maximum int number representable with n bits
		for i in range(1<<n):
			# this f-string specifies to give the RBGC-encoded i-th number repr in binary and padded with zeroes to fill width n
			gray_nums.append(f"{num_to_gray(i):0{n}b}")
	return gray_nums


def gen_n_digit_gray_seq(
	n: int,
	pad: bool = True
) -> List[str]:
	"""
	Generate a d-digit sequence of Reflected Binary Gray Code (RGBC)-encoded numbers
	"""
	# get the number of bits required to represent an n-digit decimal number
	maxim = (10**n) - 1
	num_bits = m.ceil(m.log2(maxim))
	
	if pad:		
		# convert to decimal integers from the num_bits-bit RGBC sequence
		dec_gray_seq = [f"{int(i, 2):0>3d}" for i in gen_gray_codes(num_bits, maxim)]
	else:
		dec_gray_seq = [f"{int(i, 2)}" for i in gen_gray_codes(num_bits, maxim)]
	
	# we only want n-digits, so slice up to the maximum number with n-digits
	return dec_gray_seq[:maxim]