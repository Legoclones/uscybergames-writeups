"""
Season II US Cyber Open CTF
Greys Anatomy (Crypto) challenge - by BenderBot
Writeup/Solution by LenceOfTheOrder

Problem:
Can you compromise the medical records of Seattle Grace Hospital? We've obtained a set of credentials (mgrey/1515) but haven't figured out how to bypass the second factor authentication.

0.cloud.chals.io:11444
"""

from typing import List, Dict, Union, Optional, Any
import math as m


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

'''Doesn't work... yet
def gen_gray_codes(n: int) -> List[str]:
	bitstrs = get_n_bit_bitstrings(n)
	
	reflected = reversed(bitstrs)
	prefixed_old = [f'0{i}' for i in bitstrs]
	prefixed_new = [f'1{i}' for i in reflected]
	concat = prefixed_old + prefixed_new
	return concat
'''

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