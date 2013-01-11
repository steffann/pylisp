'''
Created on 9 jan. 2013

@author: sander
'''


def ones_complement(message):
    message = bytes(message)

    # Add padding if the message has an odd number of bytes
    if len(message) % 2 == 1:
        message = message + '\x00'

    checksum = 0
    for i in range(0, len(message), 2):
        next_16_bits = (ord(message[i]) << 8) + ord(message[i + 1])
        tmp = checksum + next_16_bits
        checksum = (tmp & 0xffff) + (tmp >> 16)
    checksum = ~checksum & 0xffff

    return checksum
