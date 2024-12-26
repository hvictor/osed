# Input:    arbitrary string
# Output:   Sequence of push operations to store the string on the stack
# 
# WARNING:  This script does not avoid null bytes in the code pushing the last DWORD. 
#           You will have to avoid it by using a specific null-byte avoidance technique.
#           Example:    1. Determine the negated value of the DWORD containing NULL bytes.
#                       2. mov eax, <negated DWORD>; neg eax; push eax;
# WARNING:  If the string length is a multiple of 4 bytes, the pushed string will not contain any null bytes.
#           You will have to push a zero DWORD to terminate the string.

import sys

def string_to_dwords(input_string):
    # Add zero-padding to make the length a multiple of 4 bytes.
    padding_length = (4 - len(input_string) % 4) % 4
    padded_string = input_string + '\0' * padding_length

    # Split the string into chunks of 4 bytes
    chunks = [padded_string[i:i+4] for i in range(0, len(padded_string), 4)]

    # Build the DWORDs in little-endian format
    dwords = []
    for chunk in chunks:
        # Convert characters to ASCII codes, reverse (little-endian), and format as DWORD
        dword = ''.join(f'{ord(c):02x}' for c in reversed(chunk))
        dwords.append((dword, chunk))

    return dwords

def main():
    if len(sys.argv) != 2:
        print("Usage: python string_to_dwords.py <string>")
        sys.exit(1)

    input_string = sys.argv[1]
    dwords = string_to_dwords(input_string)

    # Print the push operations
    i = 1
    print("DWORDs to push to construct the string in memory:")
    for dword, chunk in reversed(dwords):
        print(f"push 0x{dword.upper()} = {repr(chunk)} (reversed)")
        i += 1

if __name__ == "__main__":
    main()
