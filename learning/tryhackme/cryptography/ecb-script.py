import binascii

import requests
from bs4 import BeautifulSoup
from Crypto.Cipher import AES

### Variables ###

URL = "http://10.66.173.144:5000/oracle"

BLOCK_SIZE = 0

### Oracle Interface ###


def chat_to_oracle(username):
    r = requests.post(URL, data={"username": username})
    # Parse the response
    soup = BeautifulSoup(r.text, "html.parser")
    # Find the encrypted text
    value = str(soup.find(id="encrypted-result").find("strong"))
    # Extract the value
    value = value.replace("<strong>", "").replace("</strong>", "")

    return value


### Calculate Block Size ###


def calculate_block_size():
    # To calculate the block size, we need to keep sending a large username value until the ciphertext length grows twice

    # Get the initial ciphertext length
    username = "A"
    original_length = len(chat_to_oracle(username))

    # Now grow the username until the length becomes larger, keeping count
    first_change_len = 1
    while len(chat_to_oracle(username)) == original_length:
        username += "A"
        first_change_len += 1

    print("First growth was at position: " + str(first_change_len))

    # Get the new length
    new_length = len(chat_to_oracle(username))

    # Now grow the username a second time
    second_change_len = first_change_len
    while len(chat_to_oracle(username)) == new_length:
        username += "A"
        second_change_len += 1

    print("Second growth was at position: " + str(second_change_len))

    # With these two values, we can now determine the block size:
    BLOCK_SIZE = second_change_len - first_change_len

    print("BLOCK_SIZE is: " + str(BLOCK_SIZE))

    return BLOCK_SIZE


def split_ciphertext(ciphertext, block_size):
    # This helper function will take the ciphertext and split it into blocks of the known block size
    # Times two since we have two hex for each char
    block_size = block_size * 2
    chunks = [
        ciphertext[i : i + block_size] for i in range(0, len(ciphertext), block_size)
    ]
    return chunks


### Calculate the Offset ###


def calculate_offset(block_size):
    # To calculate the offset, we will send known text for double the block size and then gradually grow the text until we get two blocks that are the same

    # Create the initial double block size buffer
    initial_text = ""
    for x in range(block_size * 2):
        initial_text += "A"

    # Send this buffer to get the initial ciphertext
    ciphertext = chat_to_oracle(initial_text)

    chunks = split_ciphertext(ciphertext, block_size)

    # Ensure that there are no duplicates already, since this would indicate that there is no offet

    if len(chunks) != len(set(chunks)):
        print("No offset found!")
        offset = 0
        return offset

    # If we got here, there is an offet. We will slowly add more text to the start of the username until we get a duplicate
    offset = 0
    while len(chunks) == len(set(chunks)):
        offset += 1
        # Increment the text by one
        initial_text = "B" + initial_text

        ciphertext = chat_to_oracle(initial_text)
        chunks = split_ciphertext(ciphertext, block_size)

    # Once we exit the loop, it means we have a duplicate chunk and have determined the offset

    print("Offset is: " + str(offset))

    return offset


### Extract information from the Oracle ###
def brute_forcer(reference_chunk, prefix, block_size, target_block_index, known_so_far):
    # Character list can be adapted if we expect other characters as well.
    # For this exercise, we stay with letters only.
    charlist = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

    for char in charlist:
        test_text = prefix + known_so_far + char

        ciphertext = chat_to_oracle(test_text)
        chunks = split_ciphertext(ciphertext, block_size)

        # Test to see if our chunk matches the reference chunk
        if reference_chunk == chunks[target_block_index]:
            print("Found the char: " + char)
            return char

    return None


def extract_n_bytes(block_size, offset, n_bytes):
    # Repeats the classic ECB "byte-at-a-time" approach to recover multiple characters.
    known = ""

    for i in range(n_bytes):
        # Pad so the next unknown byte ends at the end of a block.
        pad_len = block_size - 1 - (i % block_size)
        prefix = ("B" * offset) + ("A" * pad_len)
        print("Prefix is: " + prefix)
        print("Pad length is: " + str(pad_len))

        # Determine which ciphertext block contains the byte we are solving for.
        target_block_index = (offset + pad_len + i) // block_size

        # Get the reference block for this alignment
        ciphertext = chat_to_oracle(prefix)
        chunks = split_ciphertext(ciphertext, block_size)
        reference_chunk = chunks[target_block_index]

        print("Reference chunk is: " + str(reference_chunk))

        # Brute force the next character
        next_char = brute_forcer(
            reference_chunk, prefix, block_size, target_block_index, known
        )
        if next_char is None:
            return known

        known += next_char
        print("Recovered so far: " + known)

    return known


if __name__ == "__main__":
    # Send a message to the oracle and print the ciphertest
    print("Testing the oracle")
    ciphertext = chat_to_oracle("SuperUser")
    print("Ciphertext for the username of SuperUser is: " + ciphertext)

    # Calculate the block size from the oracle
    print("Calculating the block size")
    size = calculate_block_size()
    print("Block size is: " + str(size))

    # Calculate the offset from the oracle
    print("Calculating the offset")
    offset = calculate_offset(size)
    print("Offset is: " + str(offset))

    # Brute force multiple characters
    print("Brute forcing multiple characters")
    recovered = extract_n_bytes(size, offset, n_bytes=32)
    print("Recovered: " + recovered)
