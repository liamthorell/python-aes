from typing import Union
from os import urandom

# fmt: off
s_box_list = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
)
# fmt: on

s_box_list = b"".join([int.to_bytes(s, 1, "big") for s in s_box_list])
s_box = bytearray(s_box_list)


def find_reverse_s_box(s_box):
    reverse_s_box = [0] * 256

    for i, value in enumerate(s_box):
        reverse_s_box[value] = i

    return reverse_s_box


inv_s_box_list = find_reverse_s_box(s_box)
inv_s_box_list = b"".join([int.to_bytes(s, 1, "big") for s in inv_s_box_list])
inv_s_box = bytearray(inv_s_box_list)


def sub_word(word: list[int]) -> bytes:
    substituted_word = bytes(s_box[i] for i in word)
    return substituted_word


def rcon(i: int) -> bytes:
    # From Wikipedia
    rcon_lookup = bytearray.fromhex("01020408102040801b36")
    rcon_value = bytes([rcon_lookup[i - 1], 0, 0, 0])
    return rcon_value


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes([x ^ y for (x, y) in zip(a, b)])


def rot_word(word: list[int]) -> list[int]:
    return word[1:] + word[:1]


def key_expansion(key: bytes, nb: int = 4) -> list[list[list[int]]]:
    nk = len(key) // 4

    key_bit_length = len(key) * 8

    if key_bit_length == 128:
        nr = 10
    elif key_bit_length == 192:
        nr = 12
    else:  # 256-bit keys
        nr = 14

    w = state_from_bytes(key)

    for i in range(nk, nb * (nr + 1)):
        temp = w[i - 1]
        if i % nk == 0:
            temp = xor_bytes(sub_word(rot_word(temp)), rcon(i // nk))
        elif nk > 6 and i % nk == 4:
            temp = sub_word(temp)
        w.append(xor_bytes(w[i - nk], temp))  # type: ignore

    return [w[i * 4 : (i + 1) * 4] for i in range(len(w) // 4)]


def add_round_key(
    state: list[list[int]],
    key_schedule: list[list[list[int]]],
    round: int,
):
    round_key = key_schedule[round]
    for r in range(len(state)):
        state[r] = [state[r][c] ^ round_key[r][c] for c in range(len(state[0]))]


def sub_bytes(state: list[list[int]], provided_s_box: bytearray):
    for r in range(len(state)):
        state[r] = [provided_s_box[state[r][c]] for c in range(len(state[0]))]


def shift_rows(state: list[list[int]]):
    # [00, 10, 20, 30]     [00, 10, 20, 30]
    # [01, 11, 21, 31] --> [11, 21, 31, 01]
    # [02, 12, 22, 32]     [22, 32, 02, 12]
    # [03, 13, 23, 33]     [33, 03, 13, 23]
    state[0][1], state[1][1], state[2][1], state[3][1] = (
        state[1][1],
        state[2][1],
        state[3][1],
        state[0][1],
    )
    state[0][2], state[1][2], state[2][2], state[3][2] = (
        state[2][2],
        state[3][2],
        state[0][2],
        state[1][2],
    )
    state[0][3], state[1][3], state[2][3], state[3][3] = (
        state[3][3],
        state[0][3],
        state[1][3],
        state[2][3],
    )


def xtime(a: int) -> int:
    if a & 0x80:
        return ((a << 1) ^ 0x1B) & 0xFF
    return a << 1


def mix_column(col: list[int]):
    c_0 = col[0]
    all_xor = col[0] ^ col[1] ^ col[2] ^ col[3]
    col[0] ^= all_xor ^ xtime(col[0] ^ col[1])
    col[1] ^= all_xor ^ xtime(col[1] ^ col[2])
    col[2] ^= all_xor ^ xtime(col[2] ^ col[3])
    col[3] ^= all_xor ^ xtime(c_0 ^ col[3])


def mix_columns(state: list[list[int]]):
    for r in state:
        mix_column(r)


def state_from_bytes(data: bytes) -> list[list[int]]:
    state = [data[i * 4 : (i + 1) * 4] for i in range(len(data) // 4)]
    return state  # type: ignore


def bytes_from_state(state: list[list[int]]) -> bytes:
    return bytes(state[0] + state[1] + state[2] + state[3])


def inv_shift_rows(state: list[list[int]]) -> None:
    # [00, 10, 20, 30]     [00, 10, 20, 30]
    # [01, 11, 21, 31] <-- [11, 21, 31, 01]
    # [02, 12, 22, 32]     [22, 32, 02, 12]
    # [03, 13, 23, 33]     [33, 03, 13, 23]
    state[1][1], state[2][1], state[3][1], state[0][1] = (
        state[0][1],
        state[1][1],
        state[2][1],
        state[3][1],
    )
    state[2][2], state[3][2], state[0][2], state[1][2] = (
        state[0][2],
        state[1][2],
        state[2][2],
        state[3][2],
    )
    state[3][3], state[0][3], state[1][3], state[2][3] = (
        state[0][3],
        state[1][3],
        state[2][3],
        state[3][3],
    )
    return


def inv_sub_bytes(state: list[list[int]], provided_inv_s_box: bytearray) -> None:
    for r in range(len(state)):
        state[r] = [provided_inv_s_box[state[r][c]] for c in range(len(state[0]))]


def xtimes_0e(b):
    # 0x0e = 14 = b1110 = ((x * 2 + x) * 2 + x) * 2
    return xtime(xtime(xtime(b) ^ b) ^ b)


def xtimes_0b(b):
    # 0x0b = 11 = b1011 = ((x*2)*2+x)*2+x
    return xtime(xtime(xtime(b)) ^ b) ^ b


def xtimes_0d(b):
    # 0x0d = 13 = b1101 = ((x*2+x)*2)*2+x
    return xtime(xtime(xtime(b) ^ b)) ^ b


def xtimes_09(b):
    # 0x09 = 9  = b1001 = ((x*2)*2)*2+x
    return xtime(xtime(xtime(b))) ^ b


def inv_mix_column(col: list[int]):
    c_0, c_1, c_2, c_3 = col[0], col[1], col[2], col[3]
    col[0] = xtimes_0e(c_0) ^ xtimes_0b(c_1) ^ xtimes_0d(c_2) ^ xtimes_09(c_3)
    col[1] = xtimes_09(c_0) ^ xtimes_0e(c_1) ^ xtimes_0b(c_2) ^ xtimes_0d(c_3)
    col[2] = xtimes_0d(c_0) ^ xtimes_09(c_1) ^ xtimes_0e(c_2) ^ xtimes_0b(c_3)
    col[3] = xtimes_0b(c_0) ^ xtimes_0d(c_1) ^ xtimes_09(c_2) ^ xtimes_0e(c_3)


def inv_mix_columns(state: list[list[int]]) -> None:
    for r in state:
        inv_mix_column(r)


def inv_mix_column_optimized(col: list[int]):
    u = xtime(xtime(col[0] ^ col[2]))
    v = xtime(xtime(col[1] ^ col[3]))
    col[0] ^= u
    col[1] ^= v
    col[2] ^= u
    col[3] ^= v


def inv_mix_columns_optimized(state: list[list[int]]) -> None:
    for r in state:
        inv_mix_column_optimized(r)
    mix_columns(state)


class AES:
    def __init__(
        self,
        key: Union[None, bytes] = None,
        key_bit_length: Union[None, int] = None,
        use_round_key: bool = True,
        use_sub_bytes: bool = True,
        use_shift_rows: bool = True,
        use_mix_columns: bool = True,
        custom_s_box: Union[list[int], None] = None,
    ):
        self.key = key
        self.key_bit_length = key_bit_length
        self.use_round_key = use_round_key
        self.use_sub_bytes = use_sub_bytes
        self.use_shift_rows = use_shift_rows
        self.use_mix_columns = use_mix_columns

        if custom_s_box is not None:
            _inv_s_box = find_reverse_s_box(custom_s_box)
            _inv_s_box = b"".join([int.to_bytes(s, 1, "big") for s in _inv_s_box])
            _inv_s_box = bytearray(_inv_s_box)
            self.inv_s_box = _inv_s_box

            _s_box = b"".join([int.to_bytes(s, 1, "big") for s in custom_s_box])
            _s_box = bytearray(_s_box)
            self.s_box = _s_box

        else:
            self.s_box = s_box
            self.inv_s_box = inv_s_box

    def encrypt(self, data: bytes) -> bytes:
        if self.key_bit_length is None and self.key:
            self.key_bit_length = len(self.key) * 8

        if self.key_bit_length == 128:
            nr = 10
        elif self.key_bit_length == 192:
            nr = 12
        else:  # 256-bit keys
            nr = 14

        state = state_from_bytes(data)

        for r in range(len(state)):
            state[r] = [state[r][c] for c in range(len(state[0]))]

        key_schedule = None
        if self.use_round_key and self.key:
            key_schedule = key_expansion(self.key)

            add_round_key(state, key_schedule, round=0)

        for round in range(1, nr):
            if self.use_sub_bytes:
                sub_bytes(state, self.s_box)
            if self.use_shift_rows:
                shift_rows(state)
            if self.use_mix_columns:
                mix_columns(state)
            if self.use_round_key and key_schedule:
                add_round_key(state, key_schedule, round)

        if self.use_sub_bytes:
            sub_bytes(state, self.s_box)
        if self.use_shift_rows:
            shift_rows(state)
        if self.use_round_key and key_schedule:
            add_round_key(state, key_schedule, round=nr)

        cipher = bytes_from_state(state)
        return cipher

    def decrypt(
        self,
        cipher: bytes,
    ) -> bytes:
        if self.key_bit_length is None and self.key:
            self.key_bit_length = len(self.key) * 8

        if self.key_bit_length == 128:
            nr = 10
        elif self.key_bit_length == 192:
            nr = 12
        else:  # 256-bit keys
            nr = 14

        state = state_from_bytes(cipher)

        for r in range(len(state)):
            state[r] = [state[r][c] for c in range(len(state[0]))]

        key_schedule = None
        if self.use_round_key and self.key:
            key_schedule = key_expansion(self.key)

            add_round_key(state, key_schedule, round=0)

        for round in range(nr - 1, 0, -1):
            if self.use_shift_rows:
                inv_shift_rows(state)
            if self.use_sub_bytes:
                inv_sub_bytes(state, self.inv_s_box)
            if self.use_round_key and key_schedule:
                add_round_key(state, key_schedule, round)
            if self.use_mix_columns:
                inv_mix_columns(state)

        if self.use_shift_rows:
            inv_shift_rows(state)
        if self.use_sub_bytes:
            inv_sub_bytes(state, self.inv_s_box)
        if self.use_round_key and key_schedule:
            add_round_key(state, key_schedule, round=0)

        plain = bytes_from_state(state)
        return plain
