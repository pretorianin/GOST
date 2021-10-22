class Gost:

    def __init__(self, key) -> None:  
        self.check_size(key, 256)

        self.key_set =  [(key >> (32 * index)) & 0xFFFFFFFF for _ in range(3) for index in range(8)] 
        self.parse_last_keys()    
        self.mod_size = 2 << 32
        self.s_box = [[0x4,0xA,0x9,0x2,0xD,0x8,0x0,0xE,0x6,0xB,0x1,0xC,0x7,0xF,0x5,0x3],
                      [0xE,0xB,0x4,0xC,0x6,0xD,0xF,0xA,0x2,0x3,0x8,0x1,0x0,0x7,0x5,0x9],
                      [0x5,0x8,0x1,0xD,0xA,0x3,0x4,0x2,0xE,0xF,0xC,0x7,0x6,0x0,0x9,0xB],
                      [0x7,0xD,0xA,0x1,0x0,0x8,0x9,0xF,0xE,0x4,0x6,0xC,0xB,0x2,0x5,0x3],
                      [0x6,0xC,0x7,0x1,0x5,0xF,0xD,0x8,0x4,0xA,0x9,0xE,0x0,0x3,0xB,0x2],
                      [0x4,0xB,0xA,0x0,0x7,0x2,0x1,0xD,0x3,0x6,0x8,0x5,0x9,0xC,0xF,0xE],
                      [0xD,0xB,0x4,0x1,0x3,0xF,0x5,0x9,0x0,0xA,0xE,0x7,0x6,0x8,0x2,0xC],
                      [0x1,0xF,0xD,0x0,0x5,0x7,0xA,0x4,0x9,0x2,0x3,0xE,0x6,0xB,0x8,0xC]]

    def parse_last_keys(self):
        last_keys = self.key_set.copy()[:8]

        for i in range(len(last_keys)):
            tmp = ""
            for j in (hex(last_keys[i])[2:])[::-1]: tmp += hex(int(bin(int(j, 16))[2:].zfill(4)[::-1], 2))[2:]
            last_keys[i] = int(tmp, 16)

        self.key_set += last_keys

    def check_size(self, var, dest_size):
        if len(bin(var)) - 2 > dest_size: raise Exception("Invalid size!")

    def routine(self, in_var_1, in_var_2, index, dec):
        if dec:
            in_var = in_var_2
            var_1 = in_var_1
        else:
            in_var = in_var_1
            var_1 = in_var_2

        add_mod_32 = (var_1 + self.key_set[index]) % self.mod_size
        sbox_value = sum([(self.s_box[i][(add_mod_32 >> (4 * i)) & 0xF]) << (4 * i) for i in range(8)])
        shift_value = ((sbox_value >> (21)) | (sbox_value << 11)) & 0xFFFFFFFF
        var_2 = in_var ^ shift_value

        return (var_1, var_2) if not dec else (var_2, var_1)

    def gost_opt(self, operation, data_chunk):
        self.check_size(data_chunk, 64)

        left_side, right_side = data_chunk >> 32, data_chunk & 0xFFFFFFFF
        if operation == "encrypt": 
            for index in range(32):  left_side, right_side = self.routine(left_side, right_side, index, False)
        elif operation == "decrypt":
            for index in range(32): left_side, right_side = self.routine(left_side, right_side, 31 - index, True)
        else: raise Exception("Unsuported operation!")

        return (left_side << 32) + right_side

if __name__ == '__main__':
    data =0xdeadbeef600dc0d3 
    key = 0xffffeeeeddddccccbbbbaaaa9999888877776666555544443333222211110000
    g = Gost(key)
 
    print("key", hex(key))
    print("data", hex(data))
    data = g.gost_opt("encrypt", data)
    print("encrypted", hex(data))
    data =  g.gost_opt("decrypt", data)
    print("decrypted", hex(data))
