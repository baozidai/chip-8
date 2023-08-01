import argparse
import logging
from io import BufferedReader


def disassemble_chip8_1_instruction(bin_instruction, pc):
    """
    parse one instruction.
    """

    # 按照操作码的第一位进行函数分类
    def opc_0():
        def display_clear():
            print("CLS")

        def rtn():
            print("RT")

        def call_routine_at_NNN():
            addr = int.from_bytes(bin_instruction) & 0x0FFF
            if addr == 0:
                print()
                return
            print("CALM\t#${:03X}".format( addr))

        sub_instruction_dict: dict = {
            0x00E0: display_clear,
            0x00EE: rtn,
        }
        sub_instruction_dict.get(int.from_bytes(bin_instruction), call_routine_at_NNN)()

    def opc_1():
        addr = int.from_bytes(bin_instruction) & 0x0FFF
        print("GOTO\t#${:03X}".format( addr))

    def opc_2():
        addr = int.from_bytes(bin_instruction) & 0x0FFF
        print("CALS\t#${:03X}".format( addr))

    def opc_3():
        num = bin_instruction[1]
        X = bin_instruction[0] & 0x0F
        print("SKIP.EQ\tV{:01X}, {:02X}".format(X, num))

    def opc_4():
        num = bin_instruction[1]
        X = bin_instruction[0] & 0x0F
        print("SKIP.NE\tV{:01X}, {:02X}".format(X, num))

    def opc_5():
        X = int.from_bytes(bin_instruction[0]) & 0x0F
        Y = (int.from_bytes(bin_instruction[1]) & 0xF0) >> 4
        print("SKIP.EQ\tV{:01X}, V{:01X}".format(X, Y))

    def opc_6():
        reg = bin_instruction[0] & 0x0F
        print("MOV\tV{:1X}, #${:02X}".format(reg, bin_instruction[1]))

    def opc_7():
        X = bin_instruction[0] & 0x0F
        num = bin_instruction[1]
        print("ADD\tV{:1X}, #${:02X}".format(X, num))

    def opc_8():
        X = bin_instruction[0] & 0x0F
        Y = (bin_instruction[1] & 0xF0) >> 4
        last_4_bits = bin_instruction[1] & 0x0F
        def _0():
            print("MOV\tV{:01X}, V{:01X}".format(X,Y))
        def _1():
            print("OR\tV{:01X}, V{:01X}".format(X,Y))
        def _2():
            print("AND\tV{:01X}, V{:01X}".format(X,Y))
        def _3():
            print("XOR\tV{:01X}, V{:01X}".format(X,Y))
        def _4():
            print("ADD\tV{:01X}, V{:01X}".format(X,Y))
        def _5():
            print("SUB\tV{:01X}, V{:01X}".format(X,Y))
        def _6():
            print("SHR\tV{:01X}".format(X))
        def _7():
            print("SBX\tV{:01X}, V{:01X}".format(X,Y))
        def _e():
            print("SHL\tV{:01X}".format(X))
        sub_dict={
            0:_0,
            1:_1,
            2:_2,
            3:_3,
            4:_4,
            5:_5,
            6:_6,
            7:_7,
            0xE:_e,
        }
        sub_dict.get(last_4_bits,undefine)()

    def opc_9():
        X = int.from_bytes(bin_instruction[0]) & 0x0F
        Y = (int.from_bytes(bin_instruction[1]) & 0xF0) >> 4
        print("NEQ\tV{:01X}, V{:01X}".format(X, Y))

    def opc_A():
        addr = int.from_bytes(bin_instruction) & 0x0FFF
        print("MVI\tI, #${:03X}".format(addr))

    def opc_B():
        """Jumps to the address NNN plus V0."""
        addr = int.from_bytes(bin_instruction) & 0x0FFF
        print("JMP\tI, #${:03X}".format(addr))

    def opc_C():
        X = bin_instruction[0] & 0x0F
        print("RND\t{:02X}".format(bin_instruction[1]))

    def opc_D():
        X = bin_instruction[0] & 0x0F
        Y = (bin_instruction[1] & 0xF0) >> 4
        N = bin_instruction[1] & 0x0F
        print("DRW\tV{:02X}, V{:02X}, {:01X}".format(X, Y, N))

    def opc_E():
        X = bin_instruction[0] & 0x0F
        last_4_bits = bin_instruction[1] & 0x0F
        def ex9e():
            print("KEQ\tV{:02X}".format(X))

        def exa1():
            print("KNEQ\tV{:02X}".format(X))

        sub_dict: dict = {0xE: ex9e, 0x1: exa1}
        sub_dict.get(last_4_bits,undefine)()

    def opc_F():
        X = bin_instruction[0] & 0x0F
        def fx07():
            print("VTMR\tV{:01X}".format(X))
        def fx0a():
            print("GETK\tV{:01X}".format(X))
        def fx15():
            print("TMRV\tV{:01X}".format(X))
        def fx18():
            print("STMV\tV{:01X}".format(X))
        def fx1e():
            print("ADD\tI, V{:01X}".format(X))
        def fx29():
            print("CHAR\tV{:01X}".format(X))
        def fx33():
            print("BCD\tV{:01X}".format(X))
        def fx55():
            print("DUMP\t&I, V{:01X}".format(X))
        def fx65():
            print("LOAD\tV{:01X}, &I".format(X))
        tail_byte = bin_instruction[1]
        sub_dict:dict = {
            0x07:fx07,
            0x0a:fx0a,
            0x15:fx15,
            0x18:fx18,
            0x1e:fx1e,
            0x29:fx29,
            0x33:fx33,
            0x55:fx55,
            0x65:fx65,

        }
        sub_dict.get(tail_byte,undefine)()


    def undefine():
        print("undefine {:02X} {:02X}".format(bin_instruction[0], bin_instruction[1]))

    # 打印地址
    print(
        "{:04X} {:02X} {:02X} ".format(pc, bin_instruction[0], bin_instruction[1]),
        end="",
    )

    # 取得操作码第一位（最高位）
    firstnib = (bin_instruction[0] & int.from_bytes(b"\xF0")) >> 4
    # print(hex(firstnib).zfill(1)[2:])

    instruction_set: dict = {
        0: opc_0,
        1: opc_1,
        2: opc_2,
        3: opc_3,
        4: opc_4,
        5: opc_5,
        6: opc_6,
        7: opc_7,
        8: opc_8,
        9: opc_9,
        10: opc_A,
        11: opc_B,
        12: opc_C,
        13: opc_D,
        14: opc_E,
        15: opc_F,
    }
    instruction_set.get(firstnib, undefine)()


def main():
    pc = 0x0200

    parser = argparse.ArgumentParser(description="Disassembler for CHIP-8.")
    parser.add_argument("-f", "--file", help="File path to CHIP-8 ROM.")
    parser.add_argument(
        "-v", "--verbose", help="Show verbose log.", action="store_true"
    )
    args = parser.parse_args()

    # Process the arguments and do something
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
        logging.info("输出详细日志.")

    # logging.info("Open file {}".format(args.file))

    # Open ROM file in binary mode.
    rom: BufferedReader = open(file=args.file, mode="rb")

    # 取得文件大小
    rom.seek(0, 2)
    fsize = rom.tell()

    # 倒回seek指针
    rom.seek(0, 0)

    print("ADDR DA TA")
    while pc < 0x0200 + fsize:
        data = rom.read(2)
        if not data:
            break

        disassemble_chip8_1_instruction(data, pc)
        pc += 2


if __name__ == "__main__":
    main()
