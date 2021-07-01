''' 80856
ARM 32-bit full binary disassembler using Capstone disassembly framework.
- Daniel Chong
'''
'''
NOTE: CORTEX M processors use THUMB instructions exclusively https://stackoverflow.com/questions/28669905/what-is-the-difference-between-the-arm-thumb-and-thumb-2-instruction-encodings
https://www.keil.com/support/man/docs/armasm/armasm_dom1361289866466.htm
'''
import sys
import struct
from capstone import *
from collections import OrderedDict
import binascii
import math
import traceback
import sys

FLOW = []
FILE_NAME = ''
IMAGEBASE = '0x80000'
IS_THUMB_MODE = 1
MAX_INSTR_SIZE = 8
MD = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
REGISTER_NAMES = ['r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9'
        , 'r10', 'sl', 'r11', 'r12', 'r13', 'r14', 'r15', 'psr', 'lr', 'pc', 'sp']
BRANCH_INSTRUCTIONS = {'b', 'bl', 'blx', 'bx', 'b.w', 'bl.w', 'blx.w', 'bx.w'}
CONDITIONAL_BRANCHES =  {'blgt', 'blvc', 'blcc', 'blhs', 'blmi', 'blne', 'blal',
        'blle', 'blge', 'blvs',
        'blls', 'bllt', 'bllo', 'blcs', 'blhi', 'bleq', 'blpl', 'bgt', 'bvc', 'bcc',
        'bhs', 'bmi', 'bne', 'bal', 'ble', 'bge', 'bvs', 'bls', 'blt', 'blo', 'bcs',
        'bhi', 'beq', 'bpl', 'bxgt', 'bxvc', 'bxcc', 'bxhs', 'bxmi', 'bxne', 'bxal',
        'bxle', 'bxge', 'bxvs', 'bxls', 'bxlt', 'bxlo', 'bxcs', 'bxhi', 'bxeq', 'bxpl',
        'blxgt', 'blxvc', 'blxcc', 'blxhs', 'blxmi', 'blxne', 'blxal', 'blxle', 'blxge',
        'blxvs', 'blxls', 'blxlt', 'blxlo', 'blxcs', 'blxhi', 'blxeq', 'blxpl',
        'cbz', 'cbnz', 'blgt.w', 'blvc.w', 'blcc.w', 'blhs.w', 'blmi.w', 'blne.w', 'blal.w',
        'blle.w', 'blge.w', 'blvs.w', 'blls.w', 'bllt.w', 'bllo.w', 'blcs.w', 'blhi.w', 'bleq.w',
        'blpl.w', 'bgt.w', 'bvc.w', 'bcc.w', 'bhs.w', 'bmi.w', 'bne.w', 'bal.w', 'ble.w', 'bge.w',
        'bvs.w', 'bls.w', 'blt.w', 'blo.w', 'bcs.w', 'bhi.w', 'beq.w', 'bpl.w', 'bxgt.w', 'bxvc.w',
        'bxcc.w', 'bxhs.w', 'bxmi.w', 'bxne.w', 'bxal.w', 'bxle.w', 'bxge.w', 'bxvs.w', 'bxls.w',
        'bxlt.w', 'bxlo.w', 'bxcs.w', 'bxhi.w', 'bxeq.w', 'bxpl.w', 'blxgt.w', 'blxvc.w', 'blxcc.w',
        'blxhs.w', 'blxmi.w', 'blxne.w', 'blxal.w', 'blxle.w', 'blxge.w', 'blxvs.w', 'blxls.w',
        'blxlt.w', 'blxlo.w', 'blxcs.w', 'blxhi.w', 'blxeq.w', 'blxpl.w', 'cbz.w', 'cbnz.w'}

#Record the location of branch instructions in the binary
BRANCHES = {}
MEM_INSTR = []
STARTING_ADDRESS = ''
HEX_DATA = ''
ISR_POINTERS = []

# Takes a hex representation and returns an int
def endian_switch(val):
    tmp = "0x" + val[6] + val[7] + val[4] + val[5] + val[2] + val[3] + val[0] + val[1]
    return(int(tmp,16))

class instr_data(object):
    def __init__(self, instr, op):
        self.instr = instr
        self.op = op

class DisassemblerCore(object):
    def __init__(self, filename):
        global MEM_INSTR
        global BRANCHES
        self.filename = filename
        self.file_data = b''
        self.starting_address = ''
        self.beginning_code = ''
        self.stack_top = ''
        self.isr_num = 0
        self.isr_table_length = 0
        ISR_POINTERS = []
        self.curr_mnemonic = ''
        self.curr_op_str = ''
        self.done = False
        #Keep track of the size of the instruction (can be determined by Capstone)
        self.size = 0
        self.subroutine_branch = []

    def run(self):
        self.load_file()
        for i in range(len(self.file_data)):
            MEM_INSTR.append(0)
        self.disassemble()
        #print('\n\n\nDisassembly\n\n\n')
        disassembled_instrs = 0
        #print 'DISASSEMBLY'
        #for i in range(len(MEM_INSTR)):
        #    if MEM_INSTR[i] != 0:
        #        disassembled_instrs += 1
        #        print('%s\t%s'%(hex(i+int(IMAGEBASE,16)), MEM_INSTR[i].instr+' '+MEM_INSTR[i].op))
        #        #if 'b\t#' + hex(i+int(IMAGEBASE,16)) == MEM_INSTR[i]:
        #        #    print'banana'
        #        #    break;
        ##print BRANCHES
        #print('NUMBER OF DISASSEMBLED INSTRUCTIONS:')
        #print(disassembled_instrs)
        return True

    def load_file(self):
        global HEX_DATA, STARTING_ADDRESS
        with open(self.filename, 'rb') as f:
            self.file_data = f.read()
        f.close()
        HEX_DATA = binascii.hexlify(self.file_data)
        # Stack top stored in first word, starting address in second
        self.stack_top = endian_switch(HEX_DATA[0:8])
        self.starting_address = endian_switch(HEX_DATA[8:16])
        STARTING_ADDRESS = self.starting_address
        if self.starting_address % 2 != 0:
            IS_THUMB_MODE = 1
        else:
            IS_THUMB_MODE = 0
        # Detect endianness. (See daniEmu source code documentation if it's open source by now)
        index = 16
        while (True):
            address = endian_switch(HEX_DATA[index:index+8])
            index += 8
            if address != 0:
                if ((address % 2 == 0) or
                        (address > self.starting_address + len(self.file_data)) or
                        (address < self.starting_address - len(self.file_data))):
                    #Weird offset because of "index+=8" and self.beginning_code-thumb_mode
                    self.beginning_code = int(IMAGEBASE,16) + (index-8)/2 + 1
                    #print(hex(self.beginning_code))
                    break;
            if(address != 0):
                self.isr_num += 1
            if (address != 0) and (address not in ISR_POINTERS):
                ISR_POINTERS.append(address)
            self.isr_table_length += 1
        if self.isr_num < 8 or self.starting_address > int("0x40000000", 16):
           print(">>>>BIG ENDIAN DETECTED<<<<")
           index = 16
           del(ISR_POINTERS[:])
           self.starting_address = int(HEX_DATA[8:16], 16)
           self.stack_top = int(HEX_DATA[0:8], 16)
           while (True):
               address = int(HEX_DATA[index:index+8], 16)
               index += 8
               if address != 0:
                   if ((address % 2 == 0) or
                           (address > self.starting_address + len(self.file_data)) or
                           (address < self.starting_address - len(self.file_data))):
                       self.beginning_code = address
                       break;
               if (address != 0) and (address not in ISR_POINTERS):
                   ISR_POINTERS.append(address)
           self.isr_table_length += 1

    #Disassemble ONE instruction
    def dasm_single(self, md, code, addr):
        #Keep track of the number of instructions disassembled

        count = 0
        for(address, size, mnemonic, op_str) in md.disasm_lite(code,
                addr):
            count += 1
            self.curr_mnemonic = str(mnemonic)
            self.curr_op_str = str(op_str)
            instr = self.curr_mnemonic + '\t' + self.curr_op_str
            #MEM_INSTR[address-int(IMAGEBASE,16)] = instr
            MEM_INSTR[address-int(IMAGEBASE,16)] = instr_data(self.curr_mnemonic, self.curr_op_str)
            #if self.curr_mnemonic in self.branch_instructions or self.curr_mnemonic in self.conditional_branches:
            #   BRANCHES[address-int(IMAGEBASE,16)] = str(self.curr_mnemonic) + ', ' + str(self.curr_op_str)
            #debugging
#            print('%s\t%s\t%s\t\t%s'%(hex(address), instr, size, binascii.hexlify(code)))
        '''dasm_single is given 4 bytes. If Capstone is only able to disassemble 1 2-byte instruction,
           the second 2 bytes of the 4 belong to the next instruction.'''
        if count == 1 and size == 2:
            return False
        else:
            return True

    # https://www.capstone-engine.org/lang_python.html
    def disassemble(self):
        start = (self.beginning_code - int(IMAGEBASE, 16) - 1) * 2
        #start = (self.starting_address - int(IMAGEBASE, 16) - 1) * 2
        self.curr_instr = start
        self.curr_addr = self.beginning_code - IS_THUMB_MODE  #offset for thumb
        #self.curr_addr = self.starting_address - IS_THUMB_MODE
        # Section of code to be disassembled
        code = HEX_DATA[self.curr_instr:self.curr_instr+MAX_INSTR_SIZE].decode('hex')
        prev_addr = 0
        while(self.curr_instr+MAX_INSTR_SIZE < len(HEX_DATA)):
            if self.dasm_single(MD, code, self.curr_addr):
                self.curr_instr += MAX_INSTR_SIZE
                self.curr_addr += 4
            else:
                self.curr_instr += MAX_INSTR_SIZE/2
                self.curr_addr += 2
            code = HEX_DATA[self.curr_instr:self.curr_instr+MAX_INSTR_SIZE].decode('hex')


    def toggle_thumb(self):
        if IS_THUMB_MODE == 1:
            IS_THUMB_MODE = 0
            MD = Cs(CS_ARCH_ARM, CS_MODE_ARM)
        elif IS_THUMB_MODE == 0:
            IS_THUMB_MODE = 1
            MD = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

class path_data:
    def __init__(self, path1, path2):
        self.left = path1
        self.right = path2
        #pop instructions can lead to different addresses depending on the address of the
        #subroutine caller.
        self.pop_paths = []
        self.sources = []
        self.mode = ''
        self.arg = ''
class subroutine_data:
    def __init__(self):
        self.subroutines = {}

class GeneratorCore(object):
    def __init__(self, disassembly, branches):
        self.mem_instr = disassembly
        self.paths = {}
        # key = branch instruction, value = branch setter
        self.set_branch_pairs = {}
        self.current_setter = 0
        self.register_branches = {}
        self.register_branches['r0'] = []
        self.register_branches['r1'] = []
        self.register_branches['r2'] = []
        self.register_branches['r3'] = []
        self.register_branches['r4'] = []
        self.register_branches['r5'] = []
        self.register_branches['r6'] = []
        self.register_branches['r7'] = []
        self.register_branches['r8'] = []
        self.register_branches['r9'] = []
        self.register_branches['r10'] = []
        self.register_branches['r11'] = []
        self.register_branches['r12'] = []
        self.register_branches['r13'] = []
        self.register_branches['r14'] = []
        self.register_branches['r15'] = []
        self.register_branches['lr'] = []
        self.return_address_stack = []
        self.link_reg_branch_dest = 0
        self.link_branch_instructions = {}
        # The beginning of invalid instructions
        self.end = 0
        self.linked_instrs = {}
        # Conditional branch p                                                aths that were unexplored
        self.branches = []
        self.cond_branches = []
        #Keep track of the last instruction to add to sources
        self.last_instr = 0
        #Keep track of which isr is being analyzed
        self.isr_num = 0

    def run(self):
        self.generate_paths()
        #for i in range(len(FLOW)-1):
        #    try:
        #        if (int(FLOW[i+1],16) != self.paths[int(FLOW[i],16)].left) and (int(FLOW[i+1],16) != self.paths[int(FLOW[i],16)].right):
        #            print int(FLOW[i],16), int(FLOW[i+1],16)
        #            print self.paths[int(FLOW[i],16)].left, self.paths[int(FLOW[i],16)].right
        #            print int(FLOW[i+1],16) == self.paths[int(FLOW[i],16)].left
        #            break;
        #    except:
        #        print FLOW[i] + 'error'
        #        break;
        #addresses = list(self.paths.keys())
        #addresses.sort()
        #for i in addresses:
        #    print("Address: %s  First Path: %s   Branch Path: %s   Instruction: %s"%(hex(i), hex(self.paths[i].left), hex(self.paths[i].right), self.paths[i].arg))

        print('paths: ', len(self.paths))
           #     print("Address: %s  First Path: %s   Branch Path: %s   Instruction: %s"%(hex(i), hex(self.paths[i].left), hex(self.paths[i].right)))

        return (self.paths, self.set_branch_pairs)

    # Calculate the location of a branch with a register as the argument
    def register_branch_calc(self, instr, op, curr_addr):
        #Calculate branch destinations when argument is a register
        if instr == 'ldr' and 'pc' in op and 'sp' in op:
            return False
        if instr == 'ldr' and 'pc' in op:
            addr = curr_addr + int(IMAGEBASE, 16)
            reg = op.split(',')[0]
            arg = op.split('#')[1]
            arg = int(arg[:-1],16)
            loc = int(math.floor((addr + arg)/4)*4)
            # 8 for doubleword offset
            loc = int(loc - int(IMAGEBASE, 16)) * 2 + 8
            data = HEX_DATA[loc:loc+8]
            reg_br_addr = endian_switch(data)-1
            self.register_branches[reg].append(reg_br_addr)
            return True
        else:
            return False

    #Return format: branch instruction?, first branch path, second path, next instruction to handle, empty pop?
    def branch_destination_handler(self, instr, op, addr):
        global MEM_INSTR
        empty_pop = False
        if instr in BRANCH_INSTRUCTIONS or instr in CONDITIONAL_BRANCHES:
            dest = 0
            if op in REGISTER_NAMES:
                if len(self.register_branches[op]) == 0:
                    empty_pop = True
                    dest = 0
                else:
                    dest = self.register_branches[op].pop()
            else:
                dest = int(op.split('#')[1],16)
            if instr in BRANCH_INSTRUCTIONS:
                return (True, 0, dest, 0, empty_pop)
            elif instr in CONDITIONAL_BRANCHES:
                index = addr + 1
                while(MEM_INSTR[index] == 0):
                    index += 1
                index += int(IMAGEBASE,16)
                return (True, index, dest, addr + 1, empty_pop)
        else:
            return (False, 0, 0, 0, empty_pop)

    # Link remaining instructions after reaching end in while loop
    def remaining_instructions(self):
        test = True
        if len(self.branches) != 0:
            self.last_instr = self.cond_branches.pop()
            tmp = self.branches.pop()
            while(MEM_INSTR[tmp] == 0):
                tmp += 1
            return tmp
        elif len(self.return_address_stack) != 0:
            self.last_instr = 0
            tmp = self.return_address_stack.pop()-int(IMAGEBASE,16)
            while(MEM_INSTR[tmp] == 0):
                tmp+=1
            return tmp
        elif self.isr_num != len(ISR_POINTERS)-1:
            self.last_instr = 0
            self.isr_num += 1
            tmp = ISR_POINTERS[self.isr_num]  - int(IMAGEBASE,16)
            while(MEM_INSTR[tmp] == 0):
                tmp += 1
            return tmp
        else:
            return 0

    def pair_set_branch(self, i, instr):
        global CONDITIONAL_BRANCHES

        if instr.split('.')[0] == 'mlss':
            self.current_setter = i
            return
        elif ((instr.split('.')[0][-1] == 's' and
            instr.split('.')[0] != 'mls' and
            instr.split('.')[0] != 'bls' and
            instr.split('.')[0] != 'bcs') or
            instr.split('.')[0] == 'cmp' or
            instr.split('.')[0] == 'cmn'):
            self.current_setter = i
            return
        if instr in CONDITIONAL_BRANCHES:
            self.set_branch_pairs[self.current_setter] = i
            self.current_setter = 0

    def subroutine_handler(self, i):
        return

    def instruction_linking(self, i):
        global BRANCH_INSTRUCTIONS, REGISTER_NAMES, CONDITIONAL_BRANCHES, MEM_INSTR, ISR_POINTERS, ENDING_ADDRESS
        while True:
            if i >= len(MEM_INSTR):
                tmp = self.remaining_instructions()
                if tmp == 0:
                    return
                else:
                    i = tmp
            else:
                while(MEM_INSTR[i] == 0):
                    i += 1
                    if i == len(MEM_INSTR):
                        break
                if i == len(MEM_INSTR):
                    tmp = self.remaining_instructions()
                    if tmp == 0:
                        return
                    else:
                        i = tmp

            if i+int(IMAGEBASE,16) in self.paths:
                tmp = self.remaining_instructions()
                if tmp == 0:
                    return
                else:
                    i = tmp
            else:
                instr = MEM_INSTR[i].instr
                op = MEM_INSTR[i].op

                self.pair_set_branch(i, instr)

                if (instr == 'b' and op not in REGISTER_NAMES) and (int(op.split('#')[1],16)-int(IMAGEBASE,16) == i):
                    self.paths[i+int(IMAGEBASE,16)] = path_data(0, int(op.split('#')[1],16))
                    self.paths[i+int(IMAGEBASE,16)].arg = instr + ' ' + op
                    self.paths[i+int(IMAGEBASE,16)].sources.append(self.last_instr)
                    ENDING_ADDRESS = hex(i+int(IMAGEBASE,16))
                    #print(hex(i+int(IMAGEBASE,16)), instr, op)
                    tmp = self.remaining_instructions()
                    if tmp == 0:
                        return
                    else:
                        i = tmp
                else:

                    #print(hex(i+int(IMAGEBASE,16)), instr, op)

                    self.register_branch_calc(instr, op, i)

                    #try:
                    if ('pop' in instr and 'pc' in op) or ('ldr' in instr and 'pc' in op and 'sp' in op):
                        if len(self.return_address_stack) != 0:
                            last_instr_tmp = self.last_instr
                            self.last_instr = i
                            pop_val = self.return_address_stack.pop()
                            self.paths[i+int(IMAGEBASE,16)] = path_data(0, pop_val)
                            self.paths[i+int(IMAGEBASE,16)].arg = instr + ' ' + op
                            self.paths[i+int(IMAGEBASE,16)].sources.append(last_instr_tmp)
                            self.paths[i+int(IMAGEBASE,16)].pop_paths.append(pop_val)
                            i = pop_val - int(IMAGEBASE,16)
                            self.return_from_sub = True
                        else:
                            self.paths[i+int(IMAGEBASE,16)].sources.append(self.last_instr)
                            self.paths[i+int(IMAGEBASE,16)] = path_data(0, 0)
                            self.paths[i+int(IMAGEBASE,16)].arg = instr + ' ' + op
                            self.return_from_sub = True
                            i = self.remaining_instructions()
                    elif (instr in BRANCH_INSTRUCTIONS or instr in CONDITIONAL_BRANCHES) and 'lr' in op:
                        if len(self.return_address_stack) != 0:
                            last_instr_tmp = self.last_instr
                            self.last_instr = i
                            pop_val = self.return_address_stack.pop()
                            self.paths[i+int(IMAGEBASE,16)] = path_data(0, pop_val)
                            self.paths[i+int(IMAGEBASE,16)].arg = instr + ' ' + op
                            self.paths[i+int(IMAGEBASE,16)].sources.append(last_instr_tmp)
                            self.paths[i+int(IMAGEBASE,16)].pop_paths.append(pop_val)
                            i = pop_val - int(IMAGEBASE,16)
                            self.return_from_sub = True
                        else:
                            self.paths[i+int(IMAGEBASE,16)].sources.append(self.last_instr)
                            self.paths[i+int(IMAGEBASE,16)] = path_data(0, 0)
                            self.paths[i+int(IMAGEBASE,16)].arg = instr + ' ' + op
                            self.return_from_sub = True
                            i = self.remaining_instructions()
                    else:
                        b_result = self.branch_destination_handler(instr, op, i)
                        if b_result[0] == True:
                            self.paths[i+int(IMAGEBASE,16)] = path_data(b_result[1], b_result[2])
                            self.paths[i+int(IMAGEBASE,16)].arg = instr + ' ' + op
                            self.paths[i+int(IMAGEBASE,16)].sources.append(self.last_instr)
                            #if no branch destination was determined
                            if b_result[4] == True:
                                return
                            if 'bl' in instr:
                                index = i + 1
                                while(MEM_INSTR[index] == 0):
                                    index += 1
                                index += int(IMAGEBASE,16)
                                self.return_address_stack.append(index)
                            if b_result[3] != 0:
                                self.branches.append(b_result[3])
                                self.cond_branches.append(i)
                                self.last_instr = i
                                i = b_result[2]-int(IMAGEBASE,16)
                            else:
                                self.last_instr = i
                                i = b_result[2]-int(IMAGEBASE,16)
                        elif b_result[0] == False:
                            index = i + 1
                            while(MEM_INSTR[index] == 0):
                                index += 1
                            index += int(IMAGEBASE,16)
                            self.paths[i+int(IMAGEBASE,16)] = path_data(index, 0)
                            self.paths[i+int(IMAGEBASE,16)].arg = instr + ' ' + op
                            self.paths[i+int(IMAGEBASE,16)].sources.append(self.last_instr)
                            self.last_instr = i
                            i = i + 1
                    #i = self.remaining_instructions()

    def generate_paths(self):
        '''mem_instr and branches have the imagebase subtracted from them!!'''
        global STARTING_ADDRESS, MEM_INSTR, BRANCHES, BRANCH_INSTRUCTIONS, CONDITIONAL_BRANCHES, HEX_DATA, IS_THUMB_MODE

        i = STARTING_ADDRESS-int(IMAGEBASE,16)-IS_THUMB_MODE

        self.instruction_linking(i)
        return 0

#Generate models that represent conditional branch paths
def symbolic_exec(paths, set_branch_pairs):
    #key is setter instruction
    global MEM_INSTR
    sym_models = {}
    error_count = 0
    for key in set_branch_pairs:
        model = ''
        syms = {}
        left_model = ''
        right_model = ''
        dest_reg = ''
        if key != 0:    #if there is a setter for the conditional branch
            branch_setter = MEM_INSTR[key].instr.split('.')[0]
            branch_args = MEM_INSTR[key].op
            branch_args = branch_args.split(', ')
            branch_condition = MEM_INSTR[set_branch_pairs[key]].instr.split('b')[1]
            if branch_setter == 'cbz':
                branch_setter = 'cmp'
                branch_condition = 'eq'
            elif branch_setter == 'cbnz':
                branch_setter = 'cmp'
                branch_condition = 'ne'
            if (branch_setter == "cmp"
                    or branch_setter == "cmn"
                    or branch_setter == 'movs'
                    or branch_setter == 'mvns'
                    or branch_setter == 'rsbs'
                    or branch_setter == 'rscs'):
                dest_reg = branch_args[0]
                syms['x'] = dest_reg
                syms['y'] = branch_args[1]
                model = 'y'
            elif branch_setter == 'adds':
                if len(branch_args) == 3:
                    dest_reg = branch_args[0]
                    syms['x'] = dest_reg
                    syms['y'] = branch_args[1]
                    syms['z'] = branch_args[2]
                    model = 'y + z'
                else:
                    dest_reg = branch_args[0]
                    syms['x'] = dest_reg
                    syms['y'] = branch_args[1]
                    model = 'x + y'
            elif branch_setter == 'subs' or branch_setter == 'sbcs':
                if len(branch_args) == 3:
                    dest_reg = branch_args[0]
                    syms['x'] = dest_reg
                    syms['y'] = branch_args[1]
                    syms['z'] = branch_args[2]
                    model = 'y - z'
                else:
                    dest_reg = branch_args[0]
                    syms['x'] = dest_reg
                    syms['y'] = branch_args[1]
                    model = 'x - y'
            elif branch_setter == 'lsls':
                if len(branch_args) == 3:
                    dest_reg = branch_args[0]
                    syms['x'] = dest_reg
                    syms['y'] = branch_args[1]
                    syms['z'] = branch_args[2]
                    model = 'y << z'
                elif len(branch_args) == 2 or branch_args[0] == branch_args[1]:
                    dest_reg = branch_args[0]
                    syms['x'] = dest_reg
                    syms['y'] = branch_args[1]
                    model = 'x << y'
            elif branch_setter == 'asrs':
                if len(branch_args) == 3:
                    dest_reg = branch_args[0]
                    syms['x'] = dest_reg
                    syms['y'] = branch_args[1]
                    syms['z'] = branch_args[2]
                    model = 'y >> z'
                elif len(branch_args) == 2 or branch_args[0] == branch_args[1]:
                    dest_reg = branch_args[0]
                    syms['x'] = dest_reg
                    syms['y'] = branch_args[1]
                    model = 'x >> y'
            elif branch_setter == 'ands':
                if len(branch_args) == 3:
                    dest_reg = branch_args[0]
                    syms['x'] = dest_reg
                    syms['y'] = branch_args[1]
                    syms['z'] = branch_args[2]
                    model = 'y & z'
                else:
                    dest_reg = branch_args[0]
                    syms['x'] = dest_reg
                    syms['y'] = branch_args[1]
                    model = 'x & y'
            elif branch_setter == 'eors':
                if len(branch_args) == 3:
                    dest_reg = branch_args[0]
                    syms['x'] = dest_reg
                    syms['y'] = branch_args[1]
                    syms['z'] = branch_args[2]
                    model = 'y ^ z'
                else:
                    dest_reg = branch_args[0]
                    syms['x'] = dest_reg
                    syms['y'] = branch_args[1]
                    model = 'x ^ y'
            elif branch_setter == 'orrs':
                if len(branch_args) == 3:
                    dest_reg = branch_args[0]
                    syms['x'] = dest_reg
                    syms['y'] = branch_args[1]
                    syms['z'] = branch_args[2]
                    model = 'y | z'
                else:
                    dest_reg = branch_args[0]
                    syms['x'] = dest_reg
                    syms['y'] = branch_args[1]
                    model = 'x | y'
            elif branch_setter == 'lsrs':
                model = 'undetermined'
            elif branch_setter == 'bics':
                model = 'undetermined'
            else:
                model = "undetermined"
                #print branch_setter
                error_count += 1

            if 'eq' in branch_condition:
                left_model = 'x == ' + model
                right_model = 'x != ' + model
            elif 'ne' in branch_condition:
                left_model = 'x != ' + model
                right_model = 'x  == ' + model
            elif 'cs' in branch_condition or 'hs' in branch_condition:
                left_model = 'UGE(x,' + model + ')'
                right_model = 'ULT(x,' + model + ')'
            elif 'cc' in branch_condition  or 'lo' in branch_condition:
                left_model = 'ULT(x,' + model + ')'
                right_model = 'UGE(x,' + model + ')'
            elif 'mi' in branch_condition:
                left_model = '0 > ' + model
                right_model = '0 <= ' + model
            elif 'pl' in branch_condition:
                left_model = '0 <= ' + model
                right_model = '0 > ' + model
            elif 'vs' in branch_condition:
                #0x7ffffffff: max signed 32-bit number
                left_model = 'UGT(' + model + ', int(0x7fffffff,16))'
                right_model = 'ULE(' + model + ', int(0x7fffffff,16))'
            elif 'vc' in branch_condition:
                left_model = 'ULE(' + model + ', int(0x7fffffff,16))'
                right_model = 'UGT(' + model + ', int(0x7fffffff,16))'
            elif 'hi' in branch_condition:
                left_model = 'UGT(' + dest_reg + ', ' + model + ')'
                right_model = 'ULE(' + dest_reg + ', ' + model + ')'
            elif 'ls' in branch_condition:
                left_model = 'ULE(' + dest_reg + ', ' + model + ')'
                right_model = 'UGT(' + dest_reg + ', ' + model + ')'
            elif 'ge' in branch_condition:
                left_model = 'x >= ' + model
                right_model = 'x < ' + model
            elif 'lt' in branch_condition:
                left_model = 'x < ' + model
                right_model = 'x >= ' + model
            elif 'gt' in branch_condition:
                left_model = 'x > ' + model
                right_model = 'x <= ' + model
            elif 'le' in branch_condition:
                left_model = 'x <= ' + model
                right_model = 'x > ' + model
            sym_models[key] = (left_model, right_model, syms)
        else:
            error_count += 1

    return sym_models
    #print(sym_models)
    #print(error_count)

def get_models():
    global SYM_MODELS
    return SYM_MODELS

def get_pairs():
    global SET_BRANCH_PAIRS
    return SET_BRANCH_PAIRS

#target address to locate is a hex string
def get_path(target):
    target = int(target, 16)
    if target not in PATHS:
        print('not in paths')
        return
    curr = STARTING_ADDRESS-1
    target_map = []
    untaken_branches = []
    depth_count = []
    dp_index = 0
    depth_count.append(0)
    while curr != target:
        if curr not in target_map:
            if curr in PATHS:
                print(hex(curr), MEM_INSTR[curr-int(IMAGEBASE,16)].instr, MEM_INSTR[curr-int(IMAGEBASE,16)].op)
                target_map.append(curr)
                depth_count[dp_index]+=1
                if PATHS[curr].left != 0:
                    if PATHS[curr].right != 0:
                       untaken_branches.append(PATHS[curr].right)
                       dp_index+=1
                       depth_count.append(0)
                    curr = PATHS[curr].left
                else:
                    curr = PATHS[curr].right
            else:
                if len(untaken_branches) != 0:
                    curr = untaken_branches.pop()
                    for i in range(depth_count[dp_index]):
                        target_map.pop()
                    depth_count.pop()
                    dp_index-=1
                else:
                    print('failed')
                    return
        else:
            if len(untaken_branches) != 0:
                curr = untaken_branches.pop()
                for i in range(depth_count[dp_index]):
                    target_map.pop()
                depth_count.pop()
                dp_index-=1
            else:
                print('failed')
                return
        if curr == target:
            print(hex(curr), 'end')
            #print depth_count
            target_map.append(curr)
    print target_map
    for i in target_map:
        tmp = i-int(IMAGEBASE,16)
        print(hex(i), MEM_INSTR[tmp].instr, MEM_INSTR[tmp].op)

# Main
def main():
    global FLOW, FILE_NAME, SET_BRANCH_PAIRS, SYM_MODELS, PATHS
    tmp = False
    if len(sys.argv) > 1:
        FILE_NAME = str(sys.argv[1])
        #IMAGEBASE = str(sys.argv[2])
        with open('startup.txt', 'w') as f:
            f.write(FILE_NAME)
            #f.write(IMAGEBASE)
            f.close()
    else:
        with open('startup.txt', 'r') as f:
            FILE_NAME = f.readline()
            f.close()
        if len(FILE_NAME) == 0:
            print('No file found')
            return True
    dc = DisassemblerCore(FILE_NAME)
    dc.run()
    #flow_file = open('flow.txt', 'r')
    #content = flow_file.read()
    #FLOW = content.split(", ")
    #flow_file.close()
    gc = GeneratorCore(MEM_INSTR, BRANCHES)
    PATHS, SET_BRANCH_PAIRS = gc.run()
    #SYM_MODELS = symbolic_exec(PATHS, SET_BRANCH_PAIRS)
    #get_path('0x80674')
    #get_path('0x88888')
    #get_path(ENDING_ADDRESS)
    #print(ENDING_ADDRESS)
    page_size = 1024
    image_base = min(PATHS) & ~(page_size-1)
    print hex(image_base)


if __name__ == '__main__':
    main()
