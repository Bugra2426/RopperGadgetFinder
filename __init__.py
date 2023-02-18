import binaryninja as bn
import ropper

class RopperPlugin(bn.plugin.BackgroundTaskThread):
    def __init__(self, bv):
        super(RopperPlugin, self).__init__('Extracting ROP Gadgets')
        self.bv = bv

    def run(self):
        try:
            # Create a Ropper object for the current binary
            rop = ropper.Ropper(self.bv.file.filename)

            # Set the architecture of the binary
            arch = self.bv.arch.name
            rop.options.architecture = arch

            # Set the number of bytes per instruction based on the architecture
            if arch == 'x86':
                bytes_per_inst = 1
            elif arch.startswith('arm'):
                bytes_per_inst = 4
            else:
                bn.log_error('Unsupported architecture: %s' % arch)
                return

            # Extract ROP gadgets from the binary
            gadgets = rop.search(searchtype='all', range=(0x0, 0xffffffff), inst_bytes=bytes_per_inst)

            # Print the gadgets to the Binary Ninja log
            bn.log_info('ROP Gadgets:\n')
            for gadget in gadgets:
                bn.log_info('%s\n' % gadget)

        except Exception as e:
            bn.log_error('Error extracting ROP gadgets: %s' % str(e))

def extract_rop_gadgets(bv):
    # Create an instance of the RopperPlugin and start it as a background task
    RopperPlugin(bv).start()

bn.PluginCommand.register('Extract ROP Gadgets', 'Extract ROP gadgets from the current binary', extract_rop_gadgets)
