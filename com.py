#!/usr/bin/python

"""
Communication module for interfacing with Polly, a deterministic Bitcoin hardware wallet adhering to BIP32. 

Requires the HID API for USB communications.


The MIT License (MIT)

Copyright (c) 2014 by Nathaniel Burke

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""

import sys
import hid
import serial
from serial.tools import list_ports
import time

from struct import pack, unpack

# Polly USB vendor and device ID
POLLY_VID  = 0x0451
POLLY_DID  = 0x16C9

# Commands                  # Response (assuming properly formed command)
CMD_RESET             = 1   # SUCCESS
CMD_IDENTIFY          = 2   # SUCCESS
CMD_GET_PUBLIC_KEY    = 3   # SUCCESS, INVALID

CMD_SIGN_TX           = 4   # SUCCESS, INVALID
CMD_PREV_TX           = 5   # SUCCESS, INVALID
CMD_GET_SIGNED_TX     = 6   # SUCCESS, INVALID, USER, DENIED, BUSY

CMD_SET_MASTER_SEED   = 11  # SUCCESS, INVALID

CMD_ACK_SUCCESS       = 32
CMD_ACK_INVALID       = 33
CMD_ACK_DENIED        = 34
CMD_ACK_USER          = 35
CMD_ACK_BUSY          = 36

# Command payloads
CMD_SIMPLE_BYTES               = 1
CMD_IDENTIFY_RESP_BYTES        = 17
CMD_GET_PUBLIC_KEY_RESP_BYTES  = 65
CMD_GET_PUBLIC_KEY_BYTES       = 8
CMD_SET_MASTER_SEED_MAX_BYTES  = ((18 * 8) + 7)  # 18 words, max 8 chars per word, 7 spaces

# Packet size
PACKET_BYTES = 64

# Control flow
CTRL_START         = 0x80
CTRL_CONT          = 0x88
CTRL_START_STREAM  = 0xC0
CTRL_CONT_STREAM   = 0xC8

# Default command timeout
READ_TIMEOUT_MS  = 100000

class PollyCom:
    """ 
    Class for communication with the Polly hardware Bitcoin wallet.
    """
    
    # General device handle, could be USB or Bluetooth serial
    dev = None
    
    # String for the handle type ('usb' or 'bluetooth')
    devtype = None

    KEY_MASTER  = 0
    KEY_ACCOUNT = 1
    KEY_CHAIN   = 2
    KEY_ADDRESS = 3
    
    def __init__(self, usbscan = False):
        
        # Tracks time to execute commands on Polly 
        self.t = 0
        
        # Make a connection with Polly
        if None == PollyCom.dev :
            
            print ()
            print ("Connecting to Polly")
            print ("-------------------")
            print ()
            
            print ("Trying USB : ", end = '')
            PollyCom.dev = hid.device()
            
            try:
                raise IOError("ok")
            
                if True == usbscan:
                    self.__usb_scan()
        
                PollyCom.dev.open(POLLY_VID, POLLY_DID)
                PollyCom.devtype = 'usb'
                
                # TODO flush out any previous command data
                
                model = self.send_identify()
                
                if 'Polly' in model:
                
                    print ("found")
                    print ()
                    print (" Manufacturer : %s" % PollyCom.dev.get_manufacturer_string())
                    print (" Product      : %s" % PollyCom.dev.get_product_string())
                    print (" Serial No    : %s" % PollyCom.dev.get_serial_number_string())
                    print (" Model        : %s" % model)
                
                    return
                
                else:
                    raise IOError()
                
            except IOError:
                print ("not found")


            # Look at all the Bluetooth serial ports                
            ports = list_ports.comports()
            PollyCom.devtype = 'bluetooth'
            bt_com = False

            for port, name, _ in ports:
                
                if 'BLUETOOTH' in name.upper():
                    
                    bt_com = True
                    
                    print ("Trying Bluetooth serial", port, ": ",  end = '')
                    
                    try:
                        PollyCom.dev = serial.Serial(port, 115200, timeout = 3, writeTimeout = 3)
                        
                        # TODO flush out any previous command data
                        
                        model = self.send_identify()
                        
                        if 'Polly' in model:
                            print ("found")
                            print ()
                            print (" Model : %s" % model)
                            
                            PollyCom.devtype = 'bluetooth'
                            return
                        
                    except IOError:
                        # Unable to connect
                        print ("not found")
            
            if False == bt_com:
                print ("Trying Bluetooth serial : no Bluetooth COM ports found")
                
                    
        print ("\n ERROR: Polly not found")
        raise Exception('Polly not found')

    def send_reset(self):
        """
        Sends the reset command and waits for an ACK.
        """
        
        # Send
        data = pack('<HB', CMD_SIMPLE_BYTES, CMD_RESET)
        self.send_data(data)
    
        # Receive
        data = self.get_data()
        cmd_bytes, cmd = unpack('<HB', bytes(data))
    
        assert cmd_bytes == CMD_SIMPLE_BYTES and\
               cmd       == CMD_ACK_SUCCESS, "send_reset : FAILED"
    
    def send_identify(self):
        """
        Sends the identify command and returns the ID string.
        """
    
        # Send
        data = pack('<HB', CMD_SIMPLE_BYTES, CMD_IDENTIFY)
        self.send_data(data)
    
        # Receive
        data = self.get_data()
        cmd_bytes, cmd, idstr = unpack('<HB16s', bytes(data))
    
        assert cmd_bytes == CMD_IDENTIFY_RESP_BYTES and\
               cmd       == CMD_ACK_SUCCESS, "send_get_id : FAILED"
    
        return ''.join(map(chr,idstr))
    
    
    def send_set_master_seed(self, wordlist):
        """
        Sends the set master seed command and waits for an ACK.
        
        wordlist -  a space separated string of 18 mnemonic words from the Polly wordlist.
                    Note: the checksum must be correct (part of the 18th word) - see BIP0039.
                    gen_wordlist can be used to generate a wordlist including the proper checksum.
        """
        
        assert len(wordlist.split(" ")) == 18, "expecting 18 words"
        assert len(wordlist) <= CMD_SET_MASTER_SEED_MAX_BYTES, "seed too long, must have invalid words"

        # Send
        data = pack('<HB' + str(len(wordlist)) + 's', 1 + len(wordlist), CMD_SET_MASTER_SEED, bytes(wordlist, 'utf-8'))
        self.send_data(data)
    
        # Receive
        data = self.get_data()
        cmd_bytes, cmd = unpack('<HB', bytes(data))
    
        assert cmd_bytes == CMD_SIMPLE_BYTES and\
               cmd       == CMD_ACK_SUCCESS, "send_set_master_seed : FAILED"
    
        
    def send_get_public_key(self, keytype, account, chain, address):
        """
        Sends the get public key command and waits for the key.
        
        keytype - Type of key to retrieve, valid values are KEY_MASTER, KEY_ACCOUNT, KEY_CHAIN, or KEY_ADDRESS.
        account - Account to use for type KEY_ACCOUNT|CHAIN|ADDRESS.
        chain   - Chain to use for type KEY_CHAIN|ADDRESS.
        address - Index (0 - 0x7FFF_FFFF) to use for type KEY_ADDRESS.
        
        Returns a public elliptic curve key in the form (x,y). (0,0) indicates a failure occured.
        """
        
        assert address < 0x80000000, "hardened address keys are not supported"
        
        # Send
        data = pack('<HBBBBL', CMD_GET_PUBLIC_KEY_BYTES, CMD_GET_PUBLIC_KEY, keytype, account, chain, address)
        self.send_data(data)
    
        # Receive
        data = self.get_data()
    
        cmd_bytes, cmd, pub_x, pub_y = unpack('HB32s32s', bytes(data))
    
        assert cmd_bytes == CMD_GET_PUBLIC_KEY_RESP_BYTES, "send_get_public_key : FAILED"
    
        if cmd == CMD_ACK_SUCCESS:
            return int.from_bytes(pub_x, 'big'), int.from_bytes(pub_y, 'big')   
        
        return 0, 0
    
    
    def send_sign_tx(self, in_key_num_pubkey, out_addr_160, out_satoshi, change_key_num, change_satoshi):
        """
        Sends the initial information needed to sign a tx and waits for an ACK. 
        
        Note: This command must be followed by one or more send_prev_tx() calls to support 
              the key nums used to fund the payment. Finally, send_get_signed_tx() must be called
              to get the signed tx.
        
        in_key_num_pubkey - tuple list of the form (in_key_num, in_key_pubkey). Each entry contains the key 
                            number to fund payment (0 - 0x7FFF_FFFF) and the key's compressed public 
                            key (33 bytes).
        out_addr_160      - output address to pay in a RIPEMD-160 form.
        out_satoshi       - satoshis to output.
        change_key_num    - send change to this key num (0 - 0x7FFF_FFFF). Pass 'None' for no change.
        change_satoshi    - satoshis to change.
        """ 

        # Number of inputs
        data = pack('B', len(in_key_num_pubkey))
    
        # Input key ids and their public keys, assuming a m/0h/0/in_key_num path
        for in_key_num, in_key_pubkey in in_key_num_pubkey:
            data = data + pack('<BBI33s', 0, 0, in_key_num, in_key_pubkey)
    
        # Output address
        data = data + pack('<20sQ', out_addr_160, out_satoshi)
    
        # Change address (optional), assuming an m/0h/1/change_key_num path
        if change_key_num != None:
            data = data + pack('<BBIQ', 0, 1, change_key_num, change_satoshi)
    
        # Command id and number of bytes
        data = pack('<HB', len(data) + 1, CMD_SIGN_TX) + data
    
        # Send
        self.send_data(data)
    
        # Receive
        data = self.get_data()
        cmd_bytes, cmd = unpack('<HB', bytes(data))
    
        assert cmd_bytes == CMD_SIMPLE_BYTES and\
               cmd       == CMD_ACK_SUCCESS, "send_sign_tx : FAILED"

    
    def send_prev_tx(self, in_idx_out_idx, prev_tx_data):
        """
        Sends a previous tx for one or more input keys sent in send_sign_tx, and waits for an ACK.
        
        Note: This command must be preceded by send_sign_tx() and followed by send_get_signed_tx()
              to get the signed tx.
        
        Each input key sent in send_sign_tx() must have an associated previous transaction to indicate
        how many unspent coins it has. This function is used to send these supporting transactions.
        These can be faked (e.g. set the input values very high), and Polly will sign the tx. However, 
        if the previous tx is not found in the blockchain the network will reject the signed tx. 
    
        in_idx_out_idx - tuple list in the form (in_idx, out_idx). Input keys are indexed by the
                         order they were presented to the device in send_sign_tx(). in_idx is
                         this 0-based index. Each input key num (associated with in_idx) must have 
                         unspent coins. The out_idx is the output index from this previous tx
                         that matches the input key num and indicates its unspent coins.
    
        prev_tx_data   - a byte stream of the complete previous tx.
        """
    
        # Compile the out index information
        data = pack('<B', len(in_idx_out_idx))
    
        for in_idx, out_idx in in_idx_out_idx :
            data += pack('<BL', in_idx, out_idx)
    
        # Pack the command header and prev tx
        send_len = len(prev_tx_data) + len(data) + 1
        data = pack('<HB' , send_len, CMD_PREV_TX) + data + pack(str(len(prev_tx_data)) + 's', prev_tx_data)
    
        # Send
        self.send_data(data, stream = True)
    
        # Receive
        data = self.get_data()
    
        cmd_bytes, cmd = unpack('<HB', bytes(data))
    
        assert cmd_bytes == CMD_SIMPLE_BYTES and\
               cmd       == CMD_ACK_SUCCESS, "send_prev_tx : FAILED"

    
    def send_get_signed_tx(self):
        """
        Sends the get signed tx command and waits for a response.
        
        Note: This command must be preceded by send_sign_tx() and then by one or more 
              send_prev_tx() calls to support the key nums used to fund the payment.
        
        Returns a complete signed tx.
        """
    
        while True:
            
            # Send
            data = pack('<HB', CMD_SIMPLE_BYTES, CMD_GET_SIGNED_TX)
            self.send_data(data)
            
            # Receive
            data = self.get_data()
            cmd_bytes, cmd = unpack('<HB', bytes(data[0:3]))
            
            # SUCCESS, INVALID, USER, DENIED, BUSY
            
            if cmd == CMD_ACK_SUCCESS:
                # Strip away the command and command bytes, just return the signed tx
                return bytes(data[3:(3 + cmd_bytes)])
            
            elif cmd == CMD_ACK_INVALID:
                assert 0, "send_get_signed_tx: invalid response, command incorrect"
        
            elif cmd == CMD_ACK_USER:
                pass
            elif cmd == CMD_ACK_BUSY:
                pass
                
            elif cmd == CMD_ACK_DENIED: 
                assert 0, "send_get_signed_tx: user denied the signing"
                
            time.sleep(0.5)


    def get_cmd_time(self):
        """
        Returns the time in seconds to execute the last command.
        """
        
        return "{0:.3f}s".format(self.t) 


    def send_data(self, data, stream = False):
        """
        Sends raw data to Polly via USB, typically the command specific functions are used instead of this.
        
        data   - raw byte array to packet. Packetization and padding is done by this routine. 
        stream - use stream flow control if True, or normal control if False
        """ 
    
        # Commands to Polly are always send_data/get_data pairs
        # Start the timer here, it will be stopped in get_data 
        self.t = time.clock()
    
        if not stream :
            ctrl_start = CTRL_START
            ctrl_cont  = CTRL_CONT
        else:
            ctrl_start = CTRL_START_STREAM
            ctrl_cont  = CTRL_CONT_STREAM
            
        ctrl_byte = ctrl_start

        # The command byte count in the data does not include itself, hence the +2
        data_bytes_remain = (data[1] << 8) + data[0] + 2;
        data_offset       = 0
        
        # Send out the data
        while (data_bytes_remain > 0):

            # Room must be left for the control flow byte, hence PACKET_BYTES - 1  
            data_bytes = min(data_bytes_remain, PACKET_BYTES - 1)
    
            packet = bytes([ctrl_byte]) + data[data_offset : data_offset + data_bytes]
            
            # Pad out the packet if it is < PACKET_BYTES
            if len(packet) < PACKET_BYTES:
                packet = packet + bytes(PACKET_BYTES - len(packet))
            
            # USB needs the preamble byte, it is stripped off by Polly upon reception
            if PollyCom.devtype == 'usb': 
                packet = b'\x00' + packet
    
            PollyCom.dev.write(packet)
    
            data_offset       += data_bytes
            data_bytes_remain -= data_bytes
            
            ctrl_byte = ctrl_cont


    def get_data(self, timeout = READ_TIMEOUT_MS):
        """
        Gets raw data from Polly via USB, typically the command specific functions are used instead of this.
        
        Returns a single raw byte array with flow control bytes stripped.
        """ 
        
        data = []
        
        # Read in the first chunk
        if (PollyCom.devtype == 'usb'):
            tmp = PollyCom.dev.read(PACKET_BYTES, timeout)
        else:
            tmp = PollyCom.dev.read(PACKET_BYTES)
        
        assert tmp, "read timeout"
        assert tmp[0] == CTRL_START, "invalid control token, expecting CTRL_START"
    
        # The command bytes count, plus the command bytes count field itself
        data_bytes = (tmp[2] << 8) + tmp[1] + 2 
        
        # Read in the rest
        while True:
            
            # Stripping off the control byte, hence PACKET_BYTES - 1
            read_bytes = min(data_bytes, PACKET_BYTES - 1)
            
            # Strip off the control byte
            data += tmp[1 : read_bytes + 1]
            
            data_bytes -= read_bytes
            
            if data_bytes < 1 :
                break
            
            if (PollyCom.devtype == 'usb'):
                tmp = PollyCom.dev.read(PACKET_BYTES, timeout)
            else:
                tmp = PollyCom.dev.read(PACKET_BYTES)
            
            assert tmp, "read timeout"
            assert tmp[0] == CTRL_CONT, "invalid control token, expecting CTRL_CONT"
    
        # Calculate the time delta between send_data and get_data (the total command time)
        self.t = time.clock() - self.t;
    
        return data 
    
    def __usb_scan(self):
        """
        Diagnostic scan of available USB devices.
        """
        
        for d in hid.enumerate(0, 0):
            keys = d.keys()
            
            for key in keys:
                print ("%s : %s" % (key, d[key]))
                
            print ("")

def blueserial():
    ser = serial.Serial("COM3", 115200)
    ser.write(bytearray("$$$", 'ascii'))
    
    ser.timeout = 1
    
    data = ser.read(1000)
    print(str(data))
    
    ser.close()
        

def main():
    PollyCom() 

if __name__ == '__main__':
    status = main()
    sys.exit(status)