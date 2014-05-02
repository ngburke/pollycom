#!/usr/bin/env python
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
import time

from struct import pack, unpack

# Polly USB vendor and device ID
POLLY_VID  = 0x0451
POLLY_DID  = 0x16C9

# Commands
CMD_RESET            = 1
CMD_IDENTIFY         = 2
CMD_GET_PUBLIC_KEY   = 3

CMD_SIGN_TX          = 4
CMD_PREV_TX          = 5
CMD_GET_SIGNED_TX    = 6

CMD_SET_MASTER_SEED  = 11

CMD_ACK_SUCCESS      = 32
CMD_ACK_INVALID      = 33
CMD_ACK_DENIED       = 34

# Command payloads
CMD_SIMPLE_BYTES               = 1
CMD_IDENTIFY_RESP_BYTES        = 17
CMD_GET_PUBLIC_KEY_RESP_BYTES  = 65
CMD_GET_PUBLIC_KEY_BYTES       = 6
CMD_SET_MASTER_SEED_MIN_BYTES  = 16
CMD_SET_MASTER_SEED_MAX_BYTES  = 64

# USB packet size
READ_SIZE   = 64
WRITE_SIZE  = 64

# Control flow
CTRL_START         = 0x80
CTRL_CONT          = 0x88
CTRL_START_STREAM  = 0xC0
CTRL_CONT_STREAM   = 0xC8

# Default command timeout
READ_TIMEOUT_MS  = 10000

class PollyCom:
    """ 
    Class for communication with the Polly hardware Bitcoin wallet.
    """
    
    # USB device handle
    dev = None
    
    def __init__(self, scan = False):
        
        # Tracks time to execute commands on Polly 
        self.t = 0
        
        if True == scan:
            self.__usb_scan()
        
        # Make a connection with Polly
        if None == PollyCom.dev :
            PollyCom.dev = hid.device()
            
            try:
                print ("Connecting to Polly")
                print ("-------------------")
                
                PollyCom.dev.open(POLLY_VID, POLLY_DID)
                
                # TODO flush out any previous command data

                model = self.send_identify()

                print (" Manufacturer : %s" % PollyCom.dev.get_manufacturer_string())
                print (" Product      : %s" % PollyCom.dev.get_product_string())
                print (" Serial No    : %s" % PollyCom.dev.get_serial_number_string())
                print (" Model        : %s" % model)
            
            except IOError:
                print("\n ERROR: Unable to connect")
                raise
            

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
               cmd      == CMD_ACK_SUCCESS, "send_reset : FAILED"
    
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
               cmd      == CMD_IDENTIFY, "send_get_id : FAILED"
    
        return ''.join(map(chr,idstr))
    
    
    def send_set_master_seed(self, seed):
        """
        Sends the set master seed command and waits for an ACK.
        
        seed - byte object containing a seed, maximum of 64 bytes
        """
        
        assert len(seed) >= CMD_SET_MASTER_SEED_MIN_BYTES, "send_set_master_seed : Seed too short"
        assert len(seed) <= CMD_SET_MASTER_SEED_MAX_BYTES, "send_set_master_seed : Seed too long"

        # Send
        data = pack('<HB' + str(len(seed)) + 's', 1 + len(seed), CMD_SET_MASTER_SEED, seed)
        self.send_data(data)
    
        # Receive
        data = self.get_data()
        cmd_bytes, cmd = unpack('<HB', bytes(data))
    
        assert cmd_bytes == CMD_SIMPLE_BYTES and\
               cmd      == CMD_ACK_SUCCESS, "send_set_master_seed : FAILED"
    
        
    def send_get_public_key(self, key_num, master = False):
        """
        Sends the get public key command and waits for the key.
        
        key_num - retrieve the public key for this key number (0 - 0x7FFF_FFFF).
        master  - if set to 1, the master public key is retrieved and key_num is ignored.
        
        Returns a public elliptic curve key in the form (x,y). (0,0) indicates a failure occured.
        """
        
        # Send
        data = pack('<HBBL', CMD_GET_PUBLIC_KEY_BYTES, CMD_GET_PUBLIC_KEY, master, key_num)
        self.send_data(data)
    
        # Receive
        data = self.get_data()
    
        cmd_bytes, cmd, pub_x, pub_y = unpack('HB32s32s', bytes(data))
    
        assert cmd_bytes == CMD_GET_PUBLIC_KEY_RESP_BYTES, "send_get_public_key : FAILED"
    
        if cmd == CMD_GET_PUBLIC_KEY:
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
    
        # Input key ids and their public keys
        for in_key_num, in_key_pubkey in in_key_num_pubkey:
            data = data + pack('<I',   in_key_num)
            data = data + pack('<33s', in_key_pubkey)
    
        # Output address
        data = data + pack('<20sQ', out_addr_160, out_satoshi)
    
        # Change address (optional)
        if change_key_num != None:
            data = data + pack('<IQ', change_key_num, change_satoshi)
    
        # Command id and number of bytes
        data = pack('<HB', len(data) + 1, CMD_SIGN_TX) + data
    
        # Send
        self.send_data(data)
    
        # Receive
        data = self.get_data()
        cmd_bytes, cmd = unpack('<HB', bytes(data))
    
        assert cmd_bytes == CMD_SIMPLE_BYTES and\
               cmd      == CMD_ACK_SUCCESS, "send_sign_tx : FAILED"

    
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
               cmd      == CMD_ACK_SUCCESS, "send_prev_tx : FAILED"

    
    def send_get_signed_tx(self):
        """
        Sends the get signed tx command and waits for a response.
        
        Note: This command must be preceded by send_sign_tx() and then by one or more 
              send_prev_tx() calls to support the key nums used to fund the payment.
        
        Returns a complete signed tx.
        """
    
        # Send
        data = pack('<HB', CMD_SIMPLE_BYTES, CMD_GET_SIGNED_TX)
        self.send_data(data)
    
        # Receive
        data = self.get_data()
        cmd_bytes, cmd = unpack('<HB', bytes(data[0:3]))
    
        assert cmd == CMD_GET_SIGNED_TX, "send_get_signed_tx: invalid response, command incorrect"
        
        # Strip away the command and command bytes, just return the signed tx
        return bytes(data[3:(3 + cmd_bytes)])


    def get_cmd_time(self):
        """
        Returns the time in seconds to execute the last command.
        """
        
        return "{0:.3f}s".format(self.t) 


    def send_data(self, data, stream = False):
        """
        Sends raw data to Polly via USB, typically the command specific functions are used instead of this.
        
        data   - raw byte array to send. Packetization is done by this routine. 
        stream - use stream flow control if True, or normal control if False
        """ 
    
        # Commands to Polly are always send_data/get_data pairs
        # Start the timer here, it will be stopped in get_data 
        self.t = time.clock()
    
        remainBytes = (data[1] << 8) + data[0];
    
        # The command bytes count, plus the control byte
        sendBytes = min(remainBytes + 2, WRITE_SIZE - 1)
        sendPos = 0
        
        if not stream :
            ctrl_start = CTRL_START
            ctrl_cont  = CTRL_CONT
        else:
            ctrl_start = CTRL_START_STREAM
            ctrl_cont  = CTRL_CONT_STREAM
    
        send = [0x00, ctrl_start]
        send += data[sendPos : sendBytes]
        
        PollyCom.dev.write(send)
    
        sendPos = sendBytes
        remainBytes -= sendBytes - 2
    
        # Send out the rest
        while (remainBytes > 0):
            sendBytes = min(remainBytes, WRITE_SIZE - 1)
    
            send = [0x00, ctrl_cont]
            send += data[sendPos : sendPos+sendBytes]
    
            PollyCom.dev.write(send)
    
            sendPos += sendBytes
            remainBytes -= sendBytes

    def get_data(self):
        """
        Gets raw data from Polly via USB, typically the command specific functions are used instead of this.
        
        Returns a single raw byte array with flow control bytes stripped.
        """ 
        
        # Read in the first chunk
        tmp = PollyCom.dev.read(READ_SIZE, READ_TIMEOUT_MS)
        
        assert tmp, "read timeout"
        assert tmp[0] == CTRL_START, "invalid control token, expecting CTRL_START"
    
        # The command bytes count, plus the command bytes count field itself
        remainBytes = (tmp[2] << 8) + tmp[1] + 2 
    
        readBytes = min(remainBytes, READ_SIZE - 1)
        data = tmp[1:readBytes+1]
    
        remainBytes = remainBytes - readBytes
    
        # Read in the rest
        while (remainBytes > 0):
            
            tmp = PollyCom.dev.read(READ_SIZE, READ_TIMEOUT_MS)
            
            assert tmp, "read timeout"
            assert tmp[0] == CTRL_CONT, "invalid control token, expecting CTRL_CONT"
            
            readBytes = min(remainBytes, READ_SIZE - 1)
            data += tmp[1:readBytes+1]
            
            remainBytes -= readBytes
    
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

def main():
    PollyCom() 

if __name__ == '__main__':
    status = main()
    sys.exit(status)