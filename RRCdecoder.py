"""Convert the HEX string in text files to LTE Signaling
- Wireshark required
"""

import os
from subprocess import run


def str2hex(digitStr):
    """manipulate from '12321323222321312A' to '000000 12 32 13 23\n000008 22 23 21 31 2A'
    """
    # remove space
    digitStr = str(digitStr).strip().replace(' ', '')
    if all([x in '0123456789ABCDEF' for x in digitStr]):
        # newStr = [digitStr[i * 2:i * 2 + 2] for i in range(int(len(digitStr) / 2))]
        # for i in range(int(len(newStr) / 8) + 1):
        #     # last = min(8 * i + 8, len(newStr))
        #     hexStr = '{:06x}'.format(i * 8) + ' ' + ' '.join(newStr[i * 8:i * 8 + 8]) + '\n'
        #     yield hexStr
        hex = []
        for i in range(len(digitStr)//8+1):
            start = i*8
            end = min(len(digitStr)-1, start+8)
            hex.append('{:06x}'.format(start))
            [hex.append(digitStr[x:x+2]) for x in range(start, end, 2)]
            yield ' '.join(hex)
            hex = []
    else:
        print('Invalid HEX string input\n{}'.format(digitStr))


def text2pcap(tmp, tmp_pcap, logcode="147"):
    cmd = []
    cmd.append(os.path.join(wireshark_dir, 'text2pcap.exe'))
    cmd.append("-q")
    cmd.append("-l")
    cmd.append(logcode)
    cmd.append(tmp)
    cmd.append(tmp_pcap)
    run(cmd)


def pcap2parser(tmp_pcap, stdoutfile):
    # call pcap parser
    cmd = []
    cmd.append(os.path.join(wireshark_dir, 'tshark.exe'))
    cmd.append("-o")
    cmd.append('uat:user_dlts:"User 0 (DLT=147)","lte-rrc.ul.dcch","0","","0",""')
    cmd.append("-r")
    cmd.append(tmp_pcap)
    cmd.append("-V")
    run(cmd, stdout=stdoutfile)


if __name__ == '__main__':
    hexfile = 'hexfile.txt'
    tmp = 'test2'
    tmp_pcap = 'test.pcap'
    tmp_txt = 'results.txt'
    wireshark_dir = r'C:\Program Files\Wireshark'
    cnt = 0
    num_lines = sum(1 for line in open(hexfile))
    with open(hexfile, 'rt') as strfile:
        with open(tmp_txt, 'wt') as stdoutfile:
            for digitStr in strfile:
                if digitStr.strip().startswith('#'):
                    continue
                with open(tmp, 'wt') as tmpfile:
                    tmpfile.writelines(str2hex(digitStr))
                # call txt2pcap
                text2pcap(tmp, tmp_pcap)
                pcap2parser(tmp_pcap, stdoutfile)
                print('{}/{} Line decoded...'.format(cnt+1, num_lines))
                cnt += 1
                #os.remove(tmp)
                #os.remove(tmp_pcap)
