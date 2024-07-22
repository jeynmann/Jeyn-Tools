#!/usr/bin/env python3

# sw_st  port      qpi    roce     sip  dip
# 0+16b 16b+16b 4B+24b 424b+3b    8+16 24+16
'''
ADB:

<node name="qp_info" size="0x38.0" segment_id="0x1530" >
  <field name="pd"            offset="0x0.0"     size=".24"    descr="Protection Domain\;Reserved when st==REG_UMR."/>
  <field name="sw_st"         offset="0x0.24"    size=".8"     descr="Transport service type" enum="RC=0x0,UC=0x1,UD=0x2,XRC=0x3,IBL2=0x4,DCI=0x5,QP0=0x7,QP1=0x8,Raw_datagram=0x9,REG_UMR=0xc,DC_CNAK=0x10"/>
  <field name="sqpn"          offset="0x4.0"     size=".24"    descr=""/>
  <field name="ip_protocol"   offset="0x4.24"    size=".8"     descr="IPv4 protocol/IPv6 Next Header (Last in case of extensions exist)" />
  <field name="sip"           offset="0x8.0"     size="0x10.0" descr="" union_selector="$(parent).ip_ver" subnode="ipv4_or_ipv6_layout"/>
  <field name="dip"           offset="0x18.0"    size="0x10.0" descr="" union_selector="$(parent).ip_ver" subnode="ipv4_or_ipv6_layout"/>
  <field name="udp_sport"     offset="0x28.0"    size=".16"    descr="For R-RoCE v2.0: UDP source port which must belong to the ;range: [QUERY_HCA_CAP. r_roce_udp_src_port_range_min-;QUERY_HCA_CAP. r_roce_udp_src_port_range_max];For RoCE v1.0 and v1.5 this field is reserved."/>
  <field name="udp_dport"     offset="0x28.16"   size=".16"    descr="" />
  <field name="rqpn"          offset="0x2c.0"    size=".24"    descr="For connected transport services, indicates the Remote QP number."/>
  <field name="data_in_order" offset="0x2c.24"   size=".1"     descr="When set, the writing of data into local memory is guaranteed to be in-order for packets belonging to the same WQE"/>
  <field name="next_send_psn" offset="0x30.0"    size=".24"    descr="Next PSN to be sent"/>
  <field name="qp_state"      offset="0x30.24"   size=".4"     descr="QP State \;0x0: RST\;0x1: INIT\;0x2: RTR\;0x3: RTS\;0x4: SQEr\;0x5: SQDRAINED - Send Queue Drained\;0x6: ERR\;0x9: Suspended" enum="RST=0x0,INIT=0x1,RTR=0x2,RTS=0x3,SQEr=0x4,SQDRAINED=0x5,ERR=0x6,Suspended=0x9"/>
  <field name="ip_ver"        offset="0x30.28"   size=".4"     descr="0x0: Ipv4\;0x1: Ipv6\;For RoCE version 1, i.e. roce_ver=0, this field is reserved." enum="Ipv4=0x0,Ipv6=0x1" />
  <field name="roce_ver"      offset="0x34.0"    size=".8"     descr="0x0: version_1_0 - RoCE version 1.0\;0x1: version_1_5 - RoCE version 1.5\;0x2: version_2_0 - RoCE version 2.0" enum="version_1_0=0x0,version_1_5=0x1,version_2_0=0x2" />
</node>

Sample:
-------------------------------------------
Segment Type: 0x1530
Segment Size: 72 Bytes
Segment Data:
         4          8         12         16
0x00121530 0x00000000 0x00000001 0x00000000
        20         24         28         32
0x00000016 0x11000190 0x00000000 0x00000000
        36         40         44         48
0x00000000 0x0D141401 0x00000000 0x00000000
        52         56         60         64
0x00000000 0x0D141401 0x12B7F299 0x01000191
        68         72
0x02000000 0x00000002
-------------------------------------------
                    Segment - qp_connection_info (0x1530) ; index1 = 0xffff, index2 = 0x0
sw_st = 0x0
rlid_or_udp_sport = 0xffc0
qpi = 0x5a
roce_ver = (ROCE_VER_IPV4_UDP = 0x3)
(UNION)sip.ipv4_layout.ipv4 = 0x101e602
(UNION)dip.ipv4_layout.ipv4 = 0x101e602
--------------------------------------------------------------------------------
'''

import sys
import argparse
import time
import os

class Verbose:
    __is_open = False

    @staticmethod
    def debug(is_open):
        Verbose.__is_open = is_open

    @staticmethod
    def print(*msg):
        if Verbose.__is_open:
            print(f"[{time.time()}] <debug> {msg}")

class Utils:
    BYTE_ORDER = sys.byteorder
    IS_LITTLE_ORDER = BYTE_ORDER == "little"
    BYTE_BITS = 8  # 8 bits
    BYTE_POWER = 3  # 8 bits
    WORD_BITS = 32 # 32 bits
    WORD_BYTES = 4 # 4 bytes

    @staticmethod
    def to_bytes(num_bits):
        return num_bits >> Utils.BYTE_POWER

    @staticmethod
    def to_bits(num_bytes):
        return num_bytes << Utils.BYTE_POWER

    @staticmethod
    def align_up(len, align):
        return Utils.align_down(len + align - 1, align)

    @staticmethod
    def align_down(len, align):
        return len & ~(align - 1)

    @staticmethod
    def round_up_to_the_next_power_of2(len):
        len -= 1
        len |= len >> 1
        len |= len >> 2
        len |= len >> 4
        len |= len >> 8
        len |= len >> 16
        len += 1
        return len

    '''
    @Note: b_stop - b_start <= 8
    '''
    @staticmethod
    def bits_val_le_8_bits(byte_str, b_start, b_len=8):
        byte_start = Utils.align_down(b_start, Utils.BYTE_BITS)
        byte_val = byte_str[byte_start]
        mask = (1 << b_len) - 1
        return (byte_val >> b_start) & mask

    '''
    @Note: b_stop - b_start <= 32
    '''
    @staticmethod
    def bits_val_le_32_bits(byte_str, b_start, b_len=32):
        word_start = Utils.align_down(b_start, Utils.WORD_BITS)
        word_val = Utils.word_val(byte_str, word_start)

        # b_stop = b_start + b_len
        # if Utils.IS_LITTLE_ORDER:
        #     n_start = b_start - word_start
        # else:
        #     n_start = word_start + Utils.WORD_BITS - b_stop
        n_start = b_start - word_start
        mask = (1 << b_len) - 1
        return (word_val >> n_start) & mask

    @staticmethod
    def word_val(byte_str, b_start, b_len=32):
        byte_start = b_start >> Utils.BYTE_POWER
        byte_stop = (b_start + b_len) >> Utils.BYTE_POWER
        return int.from_bytes(byte_str[byte_start:byte_stop], "big")

    @staticmethod
    def word_list(byte_str, b_start, b_len=32):
        b_stop = b_start + b_len
        word_range = range(b_start, b_stop, Utils.WORD_BITS)
        return [Utils.word_val(byte_str, i, min(Utils.WORD_BITS, b_stop - i))
                for i in word_range]

    @staticmethod
    def hex_word_to_bytes(hex_word):
        try:
            if hex_word[0:2] in '0x':
                hex_word = hex_word[2:]
            return bytes.fromhex(hex_word)
        except ValueError as e:
            Verbose.print(f"parse {hex_word}: {e}")
            return bytes.fromhex('FFFFFFFF')

    @staticmethod
    def fw_hex_to_bits(hex_float):
        bytes, bits = hex_float.split('.')
        bytes_val = int(bytes, 16) if bytes else 0
        bits_val = int(bits)
        return (bytes_val << Utils.BYTE_POWER) + bits_val

    @staticmethod
    def fw_field_to_bits(offset_str, size_str):
        return (Utils.fw_hex_to_bits(offset_str), Utils.fw_hex_to_bits(size_str))


class SwSt:
    RC              = 0x0
    UC              = 0x1
    UD              = 0x2
    XRC             = 0x3
    IBL2            = 0x4
    DCI             = 0x5
    QP0             = 0x7
    QP1             = 0x8
    Raw_datagram    = 0x9
    REG_UMR         = 0xc
    DC_CNON_IPK     = 0x10
    __str = {
        RC : "RC",
        UC : "UC",
        UD : "UD",
        XRC : "XRC",
        IBL2 : "IBL2",
        DCI : "DCI",
        QP0 : "QP0",
        QP1 : "QP1",
        Raw_datagram : "Raw_datagram",
        REG_UMR : "REG_UMR",
        DC_CNON_IPK : "DC_CNON_IPK",
    }

    @staticmethod
    def enum_str(t):
        try:
            return SwSt.__str[t]
        except IndexError as e:
            Verbose.print(f"sw_st invalid {t}")
            return SwSt.__str[0]


class QpState:
    RST         = 0x0
    INIT        = 0x1
    RTR         = 0x2
    RTS         = 0x3
    SQEr        = 0x4
    SQDRAINED   = 0x5
    ERR         = 0x6
    Suspended   = 0x9
    __str = {
        RST : "RST",
        INIT : "INIT",
        RTR : "RTR",
        RTS : "RTS",
        SQEr : "SQEr",
        SQDRAINED : "SQDRAINED",
        ERR : "ERR",
        Suspended : "Suspended",
    }

    @staticmethod
    def enum_str(t):
        try:
            return QpState.__str[t]
        except IndexError as e:
            Verbose.print(f"qp_state invalid {t}")
            return QpState.__str[0]


class RoceVer:
    VERSION_1_0 = 0x0
    VERSION_1_5 = 0X1
    VERSION_2_0 = 0X2
    __str = {
        VERSION_1_0 : "VERSION_1_0",
        VERSION_1_5 : "VERSION_1_5",
        VERSION_2_0 : "VERSION_2_0",
    }

    @staticmethod
    def enum_str(t):
        try:
            return RoceVer.__str[t]
        except IndexError as e:
            Verbose.print(f"roce_ver invalid {t}")
            return RoceVer.__str[0]


class IpVer:
    IPV4    = 0x0
    IPV6    = 0x1
    NON_IP  = 0x2
    __str = {
        IPV4 : "IPV4",
        IPV6 : "IPV6",
        NON_IP : "NON_IP",
    }

    @staticmethod
    def enum_str(t):
        return IpVer.__str[t]

    @staticmethod
    def ipv4_str(ip):
        return f"{((ip >> 24) & 0xff)}.{((ip >> 16) & 0xff)}.{((ip >> 8) & 0xff)}.{((ip >> 0) & 0xff)}"

    @staticmethod
    def ipv6_str(ip):
        segs = [f"{ip[i]:08x}" for i in range(0, 4)]
        return f"{segs[0][0:4]}:{segs[0][4:]}:{segs[1][0:4]}:{segs[1][4:]}:{segs[2][0:4]}:{segs[2][4:]}:{segs[3][0:4]}:{segs[3][4:]}"

class QP:
    SEG_HEAD            = [0x00111530, 0x00000000, 0x00000000, 0x00000000]
    SEG_BYTE_OFFSET     = 0x10
    SEG_BYTE_LEN        = SEG_BYTE_OFFSET + 0x38
    SEG_BITS_OFFSET     = Utils.to_bits(SEG_BYTE_OFFSET)
    SEG_BITS_LEN        = Utils.to_bits(SEG_BYTE_LEN)
    PD                  = Utils.fw_field_to_bits("0x0.0",   ".24")
    SW_ST               = Utils.fw_field_to_bits("0x0.24",  ".8")
    SQPN                = Utils.fw_field_to_bits("0x4.0",   ".24")
    IP_PROTOCOL         = Utils.fw_field_to_bits("0x4.24",  ".8")
    SIP                 = Utils.fw_field_to_bits("0x8.0",   "0x10.0")
    DIP                 = Utils.fw_field_to_bits("0x18.0",  "0x10.0")
    UDP_SPORT           = Utils.fw_field_to_bits("0x28.0",  ".16")
    UDP_DPORT           = Utils.fw_field_to_bits("0x28.16", ".16")
    RQPN                = Utils.fw_field_to_bits("0x2c.0",  ".24")
    DATA_IN_ORDER       = Utils.fw_field_to_bits("0x2c.24", ".1")
    NEXT_SEND_PSN       = Utils.fw_field_to_bits("0x30.0",  ".24")
    QP_STATE            = Utils.fw_field_to_bits("0x30.24", ".4")
    IP_VER              = Utils.fw_field_to_bits("0x30.28", ".4")
    ROCE_VER            = Utils.fw_field_to_bits("0x34.0",  ".8")
    __qpi               = 0
    # RLID_OR_UDP_SPORT   = (3, 4)

    def __init__(self) -> None:
        self.qpi = 0
        self.pd = 0
        self.sw_st = SwSt.RC
        self.sqpn = 0
        self.ip_protocol = 0
        self.sip = []
        self.dip = []
        self.udp_sport = 0
        self.udp_dport = 0
        self.rqpn = 0
        self.data_in_order = 0
        self.next_send_psn = 0
        self.qp_state = QpState.RST
        self.roce_ver = RoceVer.VERSION_1_0
        self.ip_ver = IpVer.NON_IP

    def parse(self, key, val):
        if "sip" in key:
            self.sip.append(val)
            return
        if "dip" in key:
            self.dip.append(val)
            return
        if "pd" in key:
            QP.__qpi += 1
            self.qpi = QP.__qpi
        self.__setattr__(key.strip(), val)

    @staticmethod
    def is_qp_segment(byte_str, byte_start):
        b_start = Utils.to_bits(byte_start)
        return Utils.word_list(byte_str, b_start, QP.SEG_BITS_OFFSET) == QP.SEG_HEAD

    def parse_bin_seg(self, seg_bytes):
        QP.__qpi += 1
        self.qpi = QP.__qpi
        qp_seg = seg_bytes[QP.SEG_BYTE_OFFSET:] # skip header
        self.pd = Utils.bits_val_le_32_bits(qp_seg, QP.PD[0], QP.PD[1])
        self.sw_st = Utils.bits_val_le_32_bits(qp_seg, QP.SW_ST[0], QP.SW_ST[1])
        self.sqpn = Utils.bits_val_le_32_bits(qp_seg, QP.SQPN[0], QP.SQPN[1])
        self.ip_protocol = Utils.bits_val_le_32_bits(qp_seg, QP.IP_PROTOCOL[0], QP.IP_PROTOCOL[1])
        self.sip = Utils.word_list(qp_seg, QP.SIP[0], QP.SIP[1])
        self.dip = Utils.word_list(qp_seg, QP.DIP[0], QP.DIP[1])
        self.udp_sport = Utils.bits_val_le_32_bits(qp_seg, QP.UDP_SPORT[0], QP.UDP_SPORT[1])
        self.udp_dport = Utils.bits_val_le_32_bits(qp_seg, QP.UDP_DPORT[0], QP.UDP_DPORT[1])
        self.rqpn = Utils.bits_val_le_32_bits(qp_seg, QP.RQPN[0], QP.RQPN[1])
        self.data_in_order = Utils.bits_val_le_32_bits(qp_seg, QP.DATA_IN_ORDER[0], QP.DATA_IN_ORDER[1])
        self.next_send_psn = Utils.bits_val_le_32_bits(qp_seg, QP.NEXT_SEND_PSN[0], QP.NEXT_SEND_PSN[1])
        self.qp_state = Utils.bits_val_le_32_bits(qp_seg, QP.QP_STATE[0], QP.QP_STATE[1])
        self.ip_ver = Utils.bits_val_le_32_bits(qp_seg, QP.IP_VER[0], QP.IP_VER[1])
        self.roce_ver = Utils.bits_val_le_32_bits(qp_seg, QP.ROCE_VER[0], QP.ROCE_VER[1])

    def __str__(self) -> str:
        sw_st_str = SwSt.enum_str(self.sw_st)
        qp_state_str = QpState.enum_str(self.qp_state)
        ip_ver_str = IpVer.enum_str(self.ip_ver)
        sip_str = ""
        dip_str = ""
        if self.ip_ver == IpVer.IPV4:
            sip_str = IpVer.ipv4_str(self.sip[-1])
            dip_str = IpVer.ipv4_str(self.dip[-1])
        elif self.ip_ver == IpVer.IPV6:
            sip_str = IpVer.ipv6_str(self.sip)
            dip_str = IpVer.ipv6_str(self.dip)
        return f"qp {self.qpi} lqpn {self.sqpn} rqpn {self.rqpn} type {sw_st_str} state {qp_state_str} sq-psn {self.next_send_psn} pd {self.pd} ip {ip_ver_str} sip {sip_str} dip {dip_str} sport {self.udp_sport} dport {self.udp_dport} "


class QPDump:
    def __init__(self) -> None:
        self.dump_qps = {}

    @staticmethod
    def get_vport(iface):
        vport = 0
        vport_cmd = f"/usr/sbin/devlink port show {iface}"
        Verbose.print(f"{vport_cmd}")
        # e.g. pci/0000:03:00.0/196609
        with os.popen(vport_cmd) as f:
            lines = f.readlines()
            line = lines[0]
            pcie_start = line.find('/') + 1
            vport_start = line.find('/', pcie_start) + 1
            vport_end = line.find(':', vport_start)
            vport = int(line[vport_start:vport_end]) & 0xffff
            # Verbose.print(f"vport {vport}")
        return vport

    @staticmethod
    def get_rdma_dev(iface):
        mst_dev = "/dev/mst/mt41692_pciconf0"
        rdma_dev = "mlx5_0"
        mst_cmd = f"/usr/bin/mst status -v"
        Verbose.print(f"{mst_cmd}")
        with os.popen(mst_cmd) as f:
            for line in f.readlines():
                elems = line.split()
                if len(elems) >= 5 and iface in elems[4]:
                    mst_dev = elems[2]
                    rdma_dev = elems[3]
                    break
            # Verbose.print(f"rdma_dev {rdma_dev}")
        return mst_dev,rdma_dev

    # def dump_qps_with_dump_file(self, vport, mst_dev, rdma_dev):
    #     qp_dump_file = f"/dev/shm/qp_dump_{os.getpid()}"
    #     dump_cmd = f"resourcedump dump -d {mst_dev} -s QP_INFO -i1 {vport} -b {qp_dump_file}"
    #     Verbose.print(f"{dump_cmd}")
    #     with os.popen(dump_cmd) as f:
    #         for line in f.readlines():
    #             Verbose.print(line)
    #     Verbose.print(f"parse from {qp_dump_file}")
    #     with open(qp_dump_file, "rb") as f:
    #         byte_str = tuple(b"".join(f.readlines()))
    #         start_pos = 0
    #         stop_pos = len(byte_str)
    #         while (start_pos + QP.SEG_BYTE_LEN <= stop_pos) and not QP.is_qp_segment(byte_str, start_pos):
    #             start_pos += 4
    #         for pos in range(start_pos, stop_pos, QP.SEG_BYTE_LEN):
    #             if pos + QP.SEG_BYTE_LEN > stop_pos:
    #                 break
    #             seg_bytes = byte_str[pos : pos + QP.SEG_BYTE_LEN]
    #             qp = QP()
    #             qp.parse_bin_seg(seg_bytes)
    #             # Verbose.print([f"{i:08x}" for i in Utils.word_list(seg_bytes, 0, QP.SEG_BITS_LEN)])
    #             if qp.qpi:
    #                 dump_qps.setdefault(qp.qpi, qp)
    #     Verbose.print(f"rm {qp_dump_file}")
    #     # os.remove(qp_dump_file)
    #     os.system(f"rm {qp_dump_file}")

    def dump_qps_with_adb_parser(self, vport, adb, mst_dev, rdma_dev):
        dump_qps = self.dump_qps
        dump_cmd = f"resourcedump dump -d {mst_dev} -s QP_INFO -i1 {vport} -p -a {adb} -m {rdma_dev}"
        Verbose.print(f"{dump_cmd}")
        with os.popen(dump_cmd) as f:
            lines = f.readlines()
            qp = None
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                if "qp_info (0x1530)" in line:
                    qp = QP()
                    continue
                if not qp:
                    continue
                if "--------" in line:
                    if qp.qpi:
                        dump_qps.setdefault(qp.qpi, qp)
                    qp = None
                    continue
                if '=' in line:
                    eq_pos = line.find('=')
                    key = line[:eq_pos - 1].strip()
                    val_str = line[eq_pos + 2:].strip("() ")
                    if '=' in val_str:
                        val_str = val_str[val_str.find('=') + 2:]
                    val = int(val_str, 16)
                    qp.parse(key, val)
                    # Verbose.print(key, val, val_str, line)

    def dump_qps_with_builtin_parser(self, vport, mst_dev, rdma_dev):
        dump_qps = self.dump_qps
        dump_cmd = f"resourcedump dump -d {mst_dev} -s QP_INFO -i1 {vport} -m {rdma_dev}"
        Verbose.print(f"{dump_cmd}")
        with os.popen(dump_cmd) as f:
            lines = f.readlines()
            is_seg = False
            seg_bytes = bytearray()
            for line in lines:
                if "Segment Type: 0x1530" in line:
                    is_seg = True
                    continue
                if "Segment" in line:
                    continue
                if "-------" in line:
                    # Verbose.print(f"{seg_bytes}")
                    # Verbose.print([f"{i:08x}" for i in Utils.word_list(seg_bytes, 0, Utils.to_bits(len(seg_bytes)))])
                    if len(seg_bytes) == QP.SEG_BYTE_LEN:
                        qp = QP()
                        qp.parse_bin_seg(seg_bytes)
                        dump_qps.setdefault(qp.qpi, qp)
                        # Verbose.print(f"{qp}")
                    is_seg = False
                    seg_bytes = bytearray()
                    continue
                line = line.strip()
                if line and is_seg:
                    for hex_word in line.split(): #0x12345678
                        seg_bytes.extend(Utils.hex_word_to_bytes(hex_word))

    def show_qps(self):
        for qp in self.dump_qps.values():
            if qp.qpi:
                print(qp)


if __name__ == "__main__":
    t1 = time.time()
    parser = argparse.ArgumentParser(description='resourcedump output parser')
    parser.add_argument('-p', '--vport', type=str, default='0',
                        help=argparse.SUPPRESS)
    parser.add_argument('-i', '--interface', type=str, default='',
                        help='linux interface name. e.g. pf0hpf')
    parser.add_argument('-d', '--device', type=str, default='mlx5_0',
                        help=argparse.SUPPRESS)
    parser.add_argument('-a', '--adb', type=str, default='',
                        help=argparse.SUPPRESS)
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='print verbose log.')
    args = parser.parse_args()

    Verbose.debug(args.verbose)
    # Verbose.print(f"init cost {time.time() -t1}")
    iface = args.interface
    if iface:
        vport = QPDump.get_vport(iface)
        mst_dev,rdma_dev = QPDump.get_rdma_dev(iface)
    else:
        rdma_dev = args.device
        if "mlx5_0" in rdma_dev:
            mst_dev = "/dev/mst/mt41692_pciconf0"
        else:
            mst_dev = "/dev/mst/mt41692_pciconf0.1"
        vport = int(args.vport) & 0xffff
    adb = args.adb
    # Verbose.print(f"parse cost {time.time() -t1}")


    qp_dump = QPDump()
    if adb:
        qp_dump.dump_qps_with_adb_parser(vport, adb, mst_dev, rdma_dev)
    else:
        qp_dump.dump_qps_with_builtin_parser(vport, mst_dev, rdma_dev)
    Verbose.print(f"resourcedump cost {time.time() -t1}")
    qp_dump.show_qps()
    Verbose.print(f"total cost {time.time() -t1}")
