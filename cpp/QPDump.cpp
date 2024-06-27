#include <arpa/inet.h>
#include <getopt.h>
#include <unistd.h>

#include <chrono>
#include <cstdio>
#include <iostream>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

using namespace std;

class Verbose {
public:
    Verbose() {
        if (__is_open) {
            auto tm = chrono::system_clock::to_time_t(chrono::system_clock::now());
            cout << "[" << tm << "]";
        }
    }

    ~Verbose() {
        if (__is_open) {
            cout << "\n";
        }
    }

    const Verbose &operator<<(const char *c_str) const {
        if (!__is_open) {
            return *this;
        }

        __print<const char *>(c_str);
        return *this;
    }

    template <typename T>
    const Verbose &operator<<(const T &msg) const {
        if (!__is_open) {
            return *this;
        }

        __print(msg);
        return *this;
    }

    void print(const char *c_str) const {
        if (!__is_open) {
            return;
        }

        __print<const char *>(c_str);
        return;
    }

    template <typename T, typename... O>
    void print(const T &msg, const O &...o) const {
        if (!__is_open) {
            return;
        }

        __print(msg, o...);
        return;
    }

    static void open(bool is_open) { __is_open = is_open; }

private:
    template <typename T>
    void __print(const T &msg) const {
        cout << msg;
    }

    template <typename T, typename... O>
    void __print(const T &msg, const O &...o) const {
        cout << msg;
        __print(o...);
    }

    static inline bool __is_open = false;
};

#define VERBOSE Verbose() << "[" << __FUNCTION__ << "():" << __LINE__ << "]"

struct Utils {
    static constexpr uint32_t IS_LITTLE_ORDER = true;  //
    static constexpr uint32_t BYTE_BITS = 8;           //  8 bits
    static constexpr uint32_t BYTE_POWER = 3;          //  8 bits
    static constexpr uint32_t WORD_BITS = 32;          // 32 bits
    static constexpr uint32_t WORD_BYTES = 4;          //  4 bytes

    static uint32_t to_bytes(uint32_t num_bits) { return num_bits >> Utils::BYTE_POWER; }

    static uint32_t to_bits(uint32_t num_bytes) { return num_bytes << Utils::BYTE_POWER; }

    static uint32_t align_up(uint32_t len, uint32_t align) { return Utils::align_down(len + align - 1, align); }

    static uint32_t align_down(uint32_t len, uint32_t align) { return len & ~(align - 1); }

    static uint32_t round_up_to_the_next_power_of2(uint32_t len) {
        len -= 1;
        len |= len >> 1;
        len |= len >> 2;
        len |= len >> 4;
        len |= len >> 8;
        len |= len >> 16;
        len += 1;
        return len;
    }

    /**
    @Note: b_stop - b_start <= 8
    */
    static uint32_t bits_val_le_8_bits(const uint8_t *byte_str, uint32_t b_start, uint32_t b_len = 8) {
        auto byte_start = Utils::align_down(b_start, Utils::BYTE_BITS);
        auto byte_val = byte_str[byte_start];
        auto mask = (1 << b_len) - 1;
        return (byte_val >> b_start) & mask;
    }

    /**
    @Note: b_stop - b_start <= 32
    */
    static uint32_t bits_val_le_32_bits(const uint8_t *byte_str, uint32_t b_start, uint32_t b_len = 32) {
        auto word_start = Utils::align_down(b_start, Utils::WORD_BITS);
        auto word_value = Utils::word_val(byte_str, word_start);

        auto n_start = b_start - word_start;
        auto mask = (1 << b_len) - 1;
        // VERBOSE << "b_start:" << b_start << " b_len:" << b_len;
        // VERBOSE << "word_value:" << word_value << " n_start:" << n_start << " mask:" << mask << " val:" << ((word_value >> n_start) & mask);
        return (word_value >> n_start) & mask;
    }

    /**
    @Note: not support b_len
    */
    static uint32_t word_val(const uint8_t *byte_str, uint32_t b_start, uint32_t b_len = 32) {
        auto byte_start = b_start >> Utils::BYTE_POWER;
        return ntohl(*(uint32_t *)(byte_str + byte_start));
    }

    static vector<uint32_t> word_list(const uint8_t *byte_str, uint32_t b_start, uint32_t b_len = 32) {
        vector<uint32_t> res;
        auto b_stop = b_start + b_len;
        for (uint32_t i = b_start; i < b_stop; i += Utils::WORD_BITS) {
            res.emplace_back(Utils::word_val(byte_str, i, min(Utils::WORD_BITS, b_stop - i)));
        }
        return res;
    }

    static vector<uint8_t> hex_word_to_bytes(const string &hex_word) {
        vector<uint8_t> res;
        auto ptr = hex_word.c_str();
        auto word = stoi(ptr, nullptr, 16);
        res.emplace_back((word >> 24) & 0xFF);
        res.emplace_back((word >> 16) & 0xFF);
        res.emplace_back((word >> 8) & 0xFF);
        res.emplace_back((word >> 0) & 0xFF);
        return res;
    }

    static uint32_t fw_hex_to_bits(const char *hex_float) {
        uint32_t bytes_val = 0;
        uint32_t bits_val = 0;
        auto hex_pos = hex_float;
        if (*hex_pos != '.') {
            bytes_val = stoi(hex_pos, nullptr, 16);
        }
        auto dec_pos = hex_float;
        for (; *dec_pos != '.'; ++dec_pos) {
        }
        bits_val = stoi(dec_pos + 1, nullptr, 10);
        return (bytes_val << Utils::BYTE_POWER) + bits_val;
    }

    static vector<uint32_t> fw_field_to_bits(const char *offset_str, const char *size_str) {
        return {Utils::fw_hex_to_bits(offset_str), Utils::fw_hex_to_bits(size_str)};
    }

    static vector<string> popen(const string &cmd) {
        constexpr int BUF_LEN = 512;
        char buf[BUF_LEN];
        vector<string> out;

        FILE *fp = ::popen(cmd.c_str(), "r");
        if (fp == NULL) {
            return out;
        }

        char* res = nullptr;
        do {
            res = fgets(buf, BUF_LEN, fp);
            out.emplace_back(buf);
        } while (res != nullptr);
        pclose(fp);
        return out;
    }

    static string strip(const string &s) {
        auto l = s.find_first_not_of(' ');
        auto end_pos = s.back() != '\n' ? s.size() : s.size() - 1;
        auto r = s.find_last_not_of(' ', end_pos);
        return s.substr(l, r);
    }

    static vector<string> split(const string &s, const char sep = ' ') {
        vector<string> res;

        if (s.empty()) {
            return res;
        }

        size_t r = 0;
        size_t l = s.find_first_not_of(sep, r);
        while (l != s.npos) {
            r = s.find_first_of(sep, l);
            res.emplace_back(s.substr(l, r - l));
            l = s.find_first_not_of(sep, r);
        }
        return res;
    }
};

struct SwSt {
    static constexpr uint32_t RC = 0x0;
    static constexpr uint32_t UC = 0x1;
    static constexpr uint32_t UD = 0x2;
    static constexpr uint32_t XRC = 0x3;
    static constexpr uint32_t IBL2 = 0x4;
    static constexpr uint32_t DCI = 0x5;
    static constexpr uint32_t QP0 = 0x7;
    static constexpr uint32_t QP1 = 0x8;
    static constexpr uint32_t Raw_datagram = 0x9;
    static constexpr uint32_t REG_UMR = 0xc;
    static constexpr uint32_t DC_CNON_IPK = 0x10;
    static const inline unordered_map<uint32_t, const char *> __str = {
        {RC, "RC"},
        {UC, "UC"},
        {UD, "UD"},
        {XRC, "XRC"},
        {IBL2, "IBL2"},
        {DCI, "DCI"},
        {QP0, "QP0"},
        {QP1, "QP1"},
        {Raw_datagram, "Raw_datagram"},
        {REG_UMR, "REG_UMR"},
        {DC_CNON_IPK, "DC_CNON_IPK"},
    };

    static const char *enum_str(uint32_t t) {
        try {
            return __str.at(t);
        } catch (out_of_range e) {
            VERBOSE << "invalid value:" << t;
            return "?";
        }
    }
};

struct QpState {
    static constexpr uint32_t RST = 0x0;
    static constexpr uint32_t INIT = 0x1;
    static constexpr uint32_t RTR = 0x2;
    static constexpr uint32_t RTS = 0x3;
    static constexpr uint32_t SQEr = 0x4;
    static constexpr uint32_t SQDRAINED = 0x5;
    static constexpr uint32_t ERR = 0x6;
    static constexpr uint32_t Suspended = 0x9;
    static const inline unordered_map<uint32_t, const char *> __str = {
        {RST, "RST"},   {INIT, "INIT"},           {RTR, "RTR"}, {RTS, "RTS"},
        {SQEr, "SQEr"}, {SQDRAINED, "SQDRAINED"}, {ERR, "ERR"}, {Suspended, "Suspended"},
    };

    
    static const char *enum_str(uint32_t t) {
        try {
            return __str.at(t);
        } catch (out_of_range e) {
            VERBOSE << "invalid value:" << t;
            return "?";
        }
    }
};

struct RoceVer {
    static constexpr uint32_t VERSION_1_0 = 0x0;
    static constexpr uint32_t VERSION_1_5 = 0X1;
    static constexpr uint32_t VERSION_2_0 = 0X2;
    static const inline unordered_map<uint32_t, const char *> __str = {
        {VERSION_1_0, "VERSION_1_0"},
        {VERSION_1_5, "VERSION_1_5"},
        {VERSION_2_0, "VERSION_2_0"},
    };

    
    static const char *enum_str(uint32_t t) {
        try {
            return __str.at(t);
        } catch (out_of_range e) {
            VERBOSE << "invalid value:" << t;
            return "?";
        }
    }
};

struct IpVer {
    static constexpr uint32_t IPV4 = 0x0;
    static constexpr uint32_t IPV6 = 0x1;
    static constexpr uint32_t NON_IP = 0x2;
    static const inline unordered_map<uint32_t, const char *> __str = {
        {IPV4, "IPV4"},
        {IPV6, "IPV6"},
        {NON_IP, "NON_IP"},
    };

    
    static const char *enum_str(uint32_t t) {
        try {
            return __str.at(t);
        } catch (out_of_range e) {
            VERBOSE << "invalid value:" << t;
            return "?";
        }
    }

    static string ipv4_str(uint32_t ip) {
        string buf(16, '?');
        uint32_t pos = snprintf(buf.data(), buf.size(), "%d.%d.%d.%d", ((ip >> 24) & 0xff), ((ip >> 16) & 0xff),
                                ((ip >> 8) & 0xff), ((ip >> 0) & 0xff));
        buf.resize(pos);
        return buf;
    }

    static string ipv6_str(const vector<uint32_t> &ip) {
        string buf(64, '?');
        auto pos = 0;
        for (uint32_t seg : ip) {
            pos +=
                snprintf((buf.data() + pos), (buf.size() - pos), "%04x:%04x:", ((seg >> 16) & 0xffff), ((seg >> 0) & 0xffff));
        }
        buf.resize(pos);
        return buf;
    }
};

class QP {
public:
    static const inline vector<uint32_t> SEG_HEAD = {0x00111530, 0x00000000, 0x00000000, 0x00000000};
    static const inline uint32_t SEG_BYTE_OFFSET = 0x10;
    static const inline uint32_t SEG_BYTE_LEN = SEG_BYTE_OFFSET + 0x38;
    static const inline uint32_t SEG_BITS_OFFSET = Utils::to_bits(SEG_BYTE_OFFSET);
    static const inline uint32_t SEG_BITS_LEN = Utils::to_bits(SEG_BYTE_LEN);
    static const inline vector<uint32_t> PD = Utils::fw_field_to_bits("0x0.0", ".24");
    static const inline vector<uint32_t> SW_ST = Utils::fw_field_to_bits("0x0.24", ".8");
    static const inline vector<uint32_t> SQPN = Utils::fw_field_to_bits("0x4.0", ".24");
    static const inline vector<uint32_t> IP_PROTOCOL = Utils::fw_field_to_bits("0x4.24", ".8");
    static const inline vector<uint32_t> SIP = Utils::fw_field_to_bits("0x8.0", "0x10.0");
    static const inline vector<uint32_t> DIP = Utils::fw_field_to_bits("0x18.0", "0x10.0");
    static const inline vector<uint32_t> UDP_SPORT = Utils::fw_field_to_bits("0x28.0", ".16");
    static const inline vector<uint32_t> UDP_DPORT = Utils::fw_field_to_bits("0x28.16", ".16");
    static const inline vector<uint32_t> RQPN = Utils::fw_field_to_bits("0x2c.0", ".24");
    static const inline vector<uint32_t> DATA_IN_ORDER = Utils::fw_field_to_bits("0x2c.24", ".1");
    static const inline vector<uint32_t> NEXT_SEND_PSN = Utils::fw_field_to_bits("0x30.0", ".24");
    static const inline vector<uint32_t> QP_STATE = Utils::fw_field_to_bits("0x30.24", ".4");
    static const inline vector<uint32_t> IP_VER = Utils::fw_field_to_bits("0x30.28", ".4");
    static const inline vector<uint32_t> ROCE_VER = Utils::fw_field_to_bits("0x34.0", ".8");
    static inline uint32_t __qpi = 0;

    uint32_t qpi = 0;
    uint32_t pd = 0;
    uint32_t sw_st = SwSt::RC;
    uint32_t sqpn = 0;
    uint32_t ip_protocol = 0;
    uint32_t udp_sport = 0;
    uint32_t udp_dport = 0;
    uint32_t rqpn = 0;
    uint32_t data_in_order = 0;
    uint32_t next_send_psn = 0;
    uint32_t qp_state = QpState::RST;
    uint32_t roce_ver = RoceVer::VERSION_1_0;
    uint32_t ip_ver = IpVer::NON_IP;
    vector<uint32_t> sip = {};
    vector<uint32_t> dip = {};
    unordered_map<string, uint32_t *> attr = {
        {"qpi", &qpi},
        {"pd", &pd},
        {"sw_st", &sw_st},
        {"sqpn", &sqpn},
        {"ip_protocol", &ip_protocol},
        {"udp_sport", &udp_sport},
        {"udp_dport", &udp_dport},
        {"rqpn", &rqpn},
        {"data_in_order", &data_in_order},
        {"next_send_psn", &next_send_psn},
        {"qp_state", &qp_state},
        {"roce_ver", &roce_ver},
        {"ip_ver", &ip_ver},
    };

    QP() {}

    void parse(const string &key, uint32_t val) {
        if ("sip" == key) {
            sip.emplace_back(val);
            return;
        }
        if ("dip" == key) {
            dip.emplace_back(val);
            return;
        }
        if ("pd" == key) {
            qpi = ++__qpi;
        }
        __setattr__(Utils::strip(key), val);
    }

    // static bool is_qp_segment(const uint8_t *byte_str, uint32_t byte_start) {
    //     b_start = Utils::to_bits(byte_start);
    //     return Utils::word_list(byte_str, b_start, QP::SEG_BITS_OFFSET) == QP::SEG_HEAD;
    // }

    void parse_bin_seg(const uint8_t *seg_bytes) {
        auto qp_seg = seg_bytes + QP::SEG_BYTE_OFFSET;  // skip header;
        pd = Utils::bits_val_le_32_bits(qp_seg, QP::PD[0], QP::PD[1]);
        sw_st = Utils::bits_val_le_32_bits(qp_seg, QP::SW_ST[0], QP::SW_ST[1]);
        sqpn = Utils::bits_val_le_32_bits(qp_seg, QP::SQPN[0], QP::SQPN[1]);
        ip_protocol = Utils::bits_val_le_32_bits(qp_seg, QP::IP_PROTOCOL[0], QP::IP_PROTOCOL[1]);
        sip = Utils::word_list(qp_seg, QP::SIP[0], QP::SIP[1]);
        dip = Utils::word_list(qp_seg, QP::DIP[0], QP::DIP[1]);
        udp_sport = Utils::bits_val_le_32_bits(qp_seg, QP::UDP_SPORT[0], QP::UDP_SPORT[1]);
        udp_dport = Utils::bits_val_le_32_bits(qp_seg, QP::UDP_DPORT[0], QP::UDP_DPORT[1]);
        rqpn = Utils::bits_val_le_32_bits(qp_seg, QP::RQPN[0], QP::RQPN[1]);
        data_in_order = Utils::bits_val_le_32_bits(qp_seg, QP::DATA_IN_ORDER[0], QP::DATA_IN_ORDER[1]);
        next_send_psn = Utils::bits_val_le_32_bits(qp_seg, QP::NEXT_SEND_PSN[0], QP::NEXT_SEND_PSN[1]);
        qp_state = Utils::bits_val_le_32_bits(qp_seg, QP::QP_STATE[0], QP::QP_STATE[1]);
        ip_ver = Utils::bits_val_le_32_bits(qp_seg, QP::IP_VER[0], QP::IP_VER[1]);
        roce_ver = Utils::bits_val_le_32_bits(qp_seg, QP::ROCE_VER[0], QP::ROCE_VER[1]);
        qpi = ++__qpi;
    }

    string to_string() const {
        auto sw_st_str = SwSt::enum_str(sw_st);
        auto qp_state_str = QpState::enum_str(qp_state);
        auto ip_ver_str = IpVer::enum_str(ip_ver);
        auto sip_str = string();
        auto dip_str = string();
        if (ip_ver == IpVer::IPV4) {
            sip_str = IpVer::ipv4_str(sip[3]);
            dip_str = IpVer::ipv4_str(dip[3]);
        } else if (ip_ver == IpVer::IPV6) {
            sip_str = IpVer::ipv6_str(sip);
            dip_str = IpVer::ipv6_str(dip);
        }
        stringstream ss;
        ss << " qp " << qpi << " lqpn " << sqpn << " rqpn " << rqpn << " type " << sw_st_str << " state " << qp_state_str
           << " sq-psn " << next_send_psn << " pd " << pd << " ip " << ip_ver_str << " src " << sip_str << ":" << udp_sport
           << " dst " << dip_str << ":" << udp_dport;
        return ss.str();
    }

protected:
    void __setattr__(const string &key, uint32_t val) {
        try {
            *attr.at(key) = val;
        } catch (out_of_range e) {
            VERBOSE << "invalid key:" << key << " val:" << val;
        }
    }
};

template <typename T>
ostream &operator<<(ostream &ost, const vector<T> &v) {
    ost << '{';
    for (auto &t : v) {
        ost << t;
    }
    return ost << '}';
}

template <typename K, typename V>
ostream &operator<<(ostream &ost, const unordered_map<K, V> &m) {
    ost << '{';
    for (auto &[k, v] : m) {
        ost << k << ':' << v << ',';
    }
    return ost << '}';
}

ostream &operator<<(ostream &ost, const QP &qp) { return ost << qp.to_string(); }

class QPDump {
public:
    QPDump() {}

    static uint32_t get_vport(const string &iface) {
        const string vport_cmd = string("/usr/sbin/devlink port show ").append(iface);
        uint32_t vport = 0;

        auto lines = Utils::popen(vport_cmd);
        if (lines.empty()) {
            exit(0);
        }

        auto line = lines[0];
        auto pcie_start = line.find_first_of('/') + 1;
        auto vport_start = line.find_first_of('/', pcie_start) + 1;

        try {
            vport = stoi(line.c_str() + vport_start, nullptr, 10) & 0xffff;
        } catch (invalid_argument e) {
            exit(0);
        }

        VERBOSE << vport_cmd;
        VERBOSE << vport;
        return vport;
    }

    static tuple<string, string> get_rdma_dev(const string &iface) {
        const string mst_cmd = "/usr/bin/mst status -v";
        string rdma_dev = "mlx5_0";
        string mst_dev = "/dev/mst/mt41692_pciconf0";

        auto lines = Utils::popen(mst_cmd);
        for (auto &line : lines) {
            auto elems = Utils::split(line);
            if (elems.size() >= 5 and elems[4].find(iface) != string::npos) {
                mst_dev = elems[2];
                rdma_dev = elems[3];
                break;
            }
        }

        VERBOSE << mst_cmd;
        VERBOSE << rdma_dev;
        return {mst_dev, rdma_dev};
    }

    void dump_qps_with_adb_parser(int vport, const string &adb, const string &mst_dev, const string &rdma_dev) {
        cerr << "not support adb yet";
        return;
    }
    //     dump_qps = dump_qps
    //     dump_cmd = f"resourcedump dump -d /dev/mst/mt41692_pciconf0 -s QP_INFO -i1 {vport} -p -a {adb} -m {dev}"
    //     VERBOSE.print(f"{dump_cmd}")
    //     with os.Utils::popen(dump_cmd) as f:
    //         lines = f.readlines()
    //         qp = QP()
    //         for line in lines:
    //             line = line.Utils::strip()
    //             if not line:
    //                 continue
    //             if "qp_info (0x1530)" in line:
    //                 qp = QP()
    //                 continue
    //             if "--------" in line:
    //                 dump_qps.setdefault(qp.qpi, qp) if qp.qpi else None
    //                 continue
    //             if '=' in line:
    //                 eq_pos = line.find('=')
    //                 key = line[:eq_pos - 1].Utils::strip()
    //                 val_str = line[eq_pos + 2:].Utils::strip("() ")
    //                 if '=' in val_str:
    //                     val_str = val_str[val_str.find('=') + 2:]
    //                 val = uint32_t(val_str, 16)
    //                 qp.parse(key, val)
    //                 # VERBOSE.print(key, val, val_str, line)

    void dump_test() {
        vector<string> lines{
            "0x00121530 0x00000000 0x00000001 0x00000000",
            "0x00000016 0x11000190 0x00000000 0x00000000",
            "0x00000000 0x0D141401 0x00000000 0x00000000",
            "0x00000000 0x0D141401 0x12B7F299 0x01000191",
            "0x02000000 0x00000002",
        };

        vector<uint8_t> seg_bytes;
        for (auto line : lines) {
            auto qp_dump = QPDump();
            // VERBOSE << line;
            for (auto hex_word : Utils::split(line)) {
                // auto v = VERBOSE << hex_word;
                for (auto b : Utils::hex_word_to_bytes(hex_word)) {
                    // v << hex << (int)b << dec;
                    seg_bytes.emplace_back(b);
                }
            }
        }

        auto qp = QP{};
        qp.parse_bin_seg(&seg_bytes[0]);
        VERBOSE << qp;

        exit(0);
    }

    void dump_qps_with_builtin_parser(int vport, const string &mst_dev, const string &rdma_dev) {
        string dump_cmd(256, '?');
        auto len = snprintf(dump_cmd.data(), dump_cmd.size(), "resourcedump dump -d %s -s QP_INFO -i1 %d -m %s",
                            mst_dev.c_str(), vport, rdma_dev.c_str());

        dump_cmd.resize(len);
        VERBOSE << dump_cmd;

        auto lines = Utils::popen(dump_cmd);
        vector<uint8_t> seg_bytes;
        bool is_seg = false;
        for (auto &line : lines) {
            if (line.find("Segment Type: 0x1530") != line.npos) {
                is_seg = true;
                continue;
            }
            if (line.find("Segment") != line.npos) {
                continue;
            }
            if (line.find("-------") != line.npos) {
                // VERBOSE << seg_bytes;
                // VERBOSE << Utils::word_list(seg_bytes, 0, Utils::to_bits(len(seg_bytes)));
                if (seg_bytes.size() == QP::SEG_BYTE_LEN) {
                    dump_qps.emplace_back();
                    dump_qps.back().parse_bin_seg(&seg_bytes[0]);
                    // VERBOSE << dump_qps.back().to_string();
                }
                is_seg = false;
                seg_bytes.clear();
                continue;
            }
            line = Utils::strip(line);
            if (!line.empty() and is_seg) {
                for (auto hex_word : Utils::split(line)) {
                    for (auto b : Utils::hex_word_to_bytes(hex_word)) {
                        seg_bytes.emplace_back(b);
                    }
                }
            }
        }
    }

    void show_qps() const {
        for (auto &qp : dump_qps) {
            if (qp.qpi != 0) {
                cout << qp << "\n";
            }
        }
    }

private:
    vector<QP> dump_qps;
};

int main(int argc, char *argv[]) {
    string adb = "";
    string iface = "";
    string rdma_dev = "mlx5_0";
    string mst_dev = "mlx5_0";
    int vport = 0;

    static struct option long_options[] = {
        {.name = "vport", .has_arg = 1, .flag = 0, .val = 'p'},
        {.name = "interface", .has_arg = 1, .flag = 0, .val = 'i'},
        {.name = "device", .has_arg = 1, .flag = 0, .val = 'd'},
        {.name = "adb", .has_arg = 1, .flag = 0, .val = 'a'},
        {.name = "verbose", .has_arg = 0, .flag = 0, .val = 'v'},
        {}};


	while (1) {
        auto c = getopt_long(argc, argv, "p:i:d:a:v", long_options, NULL);
        if (c == -1) break;

        switch (c) {
            case 'p':
                vport = stoi(optarg);
                break;
            case 'i':
                iface = string(optarg);
                break;
            case 'd':
                rdma_dev = string(optarg);
                break;
            case 'a':
                adb = string(optarg);
                break;
            case 'v':
                Verbose::open(true);
                break;
            default:
                return -1;
        }
    }

    // QPDump{}.dump_test();

    if (!iface.empty()) {
        vport = QPDump::get_vport(iface);
        tie(mst_dev, rdma_dev) = QPDump::get_rdma_dev(iface);
    } else {
        mst_dev = rdma_dev == "mlx5_0" ? "/dev/mst/mt41692_pciconf0" : "/dev/mst/mt41692_pciconf0.1";
    }
    auto t1 = chrono::system_clock::to_time_t(chrono::system_clock::now());
    auto qp_dump = QPDump();
    if (!adb.empty())
        qp_dump.dump_qps_with_adb_parser(vport, adb, mst_dev, rdma_dev);
    else
        qp_dump.dump_qps_with_builtin_parser(vport, mst_dev, rdma_dev);
    auto t2 = chrono::system_clock::to_time_t(chrono::system_clock::now());
    VERBOSE << "resourcedump cost " << (t2 - t1);
    qp_dump.show_qps();
    auto t3 = chrono::system_clock::to_time_t(chrono::system_clock::now());
    VERBOSE << "total cost " << (t3 - t1);
    return 0;
}
