#include "pcapplusplus/RawPacket.h"
#include "pcapplusplus/Packet.h"
#include "pcapplusplus/PcapFileDevice.h"
#include "pcapplusplus/PcapPlusPlusVersion.h"
#include "pcapplusplus/SystemUtils.h"
#include "absl/strings/string_view.h"


#include <string>
#include <vector>
namespace ProtoTest
{ 
    enum class Direction
    {
        CLIENT,
        SERVER,
        UNKNOWN
    };
    class PcapReader
    {
    private:
        PcapReader() = default;

    public:
        PcapReader(PcapReader&) = delete;
        PcapReader(PcapReader&&) = delete;
        PcapReader& operator =(PcapReader&) = delete;
        PcapReader& operator =(PcapReader&&) = delete;
        ~PcapReader() = default;
        bool OpenPcapFile(std::string,const char* filter=nullptr);
        std::string GetNextQuicPacket();
        const std::string& GetSrcIpOfCurrentPacket();
        const std::string& GetDstIpOfCurrentPacket();
        uint16_t GetSrcPortOfCurrentPacket();
        uint16_t GetDstPortOfCurrentPacket();
        Direction GetDirection();
       
        static PcapReader* GetpcapReader()
        {
            static PcapReader* reader = nullptr;
            if (reader == nullptr)
            {
                reader = new PcapReader();
            }
            return reader;
        }
    private:
        pcpp::PcapFileReaderDevice* reader_ = nullptr;
        uint16_t src_port_ = 0;
        uint16_t dst_port_ = 0;
        std::string src_ip_;
        std::string dst_ip_;
        pcpp::RawPacket cur_paket_;
    };
}