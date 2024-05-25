#include "pcap_reader.h"

#include <iostream>
#include "pcapplusplus/UdpLayer.h"
#include "pcapplusplus/IPLayer.h"
#include <fstream>
#include "config.h"
using namespace ProtoTest;

bool PcapReader::OpenPcapFile(std::string file_path, const char* filter)
{
    pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader(file_path);
    if (!reader->open())
    {
        std::cout << "can't open the file path (" << file_path << ")" << std::endl;
        return false;
    }
    if (dynamic_cast<pcpp::PcapFileReaderDevice*>(reader) != nullptr)
	{
		pcpp::PcapFileReaderDevice* pcapReader = dynamic_cast<pcpp::PcapFileReaderDevice*>(reader);
        this->reader_ = pcapReader;
        if(!pcapReader->setFilter(filter))
        {
            std::cout << "can't set filter (" << filter << ")" << std::endl;
            return false;
        }
        
        return true;
	}
    
    return false;
}


std::string PcapReader::GetNextQuicPacket()
{
    pcpp::RawPacket rawPacket;

    if (!this->reader_)
    {
        return std::string();
    }
    if (!this->reader_->getNextPacket(rawPacket))
    {
        return std::string();
    }
    pcpp::Packet parsedPacket(&rawPacket);
    
    pcpp::UdpLayer* udp_layer = parsedPacket.getLayerOfType<pcpp::UdpLayer>();
    pcpp::IPLayer* ip_layer = parsedPacket.getLayerOfType<pcpp::IPLayer>();
    if (!udp_layer || !ip_layer)
    {
        return std::string();
    }
    
    this->src_ip_ = ip_layer->getSrcIPAddress().getIPv4().toString();
    this->dst_ip_ = ip_layer->getDstIPAddress().getIPv4().toString();
    this->dst_port_ = udp_layer->getDstPort();
    this->src_port_ = udp_layer->getSrcPort();

    auto out_data = std::string(reinterpret_cast<const char*>(udp_layer->getDataPtr(udp_layer->getHeaderLen())),
        udp_layer->getDataLen() - udp_layer->getHeaderLen());
    cur_paket_ = rawPacket;
    
    return out_data;
}

const std::string& PcapReader::GetSrcIpOfCurrentPacket()
{
    return this->src_ip_;
    // TODO: 在此处插入 return 语句
}

const std::string& PcapReader::GetDstIpOfCurrentPacket()
{
    // TODO: 在此处插入 return 语句
    return this->dst_ip_;
}

uint16_t PcapReader::GetSrcPortOfCurrentPacket()
{
    return src_port_;
}

uint16_t PcapReader::GetDstPortOfCurrentPacket()
{
    return dst_port_;
}

Direction ProtoTest::PcapReader::GetDirection()
{
    std::string current_addr = this->src_ip_ + ":" + std::to_string(this->src_port_);

    if (current_addr == CLIENT_ADDR)
    {
        return Direction::CLIENT;
    }
    else if (current_addr == SERVER_ADDR)
    {
        return Direction::SERVER;
    }

    return Direction::UNKNOWN;
}






