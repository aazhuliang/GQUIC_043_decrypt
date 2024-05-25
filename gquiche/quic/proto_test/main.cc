#include "server_session.h"
#include "packet_reader.h"
#include "client_session.h"
#include "pcap_reader.h"
#include "config.h"
#include "absl/strings/escaping.h"
#include <iostream>
#include <fstream>



void ConcatHeadStream(const std::vector<std::pair<std::string, std::string>>& head_list,
	std::string& out, size_t& content_length)
{
	out.clear();
	for (auto& header_it : head_list)
	{
		std::string key;
		key.resize(header_it.first.length());
		std::transform(header_it.first.begin(), header_it.first.end(), key.begin(), ::tolower);
		if (key.compare("content-length") == 0)
		{
			content_length = std::stoull(header_it.second);
		}
		out.append(header_it.first);
		out.append(": ");
		out.append(header_it.second);
		out.append("\r\n");
	}
}

void GetBodyDataBySId(uint32_t http_stream_id, size_t content_length, std::string& out,
	const std::map<uint32_t, std::string>& body_list, bool is_verify_content_length=true)
{
	auto is_body_it = body_list.find(http_stream_id);
	if (is_body_it != body_list.end())
	{
		assert(!is_verify_content_length || content_length == is_body_it->second.length());
		out.append(is_body_it->second);
		return;
	}
	assert(!is_verify_content_length || content_length == 0);
}

void GetHttpData(ProtoTest::ServerSession& server_ssession,
	ProtoTest::ClientSession& client_session)
{
	std::ofstream f_of(ProtoTest::OUT_PATH);
	std::ostream* used_of = &f_of;
	if (!f_of.is_open())
	{
		used_of = &std::cout;
	}
	for (auto& s_it : server_ssession.GetHeadManage())
	{
		uint32_t http_stream_id = s_it.first;
		size_t req_content_length = 0;
		std::string req_head_data;
		std::string req_body_data;
		ConcatHeadStream(s_it.second, req_head_data, req_content_length);
		GetBodyDataBySId(http_stream_id, req_content_length, req_body_data, server_ssession.GetBodyManage(), req_content_length != 0);
		
		auto c_it = client_session.GetHeadManage().find(http_stream_id);
		if (c_it == client_session.GetHeadManage().end())
			continue;
		std::string rsp_head_data;
		std::string rsp_body_data;
		size_t rsp_content_length = 0;
		ConcatHeadStream(c_it->second, rsp_head_data, rsp_content_length);

		GetBodyDataBySId(http_stream_id, rsp_content_length, rsp_body_data, client_session.GetBodyManage(), rsp_content_length != 0);
		auto req_body_data_hex = absl::BytesToHexString(std::move(req_body_data));
		auto rsp_body_data_hex = absl::BytesToHexString(std::move(rsp_body_data));

		auto req_head_data_hex = absl::BytesToHexString(std::move(req_head_data));
		auto rsp_head_data_hex = absl::BytesToHexString(std::move(rsp_head_data));

		*used_of << (req_head_data_hex.empty() ? " " : req_head_data_hex);
		*used_of << "___";
		*used_of << (req_body_data_hex.empty() ? " " : req_body_data_hex);
		*used_of << "___";
		*used_of << (rsp_head_data_hex.empty() ? " " : rsp_head_data_hex);
		*used_of << "___";
		*used_of << (rsp_body_data_hex.empty() ? " " : rsp_body_data_hex);
		*used_of << std::endl;
	}
	if (f_of.is_open())
	{
		f_of.close();
	}
	
}

int main(int argc, char* argv[])
{
	ProtoTest::ServerSession server_ssession;
	ProtoTest::ClientSession client_session;

	ProtoTest::PcapReader* pcap_reader = ProtoTest::PcapReader::GetpcapReader();
	pcap_reader->OpenPcapFile(ProtoTest::IN_PCAP_PATH, ProtoTest::PCAP_FILTER);

	if (ProtoTest::IS_0RTT)
	{ 
		for (auto& rej_packet : (ProtoTest::EXTERNAL_REJ_PACKETS))
		{
			client_session.ProcessPacket(rej_packet, false);
		}
	}
	
	for ( std::string pcap_data = pcap_reader->GetNextQuicPacket();
		pcap_data != ""; 
		pcap_data = pcap_reader->GetNextQuicPacket())
	{
		ProtoTest::Direction direction = pcap_reader->GetDirection();
		if (direction == ProtoTest::Direction::CLIENT)
		{
			server_ssession.ProcessPacket(pcap_data);
		}
		else if (direction == ProtoTest::Direction::SERVER)
		{
			client_session.ProcessPacket(pcap_data);
		}
		else
		{
			//std::cout << "unknonwn direction " << pcap_reader->GetSrcIpOfCurrentPacket()
			//	<< ":" << pcap_reader->GetSrcPortOfCurrentPacket() << std::endl;
		}
	}
	



	GetHttpData(server_ssession, client_session);

	return 0;
}