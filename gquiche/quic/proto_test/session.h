#pragma once

#include "gquiche/quic/core/quic_framer.h"
#include "gquiche/quic/core/quic_versions.h"
#include "gquiche/quic/core/quic_packets.h"
#include "gquiche/quic/core/crypto/crypto_handshake_message.h"
#include "gquiche/quic/core/crypto/null_decrypter.h"
#include "gquiche/quic/core/frames/quic_stream_frame.h"
#include "gquiche/quic/core/quic_packets.h"
#include "gquiche/quic/core/crypto/crypto_handshake.h"
#include "gquiche/quic/core/crypto/curve25519_key_exchange.h"
#include "gquiche/quic/core/crypto/cert_compressor.h"

#include <string>
#include <memory>
#include <map>
namespace ProtoTest
{
	
	class CryptoParms
	{
	public:
		CryptoParms():key_exchange(nullptr){};
		~CryptoParms() = default;
		std::string scfg_str;
		std::string private_key;
		std::unique_ptr<quic::SynchronousKeyExchange> key_exchange;
		std::string hkdf_input_suffix;
		quic::QuicTag aead;
		std::string client_nonce;
		std::string server_nonce;
		std::string rej_public_value;
		std::vector<std::string> certs;
		quic::DiversificationNonce server_diversification_nonce;
		std::string shlo_public_value;
		std::string shlo_nonce;
	};

	class HandShakeVisitor;
	class CommonVisitor;
	class Session
	{
	public:
		Session(quic::Perspective perspective);
			
		virtual ~Session();
		void ProcessPacket(const std::string& quic_packet, bool is_raw_data=true);
		bool OnPacketHeader(const quic::QuicPacketHeader& header);
		quic::QuicFramer* GetFramer();
		virtual void OnHandshakeMessage(const quic::CryptoHandshakeMessage& message);
		virtual bool OnCryptoFrame(const quic::QuicStreamFrame& frame);
		virtual bool OnCommonFrame(const quic::QuicStreamFrame& frame);
		virtual void OnHeadEnd(std::vector<std::pair<std::string, std::string>> head_lists, uint32_t http_stream_id);
		virtual void OnBodyData(std::string body_data, uint32_t stream_id);
		quic::EncryptionLevel GetCryptoLevel();
		static Session* GetServerSession();
		static Session* GetClientSession();
		quic::QuicConnectionId& GetConnId();
		quic::ParsedQuicVersion GetCurrentVersion();
		void SetDecrypter(quic::EncryptionLevel level,
			std::unique_ptr<quic::QuicDecrypter> decrypter);
		void SetAlternativeDecrypter(quic::EncryptionLevel level,
			std::unique_ptr<quic::QuicDecrypter> decrypter,
			bool latch_once_used = true);
		CommonVisitor* GetCommonVisitor();
		quic::Perspective GetPerspective();
		uint64_t GetCurrentPacketNumber();
		const std::map<uint32_t, std::vector<std::pair<std::string, std::string>>>& GetHeadManage();
		const std::map<uint32_t, std::string>& GetBodyManage();
	protected:
		quic::ParsedQuicVersionVector GetAllSupportVersion();
		void CreateFramer(quic::Perspective perspective);
		void SetVisitor(quic::QuicFramerVisitorInterface* visitor);

		bool CalcuteInitCryptopair(quic::Perspective perspective, quic::CrypterPair& out_crypters);
		bool CalcuteForwardCryptopair(quic::Perspective perspective, quic::CrypterPair& out_crypters);
		const quic::QuicFramerVisitorInterface* GetCurrentVisitor();
		enum class State
		{
			UNKNOWN,
			RECV_CHLO,
			RECV_REJ,
			RECV_DATA
			
		};
		State current_state_;
		std::unique_ptr<HandShakeVisitor> visitor_;
		std::unique_ptr<CommonVisitor> common_visitor_;
		static CryptoParms crypto_parms_;
		static Session* server_session_;
		static Session* client_session_;
		
	private:
		quic::EncryptionLevel crypto_level_;
		std::unique_ptr<quic::QuicFramer> framer_;
		quic::Perspective perspective_;
		quic::QuicConnectionId conn_id_;
		quic::QuicFramerVisitorInterface* current_visitor_;
		uint64_t current_packet_number_;
		std::map<uint32_t, std::vector<std::pair<std::string, std::string>>> head_manage_;
		std::map<uint32_t, std::string> body_manage_;
	};
}
