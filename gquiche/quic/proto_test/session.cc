#include "absl/strings/escaping.h"
#include "gquiche/quic/core/crypto/crypto_protocol.h"
#include "gquiche/quic/core/crypto/cert_compressor.h"
#include "gquiche/quic/core/crypto/crypto_handshake.h"
#include "gquiche/quic/core/crypto/crypto_utils.h"
#include "gquiche/quic/core/crypto/crypto_framer.h"
#include "config.h"
#include "session.h"
#include "pcap_reader.h"
#include "hand_shake_visitor.h"
#include "common_visitor.h"

ProtoTest::Session* ProtoTest::Session::server_session_ = nullptr;
ProtoTest::Session* ProtoTest::Session::client_session_ = nullptr;
ProtoTest::CryptoParms ProtoTest::Session::crypto_parms_;

ProtoTest::Session::Session(quic::Perspective perspective)
	: current_state_(State::UNKNOWN),
	visitor_(nullptr),
	common_visitor_(nullptr),
	crypto_level_(quic::EncryptionLevel::NUM_ENCRYPTION_LEVELS),
	framer_(nullptr),
	perspective_(perspective),
	conn_id_(),
	current_visitor_(nullptr),
	current_packet_number_(0),
	head_manage_(),
	body_manage_()
{
	this->CreateFramer(perspective_);
	this->visitor_ = std::make_unique<ProtoTest::HandShakeVisitor>(this->GetFramer(), this);
	this->SetVisitor(this->visitor_.get());
	this->SetDecrypter(quic::EncryptionLevel::ENCRYPTION_INITIAL, std::make_unique<quic::NullDecrypter>(perspective));
	this->common_visitor_ = std::make_unique<ProtoTest::CommonVisitor>(this->GetFramer(), this);
};
ProtoTest::Session::~Session()
{
}
void ProtoTest::Session::ProcessPacket(const std::string& quic_packet, bool is_raw_data)
{
	if (this->GetFramer() 
		&& this->GetCurrentVisitor() 
		&& this->GetCryptoLevel() != quic::EncryptionLevel::NUM_ENCRYPTION_LEVELS)
	{
		if (!is_raw_data)
		{
			std::string hex_quic_data = absl::HexStringToBytes(quic_packet);
			quic::QuicEncryptedPacket encrypted(hex_quic_data.c_str(), hex_quic_data.length());
			this->GetFramer()->ProcessPacket(encrypted);
		}
		else
		{
			quic::QuicEncryptedPacket encrypted(quic_packet.c_str(), quic_packet.length());
			this->GetFramer()->ProcessPacket(encrypted);
		}		
		
	}
}

quic::QuicFramer* ProtoTest::Session::GetFramer()
{
	return this->framer_.get();
}

void ProtoTest::Session::OnHandshakeMessage(const quic::CryptoHandshakeMessage& message)
{
	std::cout << message.DebugString() << std::endl;
}

bool ProtoTest::Session::OnCryptoFrame(const quic::QuicStreamFrame& frame)
{

	return false;
}

bool ProtoTest::Session::OnCommonFrame(const quic::QuicStreamFrame& frame)
{
	if (this->current_state_ == Session::State::RECV_DATA
		&& dynamic_cast<const ProtoTest::CommonVisitor*>(GetCurrentVisitor()))
	{
		return true;
	}
	return false;
}


void ProtoTest::Session::OnHeadEnd(std::vector<std::pair<std::string, std::string>> head_lists,
	uint32_t http_stream_id)
{
	if (head_manage_.find(http_stream_id) != head_manage_.end())
		assert(false);
	head_manage_.emplace(http_stream_id, std::move(head_lists));
	
}

void ProtoTest::Session::OnBodyData(std::string body_data, uint32_t stream_id)
{
	auto b_it = body_manage_.find(stream_id);
	if (b_it == body_manage_.end())
	{
		body_manage_.emplace(stream_id, std::move(body_data));
	}
	else
	{
		b_it->second.append(body_data);
	}
}



quic::ParsedQuicVersion ProtoTest::Session::GetCurrentVersion()
{
	return  quic::ParseQuicVersionString(ProtoTest::USED_QUIC_VERSION);
}


quic::ParsedQuicVersionVector ProtoTest::Session::GetAllSupportVersion()
{
	assert(this->GetCurrentVersion() == quic::ParsedQuicVersion::Q043());
	return quic::ParsedQuicVersionVector{ this->GetCurrentVersion() };
}

bool ProtoTest::Session::OnPacketHeader(const quic::QuicPacketHeader& header)
{
	if (this->conn_id_.IsEmpty())
	{
		this->conn_id_ = header.destination_connection_id;
	}
	this->current_packet_number_ = header.packet_number.ToUint64();
	assert(this->conn_id_ == header.destination_connection_id);
	return true;
}

quic::EncryptionLevel ProtoTest::Session::GetCryptoLevel()
{
	return this->crypto_level_;

}

ProtoTest::Session* ProtoTest::Session::GetServerSession()
{
	return server_session_;

}

ProtoTest::Session* ProtoTest::Session::GetClientSession()
{
	return client_session_;
}

quic::QuicConnectionId& ProtoTest::Session::GetConnId()
{
	return this->conn_id_;

}




void ProtoTest::Session::CreateFramer(quic::Perspective perspective)
{
	assert(this->framer_ == nullptr);
	quic::QuicTime start(quic::QuicTime::Zero());
	quic::QuicFramer* framer = new quic::QuicFramer(this->GetAllSupportVersion(), start,
		perspective,
		quic::kQuicDefaultConnectionIdLength);

	if (framer != nullptr)
	{
		framer->set_version(this->GetCurrentVersion());
		this->framer_.reset(framer);
	}

}

void ProtoTest::Session::SetVisitor(quic::QuicFramerVisitorInterface* visitor)
{
	if (this->framer_ != nullptr && visitor != nullptr)
	{
		this->framer_->set_visitor(visitor);
		this ->current_visitor_ = visitor;
	}
}

void ProtoTest::Session::SetDecrypter(quic::EncryptionLevel level, std::unique_ptr<quic::QuicDecrypter> decrypter)
{
	if (this->framer_ != nullptr && decrypter != nullptr && level != quic::EncryptionLevel::NUM_ENCRYPTION_LEVELS)
	{
		this->framer_->SetDecrypter(level, std::move(decrypter));
		this->crypto_level_ = level;
	}

}

void ProtoTest::Session::SetAlternativeDecrypter(quic::EncryptionLevel level,
	std::unique_ptr<quic::QuicDecrypter> decrypter,
	bool latch_once_used )
{
	if (this->framer_ != nullptr && decrypter != nullptr && level != quic::EncryptionLevel::NUM_ENCRYPTION_LEVELS)
	{
		this->framer_->SetAlternativeDecrypter(level, std::move(decrypter), latch_once_used);
		this->crypto_level_ = level;
	}
}

ProtoTest::CommonVisitor* ProtoTest::Session::GetCommonVisitor()
{
	return this->common_visitor_.get();
}





bool ProtoTest::Session::CalcuteInitCryptopair(quic::Perspective perspective, quic::CrypterPair& out_crypters)
{
	if (crypto_parms_.key_exchange == nullptr)
		return false;
	if (crypto_parms_.rej_public_value.empty())
		return false;
	if (crypto_parms_.hkdf_input_suffix.empty())
		return false;
	if (crypto_parms_.client_nonce.empty())
		return false;

	std::string initial_premaster_secret;
	if (!crypto_parms_.key_exchange->CalculateSharedKeySync(
		crypto_parms_.rej_public_value, &initial_premaster_secret))
	{

		std::cout << "Key exchange failure" << std::endl;
		return false;
	}

	std::string hkdf_input;
	std::string pre_shared_key;
	std::string subkey_secret;
	const size_t label_len = strlen(quic::QuicCryptoConfig::kInitialLabel) + 1;
	hkdf_input.reserve(label_len + crypto_parms_.hkdf_input_suffix.size());
	hkdf_input.append(quic::QuicCryptoConfig::kInitialLabel, label_len);
	hkdf_input.append(crypto_parms_.hkdf_input_suffix);

	if (perspective == quic::Perspective::IS_SERVER)
	{
		quic::CryptoUtils::Diversification diversification =
			quic::CryptoUtils::Diversification::Now(&crypto_parms_.server_diversification_nonce);
		if (!quic::CryptoUtils::DeriveKeys(
			this->GetCurrentVersion(), initial_premaster_secret,
			crypto_parms_.aead, crypto_parms_.client_nonce, crypto_parms_.server_nonce,
			pre_shared_key, hkdf_input, perspective,
			diversification,
			&out_crypters, &subkey_secret))
		{

			std::cout << "Symmetric key setup failed" << std::endl;
			return false;
		}
	}
	else if (perspective == quic::Perspective::IS_CLIENT)
	{
		if (!quic::CryptoUtils::DeriveKeys(
			this->GetCurrentVersion(), initial_premaster_secret,
			crypto_parms_.aead, crypto_parms_.client_nonce, crypto_parms_.server_nonce,
			pre_shared_key, hkdf_input, perspective,
			quic::CryptoUtils::Diversification::Pending(),
			&out_crypters, &subkey_secret))
		{

			std::cout << "Symmetric key setup failed" << std::endl;
			return false;
		}
	}

	return true;
}

// 这个函数流程和CalcuteInitCryptopair基本相同，可以合并为一个。
bool ProtoTest::Session::CalcuteForwardCryptopair(quic::Perspective perspective, quic::CrypterPair& out_crypters)
{
	
	if (crypto_parms_.key_exchange == nullptr)
		return false;
	if (crypto_parms_.rej_public_value.empty())
		return false;
	if (crypto_parms_.hkdf_input_suffix.empty())
		return false;
	if (crypto_parms_.client_nonce.empty())
		return false;
	//if (crypto_parms_.server_nonce.empty())
	//	return false;


	std::string forward_premaster_secret;
	if (!crypto_parms_.key_exchange->CalculateSharedKeySync(
		crypto_parms_.shlo_public_value, &forward_premaster_secret))
	{

		std::cout << "Key exchange failure" << std::endl;
		return false;
	}

	std::string hkdf_input;
	std::string pre_shared_key;
	std::string subkey_secret;
	const size_t label_len = strlen(quic::QuicCryptoConfig::kForwardSecureLabel) + 1;
	hkdf_input.reserve(label_len + crypto_parms_.hkdf_input_suffix.size());
	hkdf_input.append(quic::QuicCryptoConfig::kForwardSecureLabel, label_len);
	hkdf_input.append(crypto_parms_.hkdf_input_suffix);

	if (!quic::CryptoUtils::DeriveKeys(
		this->GetCurrentVersion(), forward_premaster_secret,
		crypto_parms_.aead, crypto_parms_.client_nonce, crypto_parms_.shlo_nonce.empty() ? 
		crypto_parms_.server_nonce : crypto_parms_.shlo_nonce,
		pre_shared_key, hkdf_input, perspective,
		quic::CryptoUtils::Diversification::Never(),
		&out_crypters, &subkey_secret))
	{

		std::cout << "Symmetric key setup failed" << std::endl;
		return false;
	}

	return true;
}

quic::Perspective ProtoTest::Session::GetPerspective()
{
	return this->perspective_;
}

uint64_t ProtoTest::Session::GetCurrentPacketNumber()
{
	return this->current_packet_number_;
}

const std::map<uint32_t, std::vector<std::pair<std::string, std::string>>>& ProtoTest::Session::GetHeadManage()
{
	// TODO: 在此处插入 return 语句
	return this->head_manage_;
}

const std::map<uint32_t, std::string>& ProtoTest::Session::GetBodyManage()
{
	// TODO: 在此处插入 return 语句
	return this->body_manage_;
}

const quic::QuicFramerVisitorInterface* ProtoTest::Session::GetCurrentVisitor()
{
	return this ->current_visitor_;
}

/*
http2::Http2DecoderAdapter& ProtoTest::Session::GetH2DeFramer()
{
	// TODO: 在此处插入 return 语句
	return this->h2_deframer_;
}*/
