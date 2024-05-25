#include <memory>
#include <iostream>
#include "gquiche/quic/core/crypto/crypto_protocol.h"
#include "gquiche/quic/core/crypto/curve25519_key_exchange.h"
#include "gquiche/quic/core/crypto/cert_compressor.h"
#include "gquiche/quic/core/crypto/crypto_handshake.h"
#include "gquiche/quic/core/crypto/crypto_utils.h"
#include "server_session.h"
#include "hand_shake_visitor.h"
#include "common_visitor.h"
#include "config.h"


ProtoTest::ServerSession::ServerSession(): Session(quic::Perspective::IS_SERVER)//,
{
	current_state_ = Session::State::RECV_CHLO;
	server_session_ = this;
	
}

ProtoTest::ServerSession::~ServerSession()
{
}


void ProtoTest::ServerSession::OnHandshakeMessage(const quic::CryptoHandshakeMessage& message)
{
	absl::string_view scid;
	if (message.tag() == quic::kCHLO 
		&& message.GetStringPiece(quic::kSCID, &scid))
	{

		crypto_parms_.hkdf_input_suffix.clear();

		crypto_parms_.hkdf_input_suffix.append(this->GetConnId().data(),
			this->GetConnId().length());

		const quic::QuicData& client_hello_serialized = message.GetSerialized();
		crypto_parms_.hkdf_input_suffix.append(client_hello_serialized.data(),
			client_hello_serialized.length());

		crypto_parms_.hkdf_input_suffix.append(crypto_parms_.scfg_str);
		crypto_parms_.hkdf_input_suffix.append(crypto_parms_.certs[0]);

		quic::QuicTagVector use_aead;
		message.GetTaglist(quic::kAEAD, &use_aead);
		crypto_parms_.aead = use_aead[0];

		absl::string_view client_nonce;
		message.GetStringPiece(quic::kNONC, &client_nonce);

		absl::string_view server_nonce;
		message.GetStringPiece(quic::kServerNonceTag, &server_nonce);
		crypto_parms_.client_nonce = client_nonce;
		crypto_parms_.server_nonce = server_nonce;
		std::string diversification_nonce_hex =
			absl::HexStringToBytes(ProtoTest::DIVERSIFICATION_NONCE);

		std::copy(diversification_nonce_hex.begin(), diversification_nonce_hex.end(),
			crypto_parms_.server_diversification_nonce.begin());

		
		quic::CrypterPair initial_crypters;
		quic::CrypterPair initial_crypters_client;
		CalcuteInitCryptopair(quic::Perspective::IS_SERVER, initial_crypters);
		CalcuteInitCryptopair(quic::Perspective::IS_CLIENT, initial_crypters_client);
			

		this->SetVisitor(this->common_visitor_.get());
		this->SetDecrypter(quic::EncryptionLevel::ENCRYPTION_ZERO_RTT, std::move(initial_crypters.decrypter));
		this->GetClientSession()->SetAlternativeDecrypter(quic::EncryptionLevel::ENCRYPTION_ZERO_RTT, 
			std::move(initial_crypters_client.decrypter));

		current_state_ = Session::State::RECV_DATA;
	}
}

bool ProtoTest::ServerSession::OnCryptoFrame(const quic::QuicStreamFrame& frame)
{

	absl::string_view data(frame.data_buffer, frame.data_length);
	if (this->current_state_ == Session::State::RECV_CHLO
		&& absl::StartsWith(data, "CHLO")
		&& dynamic_cast<const ProtoTest::HandShakeVisitor*>(GetCurrentVisitor()))
	{
		return true;
	}
	
	return false;
}
