#include "gquiche/quic/core/crypto/crypto_protocol.h"
#include "client_session.h"
#include "config.h"
#include "hand_shake_visitor.h"
#include "common_visitor.h"


ProtoTest::ClientSession::~ClientSession()
{
}

void ProtoTest::ClientSession::OnHandshakeMessage(const quic::CryptoHandshakeMessage& message)
{
	if (message.tag() == quic::kREJ)
	{

		absl::string_view scfg_str;
		if (!message.GetStringPiece(quic::kSCFG, &scfg_str))
		{
			std::cout << "Handshake not ready" << std::endl;
			return;
		}
		crypto_parms_.scfg_str = scfg_str;
		std::unique_ptr<quic::CryptoHandshakeMessage> scfg = quic::CryptoFramer::ParseMessage(scfg_str);
		if (!scfg)
		{
			std::cout << "Handshake not ready" << std::endl;
			return;
		}
		quic::QuicTagVector their_aeads;
		quic::QuicTagVector their_key_exchanges;

		if (scfg->GetTaglist(quic::kAEAD, &their_aeads) != quic::QUIC_NO_ERROR ||
			scfg->GetTaglist(quic::kKEXS, &their_key_exchanges) != quic::QUIC_NO_ERROR)
		{
			std::cout << "Missing AEAD or KEXS" << std::endl;
			return ;
		}

		absl::string_view public_value;
		if (scfg->GetNthValue24(quic::kPUBS, 0, &public_value) !=
			quic::QUIC_NO_ERROR)
		{
			std::cout << "Missing public value" << std::endl;
			return;
		}
		crypto_parms_.rej_public_value = public_value;
		crypto_parms_.private_key = ProtoTest::PRIVATE_KEY;
		std::string private_key_hex = absl::HexStringToBytes(crypto_parms_.private_key);
		// 这里偷懒写死了密钥交换算法，正确的做法应该是根据SCID来判断使用哪个密钥交换算法。
		crypto_parms_.key_exchange = quic::Curve25519KeyExchange::New(private_key_hex);

		absl::string_view cert_bytes;
		bool has_cert = message.GetStringPiece(quic::kCertificateTag, &cert_bytes);
		if (!has_cert)
		{
			return;
		}
		if (!quic::CertCompressor::DecompressChain(cert_bytes, std::vector<std::string>(), &crypto_parms_.certs))
		{
			std::cout << "Certificate data invalid" << std::endl;
			return ;
		}
		if (crypto_parms_.certs.empty())
		{
			std::cout << "No certs to calculate XLCT" << std::endl;
			return ;
		}
	}
	else if (message.tag() == quic::kSHLO)
	{
		
		absl::string_view public_value;
		if (!message.GetStringPiece(quic::kPUBS, &public_value))
		{
			std::cout << "server hello missing forward secure public value" << std::endl;

			return ;
		}

		absl::string_view shlo_nonce;
		if (!message.GetStringPiece(quic::kServerNonceTag, &shlo_nonce))
		{
			std::cout << "server hello missing server nonce" << std::endl;

			return ;
		}

		crypto_parms_.shlo_public_value = public_value;
		crypto_parms_.shlo_nonce = shlo_nonce;

		quic::CrypterPair forward_crypters;
		quic::CrypterPair forward_crypters_server;
		CalcuteForwardCryptopair(quic::Perspective::IS_CLIENT, forward_crypters);
		CalcuteForwardCryptopair(quic::Perspective::IS_SERVER, forward_crypters_server);
		this->SetAlternativeDecrypter(quic::EncryptionLevel::ENCRYPTION_FORWARD_SECURE, 
			std::move(forward_crypters.decrypter), false);
		//GetServerSession()->SetDecrypter(quic::EncryptionLevel::ENCRYPTION_FORWARD_SECURE, std::move(forward_crypters_server.decrypter));
		GetServerSession()->SetAlternativeDecrypter(quic::EncryptionLevel::ENCRYPTION_FORWARD_SECURE, std::move(forward_crypters_server.decrypter), false);
		this->current_state_ = Session::State::RECV_DATA;
		this->SetVisitor(this->common_visitor_.get());

	}

}

bool ProtoTest::ClientSession::OnCryptoFrame(const quic::QuicStreamFrame& frame)
{

	if (this->current_state_ == Session::State::RECV_REJ
		&& dynamic_cast<const ProtoTest::HandShakeVisitor*>(GetCurrentVisitor()))
	{
		return true;

	}
	return false;
}



