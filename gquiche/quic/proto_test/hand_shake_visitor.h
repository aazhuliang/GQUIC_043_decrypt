#pragma once

#include "test_visitor.h"
#include "gquiche/quic/core/crypto/crypto_framer.h"

namespace ProtoTest
{
	class HandShakeVisitor : public ProtoTest::QuicPacketPrinter,
		public quic::CryptoFramerVisitorInterface
	{
	public:
		HandShakeVisitor(QuicFramer* framer, Session* session) : QuicPacketPrinter(framer, session), crypto_framer_()
		{
			crypto_framer_.set_visitor(this);
		};
		~HandShakeVisitor() override {};
		bool OnStreamFrame(const QuicStreamFrame& frame) override;
		bool OnHandshakeData(absl::string_view data);
		virtual bool OnPacketHeader(const quic::QuicPacketHeader& /*header*/) override;
		// CryptoFramerVisitorInterface implementation.
		void OnError(CryptoFramer* framer) override;
		void OnHandshakeMessage(const CryptoHandshakeMessage& message) override;

	private:
		quic::CryptoFramer crypto_framer_;
	};

}