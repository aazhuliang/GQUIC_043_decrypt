#pragma once
#include <map>
#include "gquiche/quic/core/crypto/crypto_framer.h"
#include "gquiche/quic/core/quic_stream_sequencer_buffer.h"
#include "gquiche/spdy/core/http2_frame_decoder_adapter.h"

#include "test_visitor.h"
#include "SpdyFramerVisitor.h"

namespace ProtoTest
{
	class CommonVisitor : public ProtoTest::QuicPacketPrinter,
		public quic::CryptoFramerVisitorInterface
	{
	public:
		CommonVisitor(QuicFramer* framer, Session* session);

		~CommonVisitor() override {};
		bool OnStreamFrame(const QuicStreamFrame& frame) override;
		bool OnHandshakeData(absl::string_view data);
		void OnDecryptedPacket(size_t /*length*/, EncryptionLevel level) override;
		void OnError(CryptoFramer* framer) override;
		void OnHandshakeMessage(const CryptoHandshakeMessage& message) override;
		void OnHeadFrame(const QuicStreamFrame& frame, quic::QuicStreamSequencerBuffer* buffer);
		void OnBodyFrame(const QuicStreamFrame& frame, quic::QuicStreamSequencerBuffer* buffer);
		virtual bool OnPacketHeader(const quic::QuicPacketHeader& /*header*/) override;
	private:
		http2::Http2DecoderAdapter h2_deframer_;
		std::unique_ptr<SqdyFramerVisitror> spdy_framer_visitor_;
		std::map<uint32_t, std::unique_ptr<quic::QuicStreamSequencerBuffer>> stream_map_;

	};

}