#include "hand_shake_visitor.h"
#include "pcap_reader.h"
#include "session.h"

bool ProtoTest::HandShakeVisitor::OnStreamFrame(const QuicStreamFrame& frame)
{
	if (quic::QuicVersionUsesCryptoFrames(framer_->transport_version())) {
		// CHLO will be sent in CRYPTO frames in v47 and above.
		return false;
	}
	

	absl::string_view data(frame.data_buffer, frame.data_length);
	if (QuicUtils::IsCryptoStreamId(framer_->transport_version(),
		frame.stream_id)  && this->Getsession()->OnCryptoFrame(frame))
	{

		return OnHandshakeData(data);
	}

	
	return false;
}

bool ProtoTest::HandShakeVisitor::OnHandshakeData(absl::string_view data)
{

	if (!crypto_framer_.ProcessInput(data)) {
		return false;
	}
	return true;

}

bool ProtoTest::HandShakeVisitor::OnPacketHeader(const quic::QuicPacketHeader& header)
{
	return this->Getsession()->OnPacketHeader(header);
}

void ProtoTest::HandShakeVisitor::OnError(CryptoFramer* framer)
{
}

void ProtoTest::HandShakeVisitor::OnHandshakeMessage(const CryptoHandshakeMessage& message)
{
	this->Getsession()->OnHandshakeMessage(message);
}
