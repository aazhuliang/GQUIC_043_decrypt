#include "common_visitor.h"
#include "session.h"
#include "config.h"
#include "gquiche/spdy/core/http2_frame_decoder_adapter.h"

ProtoTest::CommonVisitor::CommonVisitor(QuicFramer* framer, Session* session)
    :QuicPacketPrinter(framer, session),
    h2_deframer_(),
    spdy_framer_visitor_(std::make_unique<ProtoTest::SqdyFramerVisitror>(this->Getsession())),
    stream_map_()
{

    this->h2_deframer_.set_visitor(spdy_framer_visitor_.get());
};

bool ProtoTest::CommonVisitor::OnStreamFrame(const QuicStreamFrame& frame)
{
    
    if (frame.fin && frame.data_length == 0)
        return false;
    /*
    std::cout << this->Getsession()->GetPerspective() << ": " <<
        "stream_id is: " << frame.stream_id << " offset is: " << frame.offset << " length is: "
        << frame.data_length << " pcaket number is: " << this->Getsession()->GetCurrentPacketNumber()
        << std::endl;*/

    quic::QuicStreamSequencerBuffer* current_buffered_frames = nullptr;
    auto s_it = stream_map_.find(frame.stream_id);
    if (s_it  == stream_map_.end())
    {
        auto tmp = std::make_unique<quic::QuicStreamSequencerBuffer>(quic::kStreamReceiveWindowLimit);
        current_buffered_frames = tmp.get();
        stream_map_.emplace(frame.stream_id, std::move(tmp));
    }
    else
    {
        
        current_buffered_frames = s_it->second.get();
    }
    assert(current_buffered_frames);
    if (!Getsession()->OnCommonFrame(frame))
        return false;

    if (!quic::QuicUtils::IsCryptoStreamId(Getsession()->GetFramer()->transport_version(), frame.stream_id) &&
        Getsession()->GetCryptoLevel() == quic::EncryptionLevel::ENCRYPTION_INITIAL)
        return false;

    if (frame.stream_id == quic::QuicUtils::GetInvalidStreamId(Getsession()->GetFramer()->transport_version()))
        return false;

    bool is_stream_too_long =
        (frame.offset > quic::kMaxStreamLength) ||
        (quic::kMaxStreamLength - frame.offset < frame.data_length);
    if (is_stream_too_long)
        return false;

    if (frame.offset + frame.data_length > std::numeric_limits<quic::QuicStreamOffset>::max())
        return false;


    const size_t previous_readable_bytes = current_buffered_frames->ReadableBytes();
    size_t bytes_written;
    std::string error_details;
    quic::QuicErrorCode result = current_buffered_frames->OnStreamData(
        frame.offset, absl::string_view(frame.data_buffer, frame.data_length), &bytes_written,
        &error_details);
    if (result != QUIC_NO_ERROR)
        return false;

    if (bytes_written == 0)
        return false;

    const bool stream_unblocked =
        previous_readable_bytes == 0 && current_buffered_frames->ReadableBytes() > 0;

    if (!stream_unblocked)
        return false;

    if (HEAD_STREAM_ID == frame.stream_id)
    {
        OnHeadFrame(frame, current_buffered_frames);
    }
    else
    {
        OnBodyFrame(frame, current_buffered_frames);
    }
    

    return true;
}

bool ProtoTest::CommonVisitor::OnHandshakeData(absl::string_view data)
{
    assert(false);
	return false;
}

void ProtoTest::CommonVisitor::OnDecryptedPacket(size_t, EncryptionLevel level)
{
    
    assert(level == quic::EncryptionLevel::ENCRYPTION_ZERO_RTT || level == quic::EncryptionLevel::ENCRYPTION_FORWARD_SECURE);
    //std::cout << "OnDecryptedPacket success the current level is " << level << std::endl;
}

void ProtoTest::CommonVisitor::OnError(CryptoFramer* framer)
{
    assert(false);
}

void ProtoTest::CommonVisitor::OnHandshakeMessage(const CryptoHandshakeMessage& message)
{
    assert(false);
}



void ProtoTest::CommonVisitor::OnHeadFrame(const QuicStreamFrame& frame, quic::QuicStreamSequencerBuffer* buffer)
{
    (void)(frame);
    struct iovec iov;
    
    
    while (buffer->GetReadableRegion(&iov))
    {
        
        this->h2_deframer_.ProcessInput(static_cast<char*>(iov.iov_base), iov.iov_len);  
        buffer->MarkConsumed(iov.iov_len);
    }

   
}

void ProtoTest::CommonVisitor::OnBodyFrame(const QuicStreamFrame& frame, quic::QuicStreamSequencerBuffer* buffer)
{

    while (buffer->HasBytesToRead())
    {
        struct iovec iov;
        if (buffer->GetReadableRegions(&iov, 1) == 0)
        {
            break;
        }
        std::string body_data(static_cast<char*>(iov.iov_base), iov.iov_len);
        this->Getsession()->OnBodyData(body_data, frame.stream_id);
        buffer->MarkConsumed(iov.iov_len);
    }

    

}


bool ProtoTest::CommonVisitor::OnPacketHeader(const quic::QuicPacketHeader& header)
{
    return this->Getsession()->OnPacketHeader(header);
}

