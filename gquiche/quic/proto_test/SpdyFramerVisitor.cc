#include <vector>
#include "SpdyFramerVisitor.h"
#include "session.h"
#include "common_visitor.h"

void ProtoTest::SqdyFramerVisitror::OnError(http2::Http2DecoderAdapter::SpdyFramerError error, std::string detailed_error)
{
}

void ProtoTest::SqdyFramerVisitror::OnDataFrameHeader(SpdyStreamId stream_id, size_t length, bool fin)
{
}

void ProtoTest::SqdyFramerVisitror::OnStreamFrameData(SpdyStreamId stream_id, const char* data, size_t len)
{
}

void ProtoTest::SqdyFramerVisitror::OnStreamEnd(SpdyStreamId stream_id)
{
	
}

void ProtoTest::SqdyFramerVisitror::OnStreamPadding(SpdyStreamId stream_id, size_t len)
{
}

SpdyHeadersHandlerInterface* ProtoTest::SqdyFramerVisitror::OnHeaderFrameStart(SpdyStreamId stream_id)
{

	return &header_list_;
}

void ProtoTest::SqdyFramerVisitror::OnHeaderFrameEnd(SpdyStreamId stream_id)
{
    //std::string head_data;
    //size_t content_length = 0;
    std::vector<std::pair<std::string, std::string>> head_lists;
    for (const auto& p : this->header_list_)
    {
        /*
        std::string key;
        key.resize(p.first.length());
        std::transform(p.first.begin(), p.first.end(), key.begin(), ::tolower);
        if (key.compare("content-length") == 0)
        {
            content_length = std::stoull(p.second);
        }
        head_data.append(p.first + ": " + p.second + "\r\n");*/

        head_lists.emplace_back(p.first, p.second);
    }
    this->header_list_.Clear();
    this->current_streamid_ = stream_id;
    this->session_->OnHeadEnd(std::move(head_lists), stream_id);

	
}

void ProtoTest::SqdyFramerVisitror::OnRstStream(SpdyStreamId stream_id, SpdyErrorCode error_code)
{
}

void ProtoTest::SqdyFramerVisitror::OnSetting(SpdySettingsId id, uint32_t value)
{
}

void ProtoTest::SqdyFramerVisitror::OnSettingsEnd()
{
}

void ProtoTest::SqdyFramerVisitror::OnPing(SpdyPingId unique_id, bool is_ack)
{
}

void ProtoTest::SqdyFramerVisitror::OnGoAway(SpdyStreamId last_accepted_stream_id, SpdyErrorCode error_code)
{
}

void ProtoTest::SqdyFramerVisitror::OnHeaders(SpdyStreamId stream_id, size_t payload_length, bool has_priority, int weight, SpdyStreamId parent_stream_id, bool exclusive, bool fin, bool end)
{
}

void ProtoTest::SqdyFramerVisitror::OnWindowUpdate(SpdyStreamId stream_id, int delta_window_size)
{
}

void ProtoTest::SqdyFramerVisitror::OnPushPromise(SpdyStreamId stream_id, SpdyStreamId promised_stream_id, bool end)
{
}

void ProtoTest::SqdyFramerVisitror::OnContinuation(SpdyStreamId stream_id, size_t payload_length, bool end)
{
}

void ProtoTest::SqdyFramerVisitror::OnPriority(SpdyStreamId stream_id, SpdyStreamId parent_stream_id, int weight, bool exclusive)
{
}

void ProtoTest::SqdyFramerVisitror::OnPriorityUpdate(SpdyStreamId prioritized_stream_id, absl::string_view priority_field_value)
{
}

bool ProtoTest::SqdyFramerVisitror::OnUnknownFrame(SpdyStreamId stream_id, uint8_t frame_type)
{
	return false;
}

void ProtoTest::SqdyFramerVisitror::OnUnknownFrameStart(SpdyStreamId stream_id, size_t length, uint8_t type, uint8_t flags)
{
}

void ProtoTest::SqdyFramerVisitror::OnUnknownFramePayload(SpdyStreamId stream_id, absl::string_view payload)
{
}

ProtoTest::SqdyFramerVisitror::~SqdyFramerVisitror()
{
}

spdy::SpdyStreamId ProtoTest::SqdyFramerVisitror::GetCurrentStreamId()
{

	return current_streamid_;
}

ProtoTest::SqdyFramerVisitror::SqdyFramerVisitror(Session* session)
	:spdy::SpdyFramerVisitorInterface(),
	current_streamid_(0),
	header_list_()
{
	this->session_ = session;
}
