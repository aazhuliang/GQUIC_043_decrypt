#pragma once
#include "gquiche/spdy/core/http2_frame_decoder_adapter.h"
#include "gquiche/quic/core/http/quic_header_list.h"
using namespace  http2;
using namespace  spdy;
namespace ProtoTest
{
	class Session;
	class SqdyFramerVisitror : public spdy::SpdyFramerVisitorInterface
	{
	public:
		// Í¨¹ý SpdyFramerVisitorInterface ¼Ì³Ð
		virtual void OnError(http2::Http2DecoderAdapter::SpdyFramerError error, std::string detailed_error) override;
		virtual void OnDataFrameHeader(SpdyStreamId stream_id, size_t length, bool fin) override;
		virtual void OnStreamFrameData(SpdyStreamId stream_id, const char* data, size_t len) override;
		virtual void OnStreamEnd(SpdyStreamId stream_id) override;
		virtual void OnStreamPadding(SpdyStreamId stream_id, size_t len) override;
		virtual SpdyHeadersHandlerInterface* OnHeaderFrameStart(SpdyStreamId stream_id) override;
		virtual void OnHeaderFrameEnd(SpdyStreamId stream_id) override;
		virtual void OnRstStream(SpdyStreamId stream_id, SpdyErrorCode error_code) override;
		virtual void OnSetting(SpdySettingsId id, uint32_t value) override;
		virtual void OnSettingsEnd() override;
		virtual void OnPing(SpdyPingId unique_id, bool is_ack) override;
		virtual void OnGoAway(SpdyStreamId last_accepted_stream_id, SpdyErrorCode error_code) override;
		virtual void OnHeaders(SpdyStreamId stream_id, size_t payload_length, bool has_priority, int weight, SpdyStreamId parent_stream_id, bool exclusive, bool fin, bool end) override;
		virtual void OnWindowUpdate(SpdyStreamId stream_id, int delta_window_size) override;
		virtual void OnPushPromise(SpdyStreamId stream_id, SpdyStreamId promised_stream_id, bool end) override;
		virtual void OnContinuation(SpdyStreamId stream_id, size_t payload_length, bool end) override;
		virtual void OnPriority(SpdyStreamId stream_id, SpdyStreamId parent_stream_id, int weight, bool exclusive) override;
		virtual void OnPriorityUpdate(SpdyStreamId prioritized_stream_id, absl::string_view priority_field_value) override;
		virtual bool OnUnknownFrame(SpdyStreamId stream_id, uint8_t frame_type) override;
		virtual void OnUnknownFrameStart(SpdyStreamId stream_id, size_t length, uint8_t type, uint8_t flags) override;
		virtual void OnUnknownFramePayload(SpdyStreamId stream_id, absl::string_view payload) override;
		~SqdyFramerVisitror() override;
		SqdyFramerVisitror(Session* session);
		spdy::SpdyStreamId GetCurrentStreamId();
	private:
		Session* session_;
		spdy::SpdyStreamId current_streamid_;
		quic::QuicHeaderList header_list_;
	};
}