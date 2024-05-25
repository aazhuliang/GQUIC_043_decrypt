#pragma once
#include "gquiche/quic/core/quic_framer.h"
#include "gquiche/quic/core/quic_types.h"
#include "gquiche/quic/core/quic_utils.h"
#include "gquiche/quic/platform/api/quic_flags.h"
#include "gquiche/common/quiche_text_utils.h"



namespace ProtoTest
{
    using namespace quic;
    class Session;
    class QuicPacketPrinter : public QuicFramerVisitorInterface {
    public:
        explicit QuicPacketPrinter(QuicFramer* framer, Session* session) : framer_(framer), session_(session) {};
        virtual ~QuicPacketPrinter() = default;
        inline Session* Getsession()
        {
            return this->session_;
        }
        void OnError(QuicFramer* framer) override {
            std::cerr << "OnError: " << QuicErrorCodeToString(framer->error())
                << " detail: " << framer->detailed_error() << "\n";
        }
        bool OnProtocolVersionMismatch(ParsedQuicVersion received_version) override {
            framer_->set_version(received_version);
            std::cerr << "OnProtocolVersionMismatch: "
                << ParsedQuicVersionToString(received_version) << "\n";
            return true;
        }
        void OnPacket() override { //std::cerr << "OnPacket\n"; 
        }
        void OnPublicResetPacket(const QuicPublicResetPacket& /*packet*/) override {
            std::cerr << "OnPublicResetPacket\n";
        }
        void OnVersionNegotiationPacket(
            const QuicVersionNegotiationPacket& /*packet*/) override {
            std::cerr << "OnVersionNegotiationPacket\n";
        }
        void OnRetryPacket(QuicConnectionId /*original_connection_id*/,
            QuicConnectionId /*new_connection_id*/,
            absl::string_view /*retry_token*/,
            absl::string_view /*retry_integrity_tag*/,
            absl::string_view /*retry_without_tag*/) override {
            std::cerr << "OnRetryPacket\n";
        }
        bool OnUnauthenticatedPublicHeader(
            const QuicPacketHeader& /*header*/) override {
           // std::cerr << "OnUnauthenticatedPublicHeader\n";
            return true;
        }
        bool OnUnauthenticatedHeader(const QuicPacketHeader& header) override {
           // std::cerr << "OnUnauthenticatedHeader: " << header;
            return true;
        }
        void OnDecryptedPacket(size_t /*length*/, EncryptionLevel level) override {
            // This only currently supports "decrypting" null encrypted packets.
            //QUICHE_DCHECK_EQ(ENCRYPTION_INITIAL, level);
            //std::cerr << "OnDecryptedPacket\n";
        }
        bool OnPacketHeader(const QuicPacketHeader& /*header*/) override {
            //std::cerr << "OnPacketHeader\n";
            return true;
        }
        void OnCoalescedPacket(const QuicEncryptedPacket& /*packet*/) override {
            std::cerr << "OnCoalescedPacket\n";
        }
        void OnUndecryptablePacket(const QuicEncryptedPacket& /*packet*/,
            EncryptionLevel /*decryption_level*/,
            bool /*has_decryption_key*/) override {
            
            std::cerr << "OnUndecryptablePacket\n";
            assert(false);
        }
        bool OnStreamFrame(const QuicStreamFrame& frame) override {
            /*std::cerr << "OnStreamFrame: " << frame;
            std::cerr << "         data: { "
                << absl::BytesToHexString(
                    absl::string_view(frame.data_buffer, frame.data_length))
                << " }\n";*/
            return true;
        }
        bool OnCryptoFrame(const QuicCryptoFrame& frame) override {
            /*std::cerr << "OnCryptoFrame: " << frame;
            std::cerr << "         data: { "
                << absl::BytesToHexString(
                    absl::string_view(frame.data_buffer, frame.data_length))
                << " }\n";*/
            return true;
        }
        bool OnAckFrameStart(QuicPacketNumber largest_acked,
            QuicTime::Delta /*ack_delay_time*/) override {
            //std::cerr << "OnAckFrameStart, largest_acked: " << largest_acked;
            return true;
        }
        bool OnAckRange(QuicPacketNumber start, QuicPacketNumber end) override {
            //std::cerr << "OnAckRange: [" << start << ", " << end << "]";
            return true;
        }
        bool OnAckTimestamp(QuicPacketNumber packet_number,
            QuicTime timestamp) override {
            //std::cerr << "OnAckTimestamp: [" << packet_number << ", "
            //    << timestamp.ToDebuggingValue() << ")";
            return true;
        }
        bool OnAckFrameEnd(QuicPacketNumber start) override {
            //std::cerr << "OnAckFrameEnd, start: " << start;
            return true;
        }
        bool OnStopWaitingFrame(const QuicStopWaitingFrame& frame) override {
            //std::cerr << "OnStopWaitingFrame: " << frame;
            return true;
        }
        bool OnPaddingFrame(const QuicPaddingFrame& frame) override {
            //std::cerr << "OnPaddingFrame: " << frame;
            return true;
        }
        bool OnPingFrame(const QuicPingFrame& frame) override {
            std::cerr << "OnPingFrame: " << frame;
            return true;
        }
        bool OnRstStreamFrame(const QuicRstStreamFrame& frame) override {
            std::cerr << "OnRstStreamFrame: " << frame;
            return true;
        }
        bool OnConnectionCloseFrame(const QuicConnectionCloseFrame& frame) override {
            // The frame printout will indicate whether it's a Google QUIC
            // CONNECTION_CLOSE, IETF QUIC CONNECTION_CLOSE/Transport, or IETF QUIC
            // CONNECTION_CLOSE/Application frame.
            std::cerr << "OnConnectionCloseFrame: " << frame;
            return true;
        }
        bool OnNewConnectionIdFrame(const QuicNewConnectionIdFrame& frame) override {
            std::cerr << "OnNewConnectionIdFrame: " << frame;
            return true;
        }
        bool OnRetireConnectionIdFrame(
            const QuicRetireConnectionIdFrame& frame) override {
            std::cerr << "OnRetireConnectionIdFrame: " << frame;
            return true;
        }
        bool OnNewTokenFrame(const QuicNewTokenFrame& frame) override {
            std::cerr << "OnNewTokenFrame: " << frame;
            return true;
        }
        bool OnStopSendingFrame(const QuicStopSendingFrame& frame) override {
            std::cerr << "OnStopSendingFrame: " << frame;
            return true;
        }
        bool OnPathChallengeFrame(const QuicPathChallengeFrame& frame) override {
            std::cerr << "OnPathChallengeFrame: " << frame;
            return true;
        }
        bool OnPathResponseFrame(const QuicPathResponseFrame& frame) override {
            std::cerr << "OnPathResponseFrame: " << frame;
            return true;
        }
        bool OnGoAwayFrame(const QuicGoAwayFrame& frame) override {
            std::cerr << "OnGoAwayFrame: " << frame;
            return true;
        }
        bool OnMaxStreamsFrame(const QuicMaxStreamsFrame& frame) override {
            std::cerr << "OnMaxStreamsFrame: " << frame;
            return true;
        }
        bool OnStreamsBlockedFrame(const QuicStreamsBlockedFrame& frame) override {
            std::cerr << "OnStreamsBlockedFrame: " << frame;
            return true;
        }
        bool OnWindowUpdateFrame(const QuicWindowUpdateFrame& frame) override {
            //std::cerr << "OnWindowUpdateFrame: " << frame;
            return true;
        }
        bool OnBlockedFrame(const QuicBlockedFrame& frame) override {
            std::cerr << "OnBlockedFrame: " << frame;
            return true;
        }
        bool OnMessageFrame(const QuicMessageFrame& frame) override {
            std::cerr << "OnMessageFrame: " << frame;
            return true;
        }
        bool OnHandshakeDoneFrame(const QuicHandshakeDoneFrame& frame) override {
            std::cerr << "OnHandshakeDoneFrame: " << frame;
            return true;
        }
        bool OnAckFrequencyFrame(const QuicAckFrequencyFrame& frame) override {
            std::cerr << "OnAckFrequencyFrame: " << frame;
            return true;
        }
        void OnPacketComplete() override { //std::cerr << "OnPacketComplete\n";
        }
        bool IsValidStatelessResetToken(
            const StatelessResetToken& /*token*/) const override {
            std::cerr << "IsValidStatelessResetToken\n";
            return false;
        }
        void OnAuthenticatedIetfStatelessResetPacket(
            const QuicIetfStatelessResetPacket& /*packet*/) override {
            std::cerr << "OnAuthenticatedIetfStatelessResetPacket\n";
        }
        void OnKeyUpdate(KeyUpdateReason reason) override {
            std::cerr << "OnKeyUpdate: " << reason << "\n";
        }
        void OnDecryptedFirstPacketInKeyPhase() override {
            std::cerr << "OnDecryptedFirstPacketInKeyPhase\n";
        }
        std::unique_ptr<QuicDecrypter> AdvanceKeysAndCreateCurrentOneRttDecrypter()
            override {
            std::cerr << "AdvanceKeysAndCreateCurrentOneRttDecrypter\n";
            return nullptr;
        }
        std::unique_ptr<QuicEncrypter> CreateCurrentOneRttEncrypter() override {
            std::cerr << "CreateCurrentOneRttEncrypter\n";
            return nullptr;
        }

    protected:
        QuicFramer* framer_;  // Unowned.
        Session* session_;
    };

}
