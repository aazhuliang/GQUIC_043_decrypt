#pragma once
#include "session.h"
#include <memory>
#include "hand_shake_visitor.h"
namespace ProtoTest
{
	class ClientSession : public Session
	{
	public:
		ClientSession() : Session(quic::Perspective::IS_CLIENT)
		{
			current_state_ = Session::State::RECV_REJ;
			client_session_ = this;
		};
		~ClientSession() override;
		void OnHandshakeMessage(const quic::CryptoHandshakeMessage& message) override;
		bool OnCryptoFrame(const quic::QuicStreamFrame& frame) override;
	private:
		
	};
}
