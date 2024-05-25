#pragma once
#include "session.h"
#include <memory>




namespace ProtoTest
{
	class ServerSession : public Session
	{
	public:
		ServerSession() ;
		~ServerSession() override;
		void OnHandshakeMessage(const quic::CryptoHandshakeMessage& message) override;
		bool OnCryptoFrame(const quic::QuicStreamFrame& frame) override;

	private:
		
	};
}