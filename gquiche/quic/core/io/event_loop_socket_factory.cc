// Copyright 2022 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "gquiche/quic/core/io/event_loop_socket_factory.h"

#include <memory>

#include "gquiche/quic/core/io/connecting_client_socket.h"
#include "gquiche/quic/core/io/event_loop_tcp_client_socket.h"
#include "gquiche/quic/core/io/quic_event_loop.h"
#include "gquiche/quic/core/quic_types.h"
#include "gquiche/quic/platform/api/quic_socket_address.h"
#include "gquiche/common/platform/api/quiche_logging.h"
#include "gquiche/common/quiche_buffer_allocator.h"

namespace quic {

EventLoopSocketFactory::EventLoopSocketFactory(
    QuicEventLoop* event_loop, quiche::QuicheBufferAllocator* buffer_allocator)
    : event_loop_(event_loop), buffer_allocator_(buffer_allocator) {
  QUICHE_DCHECK(event_loop_);
  QUICHE_DCHECK(buffer_allocator_);
}

std::unique_ptr<ConnectingClientSocket>
EventLoopSocketFactory::CreateTcpClientSocket(
    const quic::QuicSocketAddress& peer_address,
    QuicByteCount receive_buffer_size, QuicByteCount send_buffer_size,
    ConnectingClientSocket::AsyncVisitor* async_visitor) {
  return std::make_unique<EventLoopTcpClientSocket>(
      peer_address, receive_buffer_size, send_buffer_size, event_loop_,
      buffer_allocator_, async_visitor);
}

}  // namespace quic
