// Copyright 2022 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_CORE_IO_EVENT_LOOP_SOCKET_FACTORY_H_
#define QUICHE_QUIC_CORE_IO_EVENT_LOOP_SOCKET_FACTORY_H_

#include <memory>

#include "gquiche/quic/core/io/connecting_client_socket.h"
#include "gquiche/quic/core/io/quic_event_loop.h"
#include "gquiche/quic/core/io/socket_factory.h"
#include "gquiche/quic/core/quic_types.h"
#include "gquiche/quic/platform/api/quic_socket_address.h"
#include "gquiche/common/platform/api/quiche_export.h"
#include "gquiche/common/quiche_buffer_allocator.h"

namespace quic {

// A socket factory that creates sockets implemented using an underlying
// QuicEventLoop.
class QUICHE_EXPORT_PRIVATE EventLoopSocketFactory : public SocketFactory {
 public:
  // `event_loop` and `buffer_allocator` must outlive the created factory.
  EventLoopSocketFactory(QuicEventLoop* event_loop,
                         quiche::QuicheBufferAllocator* buffer_allocator);

  // SocketFactory:
  std::unique_ptr<ConnectingClientSocket> CreateTcpClientSocket(
      const quic::QuicSocketAddress& peer_address,
      QuicByteCount receive_buffer_size, QuicByteCount send_buffer_size,
      ConnectingClientSocket::AsyncVisitor* async_visitor) override;

 private:
  QuicEventLoop* const event_loop_;                  // unowned
  quiche::QuicheBufferAllocator* buffer_allocator_;  // unowned
};

}  // namespace quic

#endif  // QUICHE_QUIC_CORE_IO_EVENT_LOOP_SOCKET_FACTORY_H_
