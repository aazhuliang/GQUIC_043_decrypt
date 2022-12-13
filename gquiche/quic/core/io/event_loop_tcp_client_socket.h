// Copyright 2022 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_CORE_IO_EVENT_LOOP_TCP_CLIENT_SOCKET_H_
#define QUICHE_QUIC_CORE_IO_EVENT_LOOP_TCP_CLIENT_SOCKET_H_

#include <string>

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "absl/types/variant.h"
#include "gquiche/quic/core/io/connecting_client_socket.h"
#include "gquiche/quic/core/io/quic_event_loop.h"
#include "gquiche/quic/core/quic_types.h"
#include "gquiche/quic/platform/api/quic_socket_address.h"
#include "gquiche/common/platform/api/quiche_export.h"
#include "gquiche/common/quiche_buffer_allocator.h"

namespace quic {

// A TCP client socket implemented using an underlying QuicEventLoop.
class QUICHE_EXPORT_PRIVATE EventLoopTcpClientSocket
    : public ConnectingClientSocket,
      public QuicSocketEventListener {
 public:
  // Will use platform default buffer size if `receive_buffer_size` or
  // `send_buffer_size` is zero. `async_visitor` may be null if no async
  // operations will be  requested. `event_loop`, `buffer_allocator`, and
  // `async_visitor` (if non-null) must outlive the created socket.
  EventLoopTcpClientSocket(const quic::QuicSocketAddress& peer_address,
                           QuicByteCount receive_buffer_size,
                           QuicByteCount send_buffer_size,
                           QuicEventLoop* event_loop,
                           quiche::QuicheBufferAllocator* buffer_allocator,
                           AsyncVisitor* async_visitor);

  ~EventLoopTcpClientSocket() override;

  // ConnectingClientSocket:
  absl::Status ConnectBlocking() override;
  void ConnectAsync() override;
  void Disconnect() override;
  absl::StatusOr<quiche::QuicheMemSlice> ReceiveBlocking(
      QuicByteCount max_size) override;
  void ReceiveAsync(QuicByteCount max_size) override;
  absl::Status SendBlocking(std::string data) override;
  absl::Status SendBlocking(quiche::QuicheMemSlice data) override;
  void SendAsync(std::string data) override;
  void SendAsync(quiche::QuicheMemSlice data) override;

  // QuicSocketEventListener:
  void OnSocketEvent(QuicEventLoop* event_loop, SocketFd fd,
                     QuicSocketEventMask events) override;

 private:
  enum class ConnectStatus {
    kNotConnected,
    kConnecting,
    kConnected,
  };

  absl::Status Open();
  void Close();
  absl::Status DoInitialConnect();
  absl::Status GetConnectResult();
  void FinishOrRearmAsyncConnect(absl::Status status);
  absl::StatusOr<quiche::QuicheMemSlice> ReceiveInternal();
  void FinishOrRearmAsyncReceive(absl::StatusOr<quiche::QuicheMemSlice> buffer);
  // Returns `true` if a byte received, or `false` if successfully received
  // empty data.
  absl::StatusOr<bool> OneBytePeek();
  absl::Status SendBlockingInternal();
  absl::Status SendInternal();
  void FinishOrRearmAsyncSend(absl::Status status);

  const QuicSocketAddress peer_address_;
  const QuicByteCount receive_buffer_size_;
  const QuicByteCount send_buffer_size_;
  QuicEventLoop* const event_loop_;                  // unowned
  quiche::QuicheBufferAllocator* buffer_allocator_;  // unowned
  AsyncVisitor* const async_visitor_;  // unowned, potentially null

  SocketFd descriptor_ = kInvalidSocketFd;
  ConnectStatus connect_status_ = ConnectStatus::kNotConnected;

  // Only set while receive in progress or pending, otherwise nullopt.
  absl::optional<QuicByteCount> receive_max_size_;

  // Only contains data while send in progress or pending, otherwise monostate.
  absl::variant<absl::monostate, std::string, quiche::QuicheMemSlice>
      send_data_;
  // Points to the unsent portion of `send_data_` while send in progress or
  // pending, otherwise empty.
  absl::string_view send_remaining_;
};

}  // namespace quic

#endif  // QUICHE_QUIC_CORE_IO_EVENT_LOOP_TCP_CLIENT_SOCKET_H_
