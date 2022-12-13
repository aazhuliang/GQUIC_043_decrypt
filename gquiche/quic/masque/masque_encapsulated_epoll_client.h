// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_MASQUE_MASQUE_ENCAPSULATED_EPOLL_CLIENT_H_
#define QUICHE_QUIC_MASQUE_MASQUE_ENCAPSULATED_EPOLL_CLIENT_H_

#include "gquiche/quic/core/io/quic_event_loop.h"
#include "gquiche/quic/masque/masque_encapsulated_client_session.h"
#include "gquiche/quic/masque/masque_epoll_client.h"
#include "gquiche/quic/platform/api/quic_export.h"
#include "gquiche/quic/tools/quic_default_client.h"

namespace quic {

// QUIC client for QUIC encapsulated in MASQUE.
class QUIC_NO_EXPORT MasqueEncapsulatedEpollClient : public QuicDefaultClient {
 public:
  MasqueEncapsulatedEpollClient(QuicSocketAddress server_address,
                                const QuicServerId& server_id,
                                QuicEventLoop* event_loop,
                                std::unique_ptr<ProofVerifier> proof_verifier,
                                MasqueEpollClient* masque_client);
  ~MasqueEncapsulatedEpollClient() override;

  // Disallow copy and assign.
  MasqueEncapsulatedEpollClient(const MasqueEncapsulatedEpollClient&) = delete;
  MasqueEncapsulatedEpollClient& operator=(
      const MasqueEncapsulatedEpollClient&) = delete;

  // From QuicClient.
  std::unique_ptr<QuicSession> CreateQuicClientSession(
      const ParsedQuicVersionVector& supported_versions,
      QuicConnection* connection) override;

  // MASQUE client that this client is encapsulated in.
  MasqueEpollClient* masque_client() { return masque_client_; }

  // Client session for this client.
  MasqueEncapsulatedClientSession* masque_encapsulated_client_session();

 private:
  MasqueEpollClient* masque_client_;  // Unowned.
};

}  // namespace quic

#endif  // QUICHE_QUIC_MASQUE_MASQUE_ENCAPSULATED_EPOLL_CLIENT_H_
