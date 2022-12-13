// Copyright (c) 2022 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// A Connection ID generator that generates deterministic connection IDs for
// QUIC servers.

#ifndef QUICHE_QUIC_CORE_CONNECTION_ID_GENERATOR_DETERMINISTIC_H_
#define QUICHE_QUIC_CORE_CONNECTION_ID_GENERATOR_DETERMINISTIC_H_

#include "gquiche/quic/core/connection_id_generator.h"

namespace quic {

// Generates connection IDs deterministically from the provided original
// connection ID.
class QUIC_EXPORT_PRIVATE DeterministicConnectionIdGenerator
    : public ConnectionIdGeneratorInterface {
 public:
  DeterministicConnectionIdGenerator(uint8_t expected_connection_id_length);

  // Hashes |original| to create a new connection ID.
  absl::optional<QuicConnectionId> GenerateNextConnectionId(
      const QuicConnectionId& original) override;
  // Replace the connection ID if and only if |original| is not of the expected
  // length.
  absl::optional<QuicConnectionId> MaybeReplaceConnectionId(
      const QuicConnectionId& original,
      const ParsedQuicVersion& version) override;

 private:
  const uint8_t expected_connection_id_length_;
};

}  // namespace quic

#endif  // QUICHE_QUIC_CORE__CONNECTION_ID_GENERATOR_DETERMINISTIC_H_
