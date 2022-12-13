// Copyright 2022 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_CORE_QUIC_DEFAULT_CLOCK_H_
#define QUICHE_QUIC_CORE_QUIC_DEFAULT_CLOCK_H_

#include "gquiche/quic/core/quic_clock.h"
#include "gquiche/quic/core/quic_time.h"
#include "gquiche/quic/platform/api/quic_export.h"

namespace quic {

// A QuicClock based on Abseil time API.  Thread-safe.
class QUIC_EXPORT_PRIVATE QuicDefaultClock : public QuicClock {
 public:
  // Provides a single default stateless instance of QuicDefaultClock.
  static QuicDefaultClock* Get();

  explicit QuicDefaultClock() = default;
  QuicDefaultClock(const QuicDefaultClock&) = delete;
  QuicDefaultClock& operator=(const QuicDefaultClock&) = delete;

  // QuicClock implementation.
  QuicTime ApproximateNow() const override;
  QuicTime Now() const override;
  QuicWallTime WallNow() const override;
  QuicTime ConvertWallTimeToQuicTime(
      const QuicWallTime& walltime) const override;
};

}  // namespace quic

#endif  // QUICHE_QUIC_CORE_QUIC_DEFAULT_CLOCK_H_
