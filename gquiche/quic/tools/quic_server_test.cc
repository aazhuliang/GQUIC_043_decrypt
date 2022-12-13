// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "gquiche/quic/tools/quic_server.h"

#include <memory>

#include "absl/base/macros.h"
#include "gquiche/quic/core/crypto/quic_random.h"
#include "gquiche/quic/core/deterministic_connection_id_generator.h"
#include "gquiche/quic/core/io/quic_default_event_loop.h"
#include "gquiche/quic/core/io/quic_event_loop.h"
#include "gquiche/quic/core/quic_default_clock.h"
#include "gquiche/quic/core/quic_default_connection_helper.h"
#include "gquiche/quic/core/quic_default_packet_writer.h"
#include "gquiche/quic/core/quic_utils.h"
#include "gquiche/quic/platform/api/quic_flags.h"
#include "gquiche/quic/platform/api/quic_logging.h"
#include "gquiche/quic/platform/api/quic_socket_address.h"
#include "gquiche/quic/platform/api/quic_test.h"
#include "gquiche/quic/platform/api/quic_test_loopback.h"
#include "gquiche/quic/test_tools/crypto_test_utils.h"
#include "gquiche/quic/test_tools/mock_quic_dispatcher.h"
#include "gquiche/quic/test_tools/quic_server_peer.h"
#include "gquiche/quic/tools/quic_memory_cache_backend.h"
#include "gquiche/quic/tools/quic_simple_crypto_server_stream_helper.h"

namespace quic {
namespace test {

using ::testing::_;

namespace {

class MockQuicSimpleDispatcher : public QuicSimpleDispatcher {
 public:
  MockQuicSimpleDispatcher(
      const QuicConfig* config, const QuicCryptoServerConfig* crypto_config,
      QuicVersionManager* version_manager,
      std::unique_ptr<QuicConnectionHelperInterface> helper,
      std::unique_ptr<QuicCryptoServerStreamBase::Helper> session_helper,
      std::unique_ptr<QuicAlarmFactory> alarm_factory,
      QuicSimpleServerBackend* quic_simple_server_backend,
      ConnectionIdGeneratorInterface& generator)
      : QuicSimpleDispatcher(config, crypto_config, version_manager,
                             std::move(helper), std::move(session_helper),
                             std::move(alarm_factory),
                             quic_simple_server_backend,
                             kQuicDefaultConnectionIdLength, generator) {}
  ~MockQuicSimpleDispatcher() override = default;

  MOCK_METHOD(void, OnCanWrite, (), (override));
  MOCK_METHOD(bool, HasPendingWrites, (), (const, override));
  MOCK_METHOD(bool, HasChlosBuffered, (), (const, override));
  MOCK_METHOD(void, ProcessBufferedChlos, (size_t), (override));
};

class TestQuicServer : public QuicServer {
 public:
  explicit TestQuicServer(QuicEventLoopFactory* event_loop_factory,
                          QuicMemoryCacheBackend* quic_simple_server_backend)
      : QuicServer(crypto_test_utils::ProofSourceForTesting(),
                   quic_simple_server_backend),
        quic_simple_server_backend_(quic_simple_server_backend),
        event_loop_factory_(event_loop_factory) {}

  ~TestQuicServer() override = default;

  MockQuicSimpleDispatcher* mock_dispatcher() { return mock_dispatcher_; }

 protected:
  QuicDispatcher* CreateQuicDispatcher() override {
    mock_dispatcher_ = new MockQuicSimpleDispatcher(
        &config(), &crypto_config(), version_manager(),
        std::make_unique<QuicDefaultConnectionHelper>(),
        std::unique_ptr<QuicCryptoServerStreamBase::Helper>(
            new QuicSimpleCryptoServerStreamHelper()),
        event_loop()->CreateAlarmFactory(), quic_simple_server_backend_,
        connection_id_generator());
    return mock_dispatcher_;
  }

  std::unique_ptr<QuicEventLoop> CreateEventLoop() override {
    return event_loop_factory_->Create(QuicDefaultClock::Get());
  }

  MockQuicSimpleDispatcher* mock_dispatcher_ = nullptr;
  QuicMemoryCacheBackend* quic_simple_server_backend_;
  QuicEventLoopFactory* event_loop_factory_;
};

class QuicServerEpollInTest : public QuicTestWithParam<QuicEventLoopFactory*> {
 public:
  QuicServerEpollInTest()
      : server_address_(TestLoopback(), 0),
        server_(GetParam(), &quic_simple_server_backend_) {}

  void StartListening() {
    server_.CreateUDPSocketAndListen(server_address_);
    server_address_ = QuicSocketAddress(server_address_.host(), server_.port());

    ASSERT_TRUE(QuicServerPeer::SetSmallSocket(&server_));

    if (!server_.overflow_supported()) {
      QUIC_LOG(WARNING) << "Overflow not supported.  Not testing.";
      return;
    }
  }

 protected:
  QuicSocketAddress server_address_;
  QuicMemoryCacheBackend quic_simple_server_backend_;
  TestQuicServer server_;
};

std::string GetTestParamName(
    ::testing::TestParamInfo<QuicEventLoopFactory*> info) {
  return EscapeTestParamName(info.param->GetName());
}

INSTANTIATE_TEST_SUITE_P(QuicServerEpollInTests, QuicServerEpollInTest,
                         ::testing::ValuesIn(GetAllSupportedEventLoops()),
                         GetTestParamName);

// Tests that if dispatcher has CHLOs waiting for connection creation, EPOLLIN
// event should try to create connections for them. And set epoll mask with
// EPOLLIN if there are still CHLOs remaining at the end of epoll event.
TEST_P(QuicServerEpollInTest, ProcessBufferedCHLOsOnEpollin) {
  // Given an EPOLLIN event, try to create session for buffered CHLOs. In first
  // event, dispatcher can't create session for all of CHLOs. So listener should
  // register another EPOLLIN event by itself. Even without new packet arrival,
  // the rest CHLOs should be process in next epoll event.
  StartListening();
  bool more_chlos = true;
  MockQuicSimpleDispatcher* dispatcher_ = server_.mock_dispatcher();
  QUICHE_DCHECK(dispatcher_ != nullptr);
  EXPECT_CALL(*dispatcher_, OnCanWrite()).Times(testing::AnyNumber());
  EXPECT_CALL(*dispatcher_, ProcessBufferedChlos(_)).Times(2);
  EXPECT_CALL(*dispatcher_, HasPendingWrites()).Times(testing::AnyNumber());
  // Expect there are still CHLOs buffered after 1st event. But not any more
  // after 2nd event.
  EXPECT_CALL(*dispatcher_, HasChlosBuffered())
      .WillOnce(testing::Return(true))
      .WillOnce(
          DoAll(testing::Assign(&more_chlos, false), testing::Return(false)));

  // Send a packet to trigger epoll event.
  int fd = socket(
      AddressFamilyUnderTest() == IpAddressFamily::IP_V4 ? AF_INET : AF_INET6,
      SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);
  ASSERT_LT(0, fd);

  char buf[1024];
  memset(buf, 0, ABSL_ARRAYSIZE(buf));
  sockaddr_storage storage = server_address_.generic_address();
  int rc = sendto(fd, buf, ABSL_ARRAYSIZE(buf), 0,
                  reinterpret_cast<sockaddr*>(&storage), sizeof(storage));
  if (rc < 0) {
    QUIC_DLOG(INFO) << errno << " " << strerror(errno);
  }

  while (more_chlos) {
    server_.WaitForEvents();
  }
}

class QuicServerDispatchPacketTest : public QuicTest {
 public:
  QuicServerDispatchPacketTest()
      : crypto_config_("blah", QuicRandom::GetInstance(),
                       crypto_test_utils::ProofSourceForTesting(),
                       KeyExchangeSource::Default()),
        version_manager_(AllSupportedVersions()),
        event_loop_(GetDefaultEventLoop()->Create(QuicDefaultClock::Get())),
        connection_id_generator_(kQuicDefaultConnectionIdLength),
        dispatcher_(&config_, &crypto_config_, &version_manager_,
                    std::make_unique<QuicDefaultConnectionHelper>(),
                    std::make_unique<QuicSimpleCryptoServerStreamHelper>(),
                    event_loop_->CreateAlarmFactory(),
                    &quic_simple_server_backend_, connection_id_generator_) {
    dispatcher_.InitializeWithWriter(new QuicDefaultPacketWriter(1234));
  }

  void DispatchPacket(const QuicReceivedPacket& packet) {
    QuicSocketAddress client_addr, server_addr;
    dispatcher_.ProcessPacket(server_addr, client_addr, packet);
  }

 protected:
  QuicConfig config_;
  QuicCryptoServerConfig crypto_config_;
  QuicVersionManager version_manager_;
  std::unique_ptr<QuicEventLoop> event_loop_;
  QuicMemoryCacheBackend quic_simple_server_backend_;
  DeterministicConnectionIdGenerator connection_id_generator_;
  MockQuicDispatcher dispatcher_;
};

TEST_F(QuicServerDispatchPacketTest, DispatchPacket) {
  // clang-format off
  unsigned char valid_packet[] = {
    // public flags (8 byte connection_id)
    0x3C,
    // connection_id
    0x10, 0x32, 0x54, 0x76,
    0x98, 0xBA, 0xDC, 0xFE,
    // packet number
    0xBC, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // private flags
    0x00
  };
  // clang-format on
  QuicReceivedPacket encrypted_valid_packet(
      reinterpret_cast<char*>(valid_packet), ABSL_ARRAYSIZE(valid_packet),
      QuicTime::Zero(), false);

  EXPECT_CALL(dispatcher_, ProcessPacket(_, _, _)).Times(1);
  DispatchPacket(encrypted_valid_packet);
}

}  // namespace
}  // namespace test
}  // namespace quic
