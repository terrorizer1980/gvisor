// Copyright 2020 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "test/syscalls/linux/socket_ipv6_udp_unbound_external_networking.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#ifdef __linux__
#include <linux/in6.h>
#endif  //  __linux__
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#include <cstdio>
#include <cstring>

#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "test/syscalls/linux/ip_socket_test_util.h"
#include "test/syscalls/linux/socket_test_util.h"
#include "test/util/posix_error.h"
#include "test/util/save_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

TEST_P(IPv6UDPUnboundExternalNetworkingSocketTest, TestJoinLeaveMulticast) {
  SKIP_IF(!found_net_interfaces_);

  auto sender = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto receiver = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  auto receiver_addr = V6Any();
  ASSERT_THAT(
      bind(receiver->get(), reinterpret_cast<sockaddr*>(&receiver_addr.addr),
           receiver_addr.addr_len),
      SyscallSucceeds());
  socklen_t receiver_addr_len = receiver_addr.addr_len;
  ASSERT_THAT(getsockname(receiver->get(),
                          reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                          &receiver_addr_len),
              SyscallSucceeds());
  EXPECT_EQ(receiver_addr_len, receiver_addr.addr_len);

  // Register to receive multicast packets.
  auto multicast_addr = V6Multicast();
  ipv6_mreq group;
  memcpy(
      &group.ipv6mr_multiaddr,
      reinterpret_cast<sockaddr_in6*>(&multicast_addr.addr)->sin6_addr.s6_addr,
      16);
  ASSERT_THAT(setsockopt(receiver->get(), IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP,
                         &group, sizeof(group)),
              SyscallSucceeds());

  // Send a multicast packet.
  auto send_addr = multicast_addr;
  reinterpret_cast<sockaddr_in6*>(&send_addr.addr)->sin6_port =
      reinterpret_cast<sockaddr_in6*>(&receiver_addr.addr)->sin6_port;
  char send_buf[200];
  RandomizeBuffer(send_buf, sizeof(send_buf));
  ASSERT_THAT(RetryEINTR(sendto)(sender->get(), send_buf, sizeof(send_buf), 0,
                                 reinterpret_cast<sockaddr*>(&send_addr.addr),
                                 send_addr.addr_len),
              SyscallSucceedsWithValue(sizeof(send_buf)));

  // Check that we received the multicast packet.
  char recv_buf[sizeof(send_buf)] = {};
  ASSERT_THAT(RetryEINTR(recv)(receiver->get(), recv_buf, sizeof(recv_buf), 0),
              SyscallSucceedsWithValue(sizeof(recv_buf)));

  EXPECT_EQ(0, memcmp(send_buf, recv_buf, sizeof(send_buf)));
}

}  // namespace testing
}  // namespace gvisor
