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

package ipv4

import (
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/network/ip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

var _ stack.NetworkEndpointStats = (*Stats)(nil)

// Stats holds the endpoint statistics.
type Stats struct {
	// IP holds the IP statistics of an endpoint.
	IP tcpip.IPStats

	// IGMP holds the IGMP statistics of an endpoint.
	IGMP tcpip.IGMPStats

	// ICMP holds the ICMPv4 statistics of an endpoint.
	ICMP tcpip.ICMPv4Stats
}

// IPStats implements stack.NetworkEndpointStats.
func (s *Stats) IPStats() *tcpip.IPStats {
	return &s.IP
}

type multiCounterStats struct {
	ip   ip.MultiCounterIPStats
	icmp multiCounterICMPv4Stats
	igmp multiCounterIGMPStats
}

type sharedStats struct {
	localStats Stats
	multiCounterStats
}

// LINT.IfChange(multiCounterICMPv4PacketStats)

type multiCounterICMPv4PacketStats struct {
	echo           tcpip.MultiCounterStat
	echoReply      tcpip.MultiCounterStat
	dstUnreachable tcpip.MultiCounterStat
	srcQuench      tcpip.MultiCounterStat
	redirect       tcpip.MultiCounterStat
	timeExceeded   tcpip.MultiCounterStat
	paramProblem   tcpip.MultiCounterStat
	timestamp      tcpip.MultiCounterStat
	timestampReply tcpip.MultiCounterStat
	infoRequest    tcpip.MultiCounterStat
	infoReply      tcpip.MultiCounterStat
}

func (m *multiCounterICMPv4PacketStats) init(a, b *tcpip.ICMPv4PacketStats) {
	m.echo.Init(a.Echo, b.Echo)
	m.echoReply.Init(a.EchoReply, b.EchoReply)
	m.dstUnreachable.Init(a.DstUnreachable, b.DstUnreachable)
	m.srcQuench.Init(a.SrcQuench, b.SrcQuench)
	m.redirect.Init(a.Redirect, b.Redirect)
	m.timeExceeded.Init(a.TimeExceeded, b.TimeExceeded)
	m.paramProblem.Init(a.ParamProblem, b.ParamProblem)
	m.timestamp.Init(a.Timestamp, b.Timestamp)
	m.timestampReply.Init(a.TimestampReply, b.TimestampReply)
	m.infoRequest.Init(a.InfoRequest, b.InfoRequest)
	m.infoReply.Init(a.InfoReply, b.InfoReply)
}

// LINT.ThenChange(../../tcpip.go:ICMPv4PacketStats)

// LINT.IfChange(multiCounterICMPv4SentPacketStats)

type multiCounterICMPv4SentPacketStats struct {
	multiCounterICMPv4PacketStats
	dropped     tcpip.MultiCounterStat
	rateLimited tcpip.MultiCounterStat
}

func (m *multiCounterICMPv4SentPacketStats) init(a, b *tcpip.ICMPv4SentPacketStats) {
	m.multiCounterICMPv4PacketStats.init(&a.ICMPv4PacketStats, &b.ICMPv4PacketStats)
	m.dropped.Init(a.Dropped, b.Dropped)
	m.rateLimited.Init(a.RateLimited, b.RateLimited)
}

// LINT.ThenChange(../../tcpip.go:ICMPv4SentPacketStats)

// LINT.IfChange(multiCounterICMPv4ReceivedPacketStats)

type multiCounterICMPv4ReceivedPacketStats struct {
	multiCounterICMPv4PacketStats
	invalid tcpip.MultiCounterStat
}

func (m *multiCounterICMPv4ReceivedPacketStats) init(a, b *tcpip.ICMPv4ReceivedPacketStats) {
	m.multiCounterICMPv4PacketStats.init(&a.ICMPv4PacketStats, &b.ICMPv4PacketStats)
	m.invalid.Init(a.Invalid, b.Invalid)
}

// LINT.ThenChange(../../tcpip.go:ICMPv4ReceivedPacketStats)

// LINT.IfChange(multiCounterICMPv4Stats)

type multiCounterICMPv4Stats struct {
	packetsSent     multiCounterICMPv4SentPacketStats
	packetsReceived multiCounterICMPv4ReceivedPacketStats
}

func (m *multiCounterICMPv4Stats) init(a, b *tcpip.ICMPv4Stats) {
	m.packetsSent.init(&a.PacketsSent, &b.PacketsSent)
	m.packetsReceived.init(&a.PacketsReceived, &b.PacketsReceived)
}

// LINT.ThenChange(../../tcpip.go:ICMPv4Stats)

// LINT.IfChange(multiCounterIGMPPacketStats)

type multiCounterIGMPPacketStats struct {
	membershipQuery    tcpip.MultiCounterStat
	v1MembershipReport tcpip.MultiCounterStat
	v2MembershipReport tcpip.MultiCounterStat
	leaveGroup         tcpip.MultiCounterStat
}

func (m *multiCounterIGMPPacketStats) init(a, b *tcpip.IGMPPacketStats) {
	m.membershipQuery.Init(a.MembershipQuery, b.MembershipQuery)
	m.v1MembershipReport.Init(a.V1MembershipReport, b.V1MembershipReport)
	m.v2MembershipReport.Init(a.V2MembershipReport, b.V2MembershipReport)
	m.leaveGroup.Init(a.LeaveGroup, b.LeaveGroup)
}

// LINT.ThenChange(../../tcpip.go:IGMPPacketStats)

// LINT.IfChange(multiCounterIGMPSentPacketStats)

type multiCounterIGMPSentPacketStats struct {
	multiCounterIGMPPacketStats
	dropped tcpip.MultiCounterStat
}

func (m *multiCounterIGMPSentPacketStats) init(a, b *tcpip.IGMPSentPacketStats) {
	m.multiCounterIGMPPacketStats.init(&a.IGMPPacketStats, &b.IGMPPacketStats)
	m.dropped.Init(a.Dropped, b.Dropped)
}

// LINT.ThenChange(../../tcpip.go:IGMPSentPacketStats)

// LINT.IfChange(multiCounterIGMPReceivedPacketStats)

type multiCounterIGMPReceivedPacketStats struct {
	multiCounterIGMPPacketStats
	invalid        tcpip.MultiCounterStat
	checksumErrors tcpip.MultiCounterStat
	unrecognized   tcpip.MultiCounterStat
}

func (m *multiCounterIGMPReceivedPacketStats) init(a, b *tcpip.IGMPReceivedPacketStats) {
	m.multiCounterIGMPPacketStats.init(&a.IGMPPacketStats, &b.IGMPPacketStats)
	m.invalid.Init(a.Invalid, b.Invalid)
	m.checksumErrors.Init(a.ChecksumErrors, b.ChecksumErrors)
	m.unrecognized.Init(a.Unrecognized, b.Unrecognized)
}

// LINT.ThenChange(../../tcpip.go:IGMPReceivedPacketStats)

// LINT.IfChange(multiCounterIGMPStats)

type multiCounterIGMPStats struct {
	packetsSent     multiCounterIGMPSentPacketStats
	packetsReceived multiCounterIGMPReceivedPacketStats
}

func (m *multiCounterIGMPStats) init(a, b *tcpip.IGMPStats) {
	m.packetsSent.init(&a.PacketsSent, &b.PacketsSent)
	m.packetsReceived.init(&a.PacketsReceived, &b.PacketsReceived)
}

// LINT.ThenChange(../../tcpip.go:IGMPStats)
