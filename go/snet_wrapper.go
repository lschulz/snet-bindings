// Copyright 2024 Lars-Christian Schulz
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

// #cgo CFLAGS: -I../include
// #include "snet/snet_cdefs.h"
// #include <stdlib.h>
// #include <string.h>
import "C"

import (
	"context"
	"net"
	"net/netip"
	"runtime/cgo"
	"time"
	"unsafe"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/path"
	snetpath "github.com/scionproto/scion/pkg/snet/path"
	"github.com/scionproto/scion/private/topology/underlay"
)

//////////////////////////
// Cgo Helper Functions //
//////////////////////////

// Copy a Go string into a fixed size char buffer including a null terminator.
func copyToCString(dst *C.char, src string, capacity int) {
	n := min(capacity, len(src)+1)
	if n == 0 {
		return
	}

	str := (*[1 << 30]C.char)(unsafe.Pointer(dst))
	for i, r := range src[:n-1] {
		str[i] = C.char(r)
	}
	str[n] = 0
}

func hostAddrToSlice(addr *C.struct_ScHostAddr) net.IP {
	ip := net.IP{}
	if addr._type == C.SC_ADDR_TYPE_IPV4 {
		ip = make(net.IP, 4)
		C.memcpy(unsafe.Pointer(&ip[0]), unsafe.Pointer(&addr.ip[0]), 4)
	} else if addr._type == C.SC_ADDR_TYPE_IPV6 {
		ip = make(net.IP, 16)
		C.memcpy(unsafe.Pointer(&ip[0]), unsafe.Pointer(&addr.ip[0]), 16)
	}
	return ip
}

func hostAddrtoNetipAddr(addr *C.struct_ScHostAddr) netip.Addr {
	if addr._type == C.SC_ADDR_TYPE_IPV4 {
		return netip.AddrFrom4(([4]byte)(hostAddrToSlice(addr)))
	} else if addr._type == C.SC_ADDR_TYPE_IPV6 {
		return netip.AddrFrom16(([16]byte)(hostAddrToSlice(addr)))
	} else {
		return netip.Addr{}
	}
}

func hostAddrfromNetipAddr(addr netip.Addr) C.struct_ScHostAddr {
	host := C.struct_ScHostAddr{}
	if addr.Is4() {
		host._type = C.SC_ADDR_TYPE_IPV4
	} else {
		host._type = C.SC_ADDR_TYPE_IPV6
		copyToCString(&host.zone[0], addr.Zone(), C.SC_IP_ZONE_ID_MAX_LEN)
	}
	copy(unsafe.Slice((*byte)(&host.ip[0]), 16), addr.AsSlice())
	return host
}

func udpAddrtoNetAddr(addr *C.struct_ScLocalUDPAddr) *net.UDPAddr {
	return &net.UDPAddr{
		IP:   hostAddrToSlice(&addr.host),
		Port: int(addr.port),
		Zone: C.GoString(&addr.host.zone[0]),
	}
}

func udpAddrfromNetUDPAddr(addr *net.UDPAddr) C.struct_ScLocalUDPAddr {
	res := C.struct_ScLocalUDPAddr{
		host: C.struct_ScHostAddr{},
		port: C.ScPort(addr.Port),
	}

	if v4 := addr.IP.To4(); v4 != nil {
		res.host._type = C.SC_ADDR_TYPE_IPV4
		C.memcpy(unsafe.Pointer(&res.host.ip), unsafe.Pointer(&v4[0]), 4)
	} else if v6 := addr.IP.To16(); v6 != nil {
		res.host._type = C.SC_ADDR_TYPE_IPV6
		C.memcpy(unsafe.Pointer(&res.host.ip), unsafe.Pointer(&v6[0]), 16)
		copyToCString(&res.host.zone[0], addr.Zone, C.SC_IP_ZONE_ID_MAX_LEN)
	} else {
		return C.struct_ScLocalUDPAddr{}
	}

	return res
}

///////////////
// Addresses //
///////////////

//export ScParseLocalUDPAddr
func ScParseLocalUDPAddr(str *C.cchar, addr *C.struct_ScLocalUDPAddr) C.ScStatus {
	ip, err := netip.ParseAddrPort(C.GoString(str))
	if err != nil {
		return C.SC_ERROR_FAILED
	}
	addr.host = hostAddrfromNetipAddr(ip.Addr())
	addr.port = C.ScPort(ip.Port())
	return C.SC_SUCCESS
}

//export ScParseLocalUDPAddrN
func ScParseLocalUDPAddrN(str *C.cchar, length C.int, addr *C.struct_ScLocalUDPAddr) C.ScStatus {
	ip, err := netip.ParseAddrPort(C.GoStringN(str, length))
	if err != nil {
		return C.SC_ERROR_FAILED
	}
	addr.host = hostAddrfromNetipAddr(ip.Addr())
	addr.port = C.ScPort(ip.Port())
	return C.SC_SUCCESS
}

//export ScFormatLocalUDPAddr
func ScFormatLocalUDPAddr(addr C.ConstPtrScLocalUDPAddr, str *C.char, cap *C.ScSize) C.ScStatus {
	ip := netip.AddrPortFrom(hostAddrtoNetipAddr(&addr.host), uint16(addr.port))
	ipstr := ip.String()
	if len(ipstr)+1 <= int(*cap) {
		slice := unsafe.Slice(str, *cap)
		for i, c := range ipstr {
			slice[i] = C.char(c)
		}
		slice[len(ipstr)] = 0
		return C.SC_SUCCESS
	} else {
		*cap = C.ScSize(len(ipstr) + 1)
		return C.SC_ERROR_BUFFER_INSUFFICIENT
	}
}

//export ScParseUDPAddr
func ScParseUDPAddr(str *C.cchar, udp *C.struct_ScUDPAddr) C.ScStatus {
	addr, err := snet.ParseUDPAddr(C.GoString(str))
	if err != nil {
		return C.SC_ERROR_INVALID_ARG
	}
	udp.ia = C.ScIA(addr.IA)
	udp.local = udpAddrfromNetUDPAddr(addr.Host)
	return C.SC_SUCCESS
}

//export ScParseUDPAddrN
func ScParseUDPAddrN(str *C.cchar, length C.int, udp *C.struct_ScUDPAddr) C.ScStatus {
	addr, err := snet.ParseUDPAddr(C.GoStringN(str, length))
	if err != nil {
		return C.SC_ERROR_INVALID_ARG
	}
	udp.ia = C.ScIA(addr.IA)
	udp.local = udpAddrfromNetUDPAddr(addr.Host)
	return C.SC_SUCCESS
}

//export ScFormatUDPAddr
func ScFormatUDPAddr(udp C.ConstPtrScUDPAddr, str *C.char, length *C.ScSize) C.ScStatus {
	// Let snet format the address
	addr := snet.UDPAddr{
		IA: addr.IA(udp.ia),
		Host: &net.UDPAddr{
			Port: int(udp.local.port),
			Zone: C.GoString(&udp.local.host.zone[0]),
		},
	}
	if udp.local.host._type == C.SC_ADDR_TYPE_IPV4 {
		addr.Host.IP = make(net.IP, 4)
		C.memcpy(unsafe.Pointer(&addr.Host.IP[0]), unsafe.Pointer(&udp.local.host.ip[0]), 4)
	} else if udp.local.host._type == C.SC_ADDR_TYPE_IPV6 {
		addr.Host.IP = make(net.IP, 16)
		C.memcpy(unsafe.Pointer(&addr.Host.IP[0]), unsafe.Pointer(&udp.local.host.ip[0]), 16)
	} else {
		return C.SC_ERROR_INVALID_ARG
	}
	strAddr := addr.String()

	if len(strAddr)+1 <= int(*length) {
		slice := unsafe.Slice(str, int(*length))
		for i, c := range strAddr {
			slice[i] = C.char(c)
		}
		slice[len(strAddr)] = 0
		return C.SC_SUCCESS
	} else {
		*length = (C.ScSize)(len(strAddr) + 1)
		return C.SC_ERROR_BUFFER_INSUFFICIENT
	}
}

///////////////////////////////
// Asynchronous Notification //
///////////////////////////////

type AsyncOp struct {
	cancel context.CancelFunc
}

func callWithTimeout(f func(context.Context) C.ScStatus, timeout int32) C.ScStatus {
	var ctx context.Context
	var cancel context.CancelFunc

	ctx = context.Background()
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, time.Duration(timeout)*time.Millisecond)
		defer cancel()
	}

	return f(ctx)
}

/**
\brief Cancel an asynchronous operation.
*/
//export ScCancelAsyncOp
func ScCancelAsyncOp(op *C.struct_ScAsyncOp) {
	cancelAsyncOp(op)
}

/////////////
// HostCtx //
/////////////

type HostCtx struct {
	ia     addr.IA
	sciond daemon.Connector
	// disp reliable.Dispatcher
	cmalloc C.ScMalloc
	cfree   C.ScFree
}

func (h *HostCtx) malloc(n int) unsafe.Pointer {
	if n < 0 {
		panic("invalid call to malloc")
	}
	if h.cmalloc != nil {
		ptr := C.call_malloc(h.cmalloc, C.size_t(n))
		C.memset(ptr, 0, C.size_t(n))
		return ptr
	} else {
		return C.calloc(1, C.size_t(n))
	}
}

func (h *HostCtx) free(ptr unsafe.Pointer) {
	if h.cfree != nil {
		C.call_free(h.cfree, ptr)
	} else {
		C.free(ptr)
	}
}

/**
\brief Initialize the host context.
*/
//export ScHostInit
func ScHostInit(hostCtx *C.ScHostCtx, config C.ConstPtrScConfig, timeout int32) C.ScStatus {
	f := func(ctx context.Context) C.ScStatus {
		return hostInit(ctx, hostCtx, config)
	}
	return callWithTimeout(f, timeout)
}

/**
\brief Initialize the host context.
*/
//export ScHostInitAsync
func ScHostInitAsync(hostCtx *C.ScHostCtx, config C.ConstPtrScConfig, op *C.struct_ScAsyncOp) {
	f := func(ctx context.Context) C.ScStatus {
		return hostInit(ctx, hostCtx, config)
	}
	callAsync(f, op)
}

func hostInit(ctx context.Context, hostCtx *C.ScHostCtx, config *C.struct_ScConfig) C.ScStatus {
	if (config.malloc == nil) != (config.free == nil) {
		return C.SC_ERROR_INVALID_ARG
	}

	// Daemon
	sciond, err := daemon.Service{
		Address: C.GoString(config.sciondAddr),
	}.Connect(ctx)
	if err != nil {
		return C.SC_ERROR_DAEMON
	}

	// Get local IA
	ia, err := sciond.LocalIA(ctx)
	if err != nil {
		return C.SC_ERROR_DAEMON
	}

	// disp := reliable.NewDispatcher(C.GoString(config.dispSock))
	host := &HostCtx{
		ia:      ia,
		sciond:  sciond,
		cmalloc: config.malloc,
		cfree:   config.free,
	}

	*hostCtx = C.ScHostCtx(cgo.NewHandle(host))
	return C.SC_SUCCESS
}

/**
\brief Destroy the host context. Make sure there are no sockets using ths context anymore before
destroying it.
*/
//export ScHostDestroy
func ScHostDestroy(hostCtx C.ScHostCtx) {
	host := cgo.Handle(hostCtx)
	h := host.Value().(*HostCtx)

	h.sciond.Close()
	host.Delete()
}

/**
\brief Allocate memory through the callback passed during host context initialization.
*/
//export ScHostAllocMem
func ScHostAllocMem(hostCtx C.ScHostCtx, size int) *C.void {
	host := cgo.Handle(hostCtx)
	h := host.Value().(*HostCtx)
	if size < 0 {
		return nil
	}
	return (*C.void)(h.malloc((int)(size)))
}

/**
\brief Deallocate memory allocated with ScHostAllocMem().
*/
//export ScHostFreeMem
func ScHostFreeMem(hostCtx C.ScHostCtx, ptr *C.void) {
	host := cgo.Handle(hostCtx)
	h := host.Value().(*HostCtx)
	h.free(unsafe.Pointer(ptr))
}

/**
\brief Return the local AS address.
*/
//export ScHostLocalIA
func ScHostLocalIA(hostCtx C.ScHostCtx) C.ScIA {
	host := cgo.Handle(hostCtx)
	h := host.Value().(*HostCtx)
	return (C.ScIA)(h.ia)
}

/**
\brief Query paths from the SCION daemon.
*/
//export ScQueryPaths
func ScQueryPaths(hostCtx C.ScHostCtx, dst C.ScIA, paths ***C.struct_ScPath, count *C.uint32_t,
	flags uint64, timeout int32) C.ScStatus {
	host := cgo.Handle(hostCtx)
	h := host.Value().(*HostCtx)
	f := func(ctx context.Context) C.ScStatus {
		return h.queryPaths(ctx, dst, paths, count, flags)
	}
	return callWithTimeout(f, timeout)
}

/**
\brief Query paths from the SCION daemon.
*/
//export ScQueryPathsAsync
func ScQueryPathsAsync(hostCtx C.ScHostCtx, dst C.ScIA, paths ***C.struct_ScPath, count *C.uint32_t,
	flags uint64, op *C.struct_ScAsyncOp) {
	host := cgo.Handle(hostCtx)
	h := host.Value().(*HostCtx)
	f := func(ctx context.Context) C.ScStatus {
		return h.queryPaths(ctx, dst, paths, count, flags)
	}
	callAsync(f, op)
}

func (h *HostCtx) queryPaths(ctx context.Context, dst C.ScIA,
	paths ***C.struct_ScPath, count *C.uint32_t, flags uint64) C.ScStatus {
	// Get paths from daemon
	dflags := daemon.PathReqFlags{
		Refresh: flags&C.SC_FLAG_PATH_REFRESH != 0,
		Hidden:  flags&C.SC_FLAG_PATH_HIDDEN != 0,
	}
	spaths, err := h.sciond.Paths(ctx, addr.IA(dst), h.ia, dflags)
	if err != nil {
		return C.SC_ERROR_DAEMON
	}

	// Count number of available SCION paths
	var pathCount int = 0
	for _, spath := range spaths {
		if _, ok := spath.Dataplane().(path.SCION); ok {
			pathCount += 1
		}
	}
	if pathCount == 0 {
		*paths = nil
		*count = 0
		return C.SC_EMPTY_RESPONSE
	}

	// Export SCION paths to C
	pathPointers := h.malloc(pathCount * int(unsafe.Sizeof(&C.struct_ScPath{})))
	cpaths := unsafe.Slice((**C.struct_ScPath)(pathPointers), pathCount)
	var i int = 0
	for _, spath := range spaths {
		dp, ok := spath.Dataplane().(path.SCION) // only SCION paths are allowed
		if !ok {
			continue
		}

		cpaths[i] = (*C.struct_ScPath)(h.malloc(int(unsafe.Sizeof(C.struct_ScPath{}))))

		// Next hop
		cpaths[i].nextHop = udpAddrfromNetUDPAddr(spath.UnderlayNextHop())

		// Data plane path
		dppath := h.malloc(len(dp.Raw))
		C.memcpy(dppath, unsafe.Pointer(&dp.Raw[0]), C.size_t(len(dp.Raw)))
		cpaths[i].dp = (*C.uchar)(dppath)
		cpaths[i].dpLen = C.ssize_t(len(dp.Raw))

		// General metadata
		md := spath.Metadata()
		numIfaces := len(md.Interfaces)
		if numIfaces%2 != 0 {
			panic("unexpected number of interfaces on path")
		}
		cpaths[i].src = C.ScIA(spath.Source())
		cpaths[i].dst = C.ScIA(spath.Destination())
		cpaths[i].expiry = C.uint32_t(md.Expiry.Unix())
		cpaths[i].mtu = C.uint16_t(md.MTU)
		cpaths[i].ifaces = C.uint16_t(numIfaces)

		// Interface metadata
		if flags&C.SC_FLAG_PATH_GET_IFACES != 0 {
			ifaceStorage := h.malloc(numIfaces * int(C.size_t(unsafe.Sizeof(C.struct_ScHopIface{}))))
			ifaces := unsafe.Slice((*C.struct_ScHopIface)(ifaceStorage), numIfaces)
			for j, iface := range md.Interfaces {
				ifaces[j].ia = C.ScIA(iface.IA)
				ifaces[j].ifid = C.ScIfId(iface.ID)
			}
			cpaths[i].ifaceMeta = (*C.struct_ScHopIface)(ifaceStorage)
		}

		// Additional metadata
		if flags&C.SC_FLAG_PATH_GET_META != 0 {
			meta := (*C.struct_ScPathMetadata)(h.malloc(int(unsafe.Sizeof(C.struct_ScPathMetadata{}))))

			// Latency
			ptr := h.malloc(len(md.Latency) * int(unsafe.Sizeof(C.uint64_t(0))))
			for i, lat := range md.Latency {
				(*[1 << 30]C.uint64_t)(ptr)[i] = C.uint64_t(lat.Nanoseconds())
			}
			meta.latencyLen = C.uint16_t(len(md.Latency))
			meta.latency = (*C.uint64_t)(ptr)

			// Bandwidth
			ptr = h.malloc(len(md.Bandwidth) * int(unsafe.Sizeof(C.uint64_t(0))))
			for i, bw := range md.Bandwidth {
				(*[1 << 30]C.uint64_t)(ptr)[i] = C.uint64_t(bw)
			}
			meta.bandwidthLen = C.uint16_t(len(md.Bandwidth))
			meta.bandwidth = (*C.uint64_t)(ptr)

			// Geo coords
			ptr = h.malloc(len(md.Geo) * int(unsafe.Sizeof(C.struct_ScGeoCoords{})))
			coords := (*[1 << 30]C.struct_ScGeoCoords)(ptr)
			for i, geo := range md.Geo {
				coords[i].latitude = C.float(geo.Latitude)
				coords[i].longitude = C.float(geo.Longitude)
			}
			meta.geoLen = C.uint16_t(len(md.Geo))
			meta.geo = (*C.struct_ScGeoCoords)(ptr)

			// Link types
			ptr = h.malloc(len(md.LinkType) * int(unsafe.Sizeof(C.ScPathLinkType(0))))
			for i, t := range md.LinkType {
				(*[1 << 30]C.ScPathLinkType)(ptr)[i] = C.ScPathLinkType(t)
			}
			meta.linkTypeLen = C.uint16_t(len(md.LinkType))
			meta.linkType = (*C.ScPathLinkType)(ptr)

			// Internal hops
			ptr = h.malloc(len(md.InternalHops) * int(unsafe.Sizeof(C.uint32_t(0))))
			for i, hops := range md.InternalHops {
				(*[1 << 30]C.uint32_t)(ptr)[i] = C.uint32_t(hops)
			}
			meta.internalHopsLen = C.uint16_t(len(md.InternalHops))
			meta.internalHops = (*C.uint32_t)(ptr)

			cpaths[i].meta = meta
		}

		i += 1
	}

	*paths = (**C.struct_ScPath)(pathPointers)
	*count = C.uint32_t(i)
	return C.SC_SUCCESS
}

////////////////////////////
// SCMP Handler Interface //
////////////////////////////

type scmpHandler struct {
	callback C.ScSCMPHandler
	userdata C.uintptr_t
}

func (h scmpHandler) Handle(pkt *snet.Packet) error {
	scmp := pkt.Payload.(snet.SCMPPayload)
	switch scmp.Type() {
	case slayers.SCMPTypeDestinationUnreachable:
		msg := pkt.Payload.(snet.SCMPDestinationUnreachable)
		m := &C.struct_ScSCMPDestinationUnreachable{
			_type: C.SC_SCMP_TYPE_PARAMETER_PROBLEM,
			code:  C.uint8_t(msg.Code()),
		}
		C.call_scmp_handler(h.callback, (*C.struct_ScSCMPMessage)(unsafe.Pointer(m)), h.userdata)

	case slayers.SCMPTypePacketTooBig:
		msg := pkt.Payload.(snet.SCMPPacketTooBig)
		m := &C.struct_ScSCMPPacketTooBig{
			_type: C.SC_SCMP_TYPE_PARAMETER_PROBLEM,
			code:  C.uint8_t(msg.Code()),
			mtu:   C.uint16_t(msg.MTU),
		}
		C.call_scmp_handler(h.callback, (*C.struct_ScSCMPMessage)(unsafe.Pointer(m)), h.userdata)

	case slayers.SCMPTypeParameterProblem:
		msg := pkt.Payload.(snet.SCMPParameterProblem)
		m := &C.struct_ScSCMPParameterProblem{
			_type:   C.SC_SCMP_TYPE_PARAMETER_PROBLEM,
			code:    C.uint8_t(msg.Code()),
			pointer: C.uint16_t(msg.Pointer),
		}
		C.call_scmp_handler(h.callback, (*C.struct_ScSCMPMessage)(unsafe.Pointer(m)), h.userdata)

	case slayers.SCMPTypeExternalInterfaceDown:
		msg := pkt.Payload.(snet.SCMPExternalInterfaceDown)
		m := &C.struct_ScSCMPExternalInterfaceDown{
			_type:      C.SC_SCMP_TYPE_EXTERNAL_INTERFACE_DOWN,
			code:       C.uint8_t(msg.Code()),
			originator: C.ScIA(msg.IA),
			_interface: C.ScIfId(msg.Interface),
		}
		C.call_scmp_handler(h.callback, (*C.struct_ScSCMPMessage)(unsafe.Pointer(m)), h.userdata)

	case slayers.SCMPTypeInternalConnectivityDown:
		msg := pkt.Payload.(snet.SCMPInternalConnectivityDown)
		m := &C.struct_ScSCMPInternalConnectivityDown{
			_type:      C.SC_SCMP_TYPE_INTERNAL_CONNECTIVITY_DOWN,
			code:       C.uint8_t(msg.Code()),
			originator: C.ScIA(msg.IA),
			egressIf:   C.ScIfId(msg.Egress),
			ingressIf:  C.ScIfId(msg.Ingress),
		}
		C.call_scmp_handler(h.callback, (*C.struct_ScSCMPMessage)(unsafe.Pointer(m)), h.userdata)
	}
	return nil
}

////////////
// Socket //
////////////

type Socket struct {
	hostCtx   *HostCtx
	sconn     snet.PacketConn
	localIA   addr.IA
	localIP   netip.Addr
	localPort uint16
}

/**
\brief Open a socket.
*/
//export ScOpenSocket
func ScOpenSocket(hostCtx C.ScHostCtx,
	local C.ConstPtrScLocalUDPAddr,
	scmpCallback C.ScSCMPHandler, scmpUserData C.uintptr_t,
	sock *C.ScSocket, timeout int32) C.ScStatus {

	host := cgo.Handle(hostCtx)
	h := host.Value().(*HostCtx)
	f := func(ctx context.Context) C.ScStatus {
		return h.openSocket(ctx, local, scmpCallback, scmpUserData, sock)
	}

	return callWithTimeout(f, timeout)
}

/**
\brief Open a socket.
*/
//export ScOpenSocketAsync
func ScOpenSocketAsync(hostCtx C.ScHostCtx,
	local C.ConstPtrScLocalUDPAddr,
	scmpCallback C.ScSCMPHandler, scmpUserData C.uintptr_t,
	sock *C.ScSocket, op *C.struct_ScAsyncOp) {

	host := cgo.Handle(hostCtx)
	h := host.Value().(*HostCtx)
	f := func(ctx context.Context) C.ScStatus {
		return h.openSocket(ctx, local, scmpCallback, scmpUserData, sock)
	}

	callAsync(f, op)
}

func (h *HostCtx) openSocket(ctx context.Context,
	local *C.struct_ScLocalUDPAddr,
	scmpCallback C.ScSCMPHandler, scmpUserData C.uintptr_t,
	sock *C.ScSocket) C.ScStatus {

	if local == nil || sock == nil {
		return C.SC_ERROR_INVALID_ARG
	}

	loc := &net.UDPAddr{
		IP:   hostAddrToSlice(&local.host),
		Port: int(local.port),
		Zone: C.GoString(&local.host.zone[0]),
	}
	// rconn, port, err := h.disp.Register(ctx, addr.IA(h.ia), loc, addr.SvcNone)
	connector := &snet.DefaultConnector{
		SCMPHandler: scmpHandler{
			callback: scmpCallback,
			userdata: scmpUserData,
		},
		CPInfoProvider: h.sciond,
	}
	sconn, err := connector.OpenUDP(ctx, loc)
	if err != nil {
		return C.SC_ERROR_FAILED
	}

	// localIP, ok := netip.AddrFromSlice(loc.IP)
	// if !ok {
	// 	panic("invalid address")
	// }
	addr, err := netip.ParseAddrPort(sconn.LocalAddr().String())
	if err != nil {
		panic("invalid address")
	}

	c := &Socket{
		hostCtx: h,
		// sconn: &snet.SCIONPacketConn{
		// 	Conn: rconn,
		// 	SCMPHandler: scmpHandler{
		// 		callback: scmpCallback,
		// 		userdata: scmpUserData,
		// 	},
		// },
		sconn:     sconn,
		localIA:   h.ia,
		localIP:   addr.Addr(),
		localPort: addr.Port(),
	}

	*sock = (C.ScSocket)(cgo.NewHandle(c))
	return C.SC_SUCCESS
}

/**
\brief Close a socket.
*/
//export ScCloseSocket
func ScCloseSocket(conn C.ScSocket) {
	h := cgo.Handle(conn)
	s := h.Value().(*Socket)

	s.sconn.Close()
	h.Delete()
}

/**
\brief Set a deadline for all current and future sent operations. Setting this to a value in
the past cancels all send operations immediately. Setting the deadline to a negative value
disables a previously set send deadline.
\param[in] conn An open socket
\param[in] deadline Deadline as Unix timestamp in milliseconds. A negative value
           disables a previously set deadline.
*/
//export ScSocketSetSendDeadline
func ScSocketSetSendDeadline(sock C.ScSocket, deadline int64) C.ScStatus {
	h := cgo.Handle(sock)
	s := h.Value().(*Socket)

	var err error
	if deadline < 0 {
		err = s.sconn.SetWriteDeadline(time.Time{})
	} else {
		err = s.sconn.SetWriteDeadline(time.UnixMilli(deadline))
	}
	if err != nil {
		return C.SC_ERROR_FAILED
	} else {
		return C.SC_SUCCESS
	}
}

/**
\brief Set a deadline for all current and future receive operations. Setting this to a value
in the past cancels all receive operations immediately. Setting the deadline to a negative
value disables a previously set receive deadline.
\param[in] conn An open socket
\param[in] deadline Deadline as Unix timestamp in milliseconds. A negative value
           disables a previously set deadline.
*/
//export ScSocketSetRecvDeadline
func ScSocketSetRecvDeadline(sock C.ScSocket, deadline int64) C.ScStatus {
	h := cgo.Handle(sock)
	s := h.Value().(*Socket)

	var err error
	if deadline < 0 {
		err = s.sconn.SetReadDeadline(time.Time{})
	} else {
		err = s.sconn.SetReadDeadline(time.UnixMilli(deadline))
	}
	if err != nil {
		return C.SC_ERROR_FAILED
	} else {
		return C.SC_SUCCESS
	}
}

/**
\brief Send a UDP packet.
*/
//export ScSendPacket
func ScSendPacket(sock C.ScSocket, pkt *C.struct_ScUDPPacket) C.ScStatus {
	h := cgo.Handle(sock)
	s := h.Value().(*Socket)
	return s.sendPacket(pkt)
}

/**
\brief Send a UDP packet.
\details Calling cancel() on the async object has no effect. The only way to cancel a pending
operation is by closing the socket or setting a send deadline.
*/
//export ScSendPacketAsync
func ScSendPacketAsync(conn C.ScSocket, pkt *C.struct_ScUDPPacket, op *C.struct_ScAsyncOp) {
	h := cgo.Handle(conn)
	s := h.Value().(*Socket)
	f := func(ctx context.Context) C.ScStatus {
		return s.sendPacket(pkt)
	}
	callAsync(f, op)
}

func (s *Socket) sendPacket(pkt *C.struct_ScUDPPacket) C.ScStatus {
	if pkt.dpPath == nil && s.localIA != addr.IA(pkt.remote.ia) {
		return C.SC_ERROR_INVALID_ARG
	}

	var path snet.DataplanePath = path.Empty{}
	var nextHop *net.UDPAddr
	if s.localIA == addr.IA(pkt.remote.ia) {
		nextHop = &net.UDPAddr{
			IP:   hostAddrToSlice(&pkt.remote.local.host),
			Port: underlay.EndhostPort,
			Zone: C.GoString(&pkt.remote.local.host.zone[0]),
		}
	} else {
		path = snetpath.SCION{Raw: unsafe.Slice((*byte)(pkt.dpPath), pkt.dpPathLen)}
		nextHop = udpAddrtoNetAddr(&pkt.router)
	}

	spkt := &snet.Packet{
		Bytes: nil,
		PacketInfo: snet.PacketInfo{
			Source: snet.SCIONAddress{
				IA:   s.localIA,
				Host: addr.HostIP(s.localIP),
			},
			Destination: snet.SCIONAddress{
				IA:   addr.IA(pkt.remote.ia),
				Host: addr.HostIP(hostAddrtoNetipAddr(&pkt.remote.local.host)),
			},
			Path: path,
			Payload: snet.UDPPayload{
				SrcPort: s.localPort,
				DstPort: uint16(pkt.remote.local.port),
				Payload: unsafe.Slice((*byte)(pkt.payload), pkt.payloadLen),
			},
		},
	}

	err := s.sconn.WriteTo(spkt, nextHop)
	if err != nil {
		return C.SC_ERROR_FAILED
	}
	return C.SC_SUCCESS
}

/**
\brief Receive a UDP packet.
*/
//export ScRecvPacket
func ScRecvPacket(sock C.ScSocket, pkt *C.struct_ScUDPPacket) C.ScStatus {
	h := cgo.Handle(sock)
	s := h.Value().(*Socket)
	return s.recvPacket(pkt)
}

/**
\brief Receive a UDP packet.
\details Calling cancel() on the async object has no effect. The only way to cancel a pending
operation is by closing the socket or setting a receive deadline.
*/
//export ScRecvPacketAsync
func ScRecvPacketAsync(sock C.ScSocket, pkt *C.struct_ScUDPPacket, op *C.struct_ScAsyncOp) {
	h := cgo.Handle(sock)
	s := h.Value().(*Socket)
	f := func(ctx context.Context) C.ScStatus {
		return s.recvPacket(pkt)
	}
	callAsync(f, op)
}

func (s *Socket) recvPacket(pkt *C.struct_ScUDPPacket) C.ScStatus {
	for {
		var spkt snet.Packet
		var lastHop net.UDPAddr

		if err := s.sconn.ReadFrom(&spkt, &lastHop); err != nil {
			return C.SC_ERROR_FAILED
		}

		// Only return UDP packets with IP destination
		udp, ok := spkt.Payload.(snet.UDPPayload)
		if !ok {
			continue
		}
		if spkt.Source.Host.Type() != addr.HostTypeIP {
			continue
		}

		// Sender address
		pkt.remote = C.struct_ScUDPAddr{
			ia: C.ScIA(spkt.Source.IA),
			local: C.struct_ScLocalUDPAddr{
				host: hostAddrfromNetipAddr(spkt.Source.Host.IP()),
				port: C.ScPort(udp.SrcPort),
			},
		}

		// Last hop
		pkt.router = udpAddrfromNetUDPAddr(&lastHop)

		// Path
		if pkt.dpPath != nil {
			rawPath, ok := spkt.Path.(snet.RawPath)
			if !ok {
				panic("unexpected path type from data plane")
			}
			if n := len(rawPath.Raw); n <= int(pkt.dpPathCap) {
				pkt.dpPathLen = C.ScSize(n)
				if n > 0 {
					C.memcpy(unsafe.Pointer(pkt.dpPath), unsafe.Pointer(&rawPath.Raw[0]), C.size_t(n))
				}
			}
		}

		// Payload
		n := min(len(udp.Payload), int(pkt.payloadCap))
		pkt.payloadLen = C.ScSize(n)
		if n > 0 {
			C.memcpy(unsafe.Pointer(pkt.payload), unsafe.Pointer(&udp.Payload[0]), C.size_t(n))
		}

		if len(udp.Payload) <= int(pkt.payloadCap) {
			return C.SC_SUCCESS
		} else {
			return C.SC_ERROR_BUFFER_INSUFFICIENT
		}
	}
}

// main for Cgo
func main() {
}
