// Copyright (c) 2018 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"github.com/kaspanet/dnsseeder/checkversion"
	"github.com/kaspanet/dnsseeder/netadapter"
	"github.com/kaspanet/kaspad/app/protocol/common"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kaspanet/kaspad/infrastructure/config"
	"github.com/pkg/errors"

	"github.com/kaspanet/dnsseeder/version"
	"github.com/kaspanet/kaspad/infrastructure/network/dnsseed"
	"github.com/kaspanet/kaspad/util/panics"
	"github.com/kaspanet/kaspad/util/profiling"

	"github.com/kaspanet/kaspad/app/appmessage"
	"github.com/kaspanet/kaspad/infrastructure/os/signal"

	_ "net/http/pprof"
)

var (
	amgr             *Manager
	wg               sync.WaitGroup
	peersDefaultPort int
	systemShutdown   int32
	defaultSeeder    *appmessage.NetAddress
)

// hostLookup returns the correct DNS lookup function to use depending on the
// passed host and configuration options. For example, .onion addresses will be
// resolved using the onion specific proxy if one was specified, but will
// otherwise treat the normal proxy as tor unless --noonion was specified in
// which case the lookup will fail. Meanwhile, normal IP addresses will be
// resolved using tor if a proxy was specified unless --noonion was also
// specified in which case the normal system DNS resolver will be used.
func hostLookup(host string) ([]net.IP, error) {
	return net.LookupIP(host)
}

func creep() {
	defer wg.Done()

	var netAdapters []*netadapter.DnsseedNetAdapter
	for i := uint8(0); i < ActiveConfig().Threads; i++ {
		netAdapters = append(netAdapters, newNetAdapter())
	}

	var knownPeers []*appmessage.NetAddress

	if len(ActiveConfig().KnownPeers) != 0 {
		for _, p := range strings.Split(ActiveConfig().KnownPeers, ",") {
			addressStr := strings.Split(p, ":")
			if len(addressStr) != 2 {
				log.Errorf("Invalid peer address: %s; addresses should be in format \"IP\":\"port\"", p)
				return
			}

			ip := net.ParseIP(addressStr[0])
			if ip == nil {
				log.Errorf("Invalid peer IP address: %s", addressStr[0])
				return
			}
			port, err := strconv.Atoi(addressStr[1])
			if err != nil {
				log.Errorf("Invalid peer port: %s", addressStr[1])
				return
			}

			knownPeers = append(knownPeers, appmessage.NewNetAddressIPPort(ip, uint16(port)))
		}

		amgr.AddAddresses(knownPeers)
		for _, peer := range knownPeers {
			amgr.Attempt(peer)
			amgr.Good(peer, nil, nil)
		}
	}

	var wgCreep sync.WaitGroup
	for {
		peers := amgr.Addresses()
		if len(peers) == 0 && amgr.AddressCount() == 0 {
			// Add peers discovered through DNS to the address manager.
			dnsseed.SeedFromDNS(ActiveConfig().NetParams(), "", true,
				nil, hostLookup, func(addrs []*appmessage.NetAddress) {
					amgr.AddAddresses(addrs)
				})
			peers = amgr.Addresses()
		}
		if len(peers) == 0 {
			log.Debugf("No stale addresses")
			for i := 0; i < 10; i++ {
				time.Sleep(time.Second)
				if atomic.LoadInt32(&systemShutdown) != 0 {
					log.Infof("Creep thread shutdown")
					return
				}
			}
			continue
		}

		for i, addr := range peers {
			if atomic.LoadInt32(&systemShutdown) != 0 {
				log.Infof("Waiting creep threads to terminate")
				wgCreep.Wait()
				log.Infof("Creep thread shutdown")
				return
			}
			wgCreep.Add(1)
			i := i
			go func(addr *appmessage.NetAddress) {
				defer wgCreep.Done()

				err := pollPeer(netAdapters[i%len(netAdapters)], addr)
				if err != nil {
					log.Debugf(err.Error())
					if defaultSeeder != nil && addr == defaultSeeder {
						panics.Exit(log, "failed to poll default seeder")
					}
				}
			}(addr)
		}
		wgCreep.Wait()
	}
}

func pollPeer(netAdapter *netadapter.DnsseedNetAdapter, addr *appmessage.NetAddress) error {
	amgr.Attempt(addr)

	peerAddress := net.JoinHostPort(addr.IP.String(), strconv.Itoa(int(addr.Port)))

	log.Debugf("Polling peer %s", peerAddress)
	routes, msgVersion, err := netAdapter.Connect(peerAddress)
	if err != nil {
		return errors.Wrapf(err, "could not connect to %s", peerAddress)
	}
	defer routes.Disconnect()

	// Abort before collecting peers for nodes below minimum protocol
	if ActiveConfig().MinProtoVer > 0 && msgVersion.ProtocolVersion < uint32(ActiveConfig().MinProtoVer) {
		return errors.Errorf("Peer %s (%s) protocol version %d is below minimum: %d",
			peerAddress, msgVersion.UserAgent, msgVersion.ProtocolVersion, ActiveConfig().MinProtoVer)
	}

	msgRequestAddresses := appmessage.NewMsgRequestAddresses(true, nil)
	err = routes.OutgoingRoute.Enqueue(msgRequestAddresses)
	if err != nil {
		return errors.Wrapf(err, "failed to request addresses from %s", peerAddress)
	}

	message, err := routes.WaitForMessageOfType(appmessage.CmdAddresses, common.DefaultTimeout)
	if err != nil {
		return errors.Wrapf(err, "failed to receive addresses from %s", peerAddress)
	}
	msgAddresses := message.(*appmessage.MsgAddresses)

	added := amgr.AddAddresses(msgAddresses.AddressList)
	log.Infof("Peer %s (%s) sent %d addresses, %d new",
		peerAddress, msgVersion.UserAgent, len(msgAddresses.AddressList), added)

	// Abort after collecting peers for nodes below minimum user agent version
	if ActiveConfig().MinUaVer != "" {
		err = checkversion.CheckVersion(ActiveConfig().MinUaVer, msgVersion.UserAgent)
		if err != nil {
			return errors.Wrapf(err, "Peer %s version %s doesn't satisfy minimum: %s",
				peerAddress, msgVersion.UserAgent, ActiveConfig().MinUaVer)
		}
	}
	amgr.Good(addr, &msgVersion.UserAgent, nil)
	return nil
}

func newNetAdapter() *netadapter.DnsseedNetAdapter {
	netAdapter, err := netadapter.NewDnsseedNetAdapter(&config.Config{Flags: &config.Flags{NetworkFlags: ActiveConfig().NetworkFlags}})
	if err != nil {
		panic(errors.Wrap(err, "Could not start net adapter"))
	}
	return netAdapter
}

func main() {
	defer panics.HandlePanic(log, "main", nil)
	interrupt := signal.InterruptListener()

	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "loadConfig: %v\n", err)
		os.Exit(1)
	}

	// Show version at startup.
	log.Infof("Version %s", version.Version())

	// Enable http profiling server if requested.
	if cfg.Profile != "" {
		profiling.Start(cfg.Profile, log)
	}

	amgr, err = NewManager(cfg.AppDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "NewManager: %v\n", err)
		os.Exit(1)
	}

	peersDefaultPort, err = strconv.Atoi(ActiveConfig().NetParams().DefaultPort)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid peers default port %s: %v\n", ActiveConfig().NetParams().DefaultPort, err)
		os.Exit(1)
	}

	if len(cfg.Seeder) != 0 {
		// Prepare the seeder address, supporting either a simple IP with default network port
		// or a full IP:port format
		seederIp := cfg.Seeder
		seederPort := peersDefaultPort

		// Try to split seeder host and port
		foundIp, foundPort, err := net.SplitHostPort(cfg.Seeder)
		if err == nil {
			seederIp = foundIp
			seederPort, err = strconv.Atoi(foundPort)
			if err != nil {
				log.Errorf("Invalid seeder port: %s", foundPort)
				return
			}
		}

		ip := net.ParseIP(seederIp)
		if ip == nil {
			hostAddrs, err := net.LookupHost(seederIp)
			if err != nil {
				log.Warnf("Failed to resolve seed host: %v, %v, ignoring", seederIp, err)
			} else {
				ip = net.ParseIP(hostAddrs[0])
				if ip == nil {
					log.Warnf("Failed to resolve seed host: %v, ignoring", seederIp)
				}
			}
		}
		if ip != nil {
			defaultSeeder = appmessage.NewNetAddressIPPort(ip, uint16(seederPort))
			amgr.AddAddresses([]*appmessage.NetAddress{defaultSeeder})
		}
	}

	wg.Add(1)
	spawn("main-creep", creep)

	dnsServer := NewDNSServer(cfg.Host, cfg.Nameserver, cfg.Listen)
	wg.Add(1)
	spawn("main-DNSServer.Start", dnsServer.Start)

	grpcServer := NewGRPCServer(amgr)
	err = grpcServer.Start(cfg.GRPCListen)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start gRPC server")
		return
	}

	defer func() {
		log.Infof("Gracefully shutting down the seeder...")
		atomic.StoreInt32(&systemShutdown, 1)
		close(amgr.quit)
		wg.Wait()
		amgr.wg.Wait()
		log.Infof("Seeder shutdown complete")
	}()

	// Wait until the interrupt signal is received from an OS signal or
	// shutdown is requested through one of the subsystems such as the RPC
	// server.
	<-interrupt
}
