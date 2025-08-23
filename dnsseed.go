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

	"io"
	"net/http"
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

				_, err := pollPeer(netAdapters[i%len(netAdapters)], addr)
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

func pollPeer(netAdapter *netadapter.DnsseedNetAdapter, addr *appmessage.NetAddress) (*appmessage.MsgVersion, error) {
	amgr.Attempt(addr)

	peerAddress := net.JoinHostPort(addr.IP.String(), strconv.Itoa(int(addr.Port)))

	log.Debugf("Polling peer %s", peerAddress)
	routes, msgVersion, err := netAdapter.Connect(peerAddress)
	if err != nil {
		return nil, errors.Wrapf(err, "could not connect to %s", peerAddress)
	}
	defer routes.Disconnect()

	// Abort before collecting peers for nodes below minimum protocol
	if ActiveConfig().MinProtoVer > 0 && msgVersion.ProtocolVersion < uint32(ActiveConfig().MinProtoVer) {
		return nil, errors.Errorf("Peer %s (%s) protocol version %d is below minimum: %d",
			peerAddress, msgVersion.UserAgent, msgVersion.ProtocolVersion, ActiveConfig().MinProtoVer)
	}

	var addresses []*appmessage.NetAddress
	for i := 0; i < 5; i++ {
		msgRequestAddresses := appmessage.NewMsgRequestAddresses(true, nil)
		err = routes.OutgoingRoute.Enqueue(msgRequestAddresses)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to request addresses from %s", peerAddress)
		}
		message, err := routes.WaitForMessageOfType(appmessage.CmdAddresses, common.DefaultTimeout)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to receive addresses from %s", peerAddress)
		}
		addrList := message.(*appmessage.MsgAddresses).AddressList
		addresses = append(addresses, addrList...)
		if i < 2 {
			time.Sleep(200 * time.Millisecond)
		}
	}

	added := amgr.AddAddresses(addresses)
	log.Infof("Peer %s (%s) sent %d addresses, %d new",
		peerAddress, msgVersion.UserAgent, len(addresses), added)

	// Abort after collecting peers for nodes below minimum user agent version
	if ActiveConfig().MinUaVer != "" {
		err = checkversion.CheckVersion(ActiveConfig().MinUaVer, msgVersion.UserAgent)
		if err != nil {
			return nil, errors.Wrapf(err, "Peer %s version %s doesn't satisfy minimum: %s",
				peerAddress, msgVersion.UserAgent, ActiveConfig().MinUaVer)
		}
	}
	amgr.Good(addr, &msgVersion.UserAgent, nil)
	return msgVersion, nil
}

func newNetAdapter() *netadapter.DnsseedNetAdapter {
	netAdapter, err := netadapter.NewDnsseedNetAdapter(&config.Config{Flags: &config.Flags{NetworkFlags: ActiveConfig().NetworkFlags}})
	if err != nil {
		panic(errors.Wrap(err, "Could not start net adapter"))
	}
	return netAdapter
}

func startHTTPServer(listenAddr string, corsOrigins []string) {
	allowedOrigins := make(map[string]bool, len(corsOrigins))
	for _, o := range corsOrigins {
		allowedOrigins[o] = true
	}
	netAdapter := newNetAdapter()
	perIpQueryCount := make(map[string]int)
	const maxQueriesPerSource = 100
	const maxConcurrentQueries = 3

	sema := make(chan struct{}, maxConcurrentQueries)
	http.HandleFunc("/peers", func(w http.ResponseWriter, r *http.Request) {
		clientIP := r.Header.Get("X-Forwarded-For")
		if clientIP != "" {
			parts := strings.Split(clientIP, ",")
			clientIP = strings.TrimSpace(parts[0])
		} else {
			clientIP, _, _ = net.SplitHostPort(r.RemoteAddr)
		}
		if len(sema) == cap(sema) {
			log.Warnf("Http [%s]: Server busy, try again later", clientIP)
			http.Error(w, "Server busy, try again later", http.StatusTooManyRequests)
			return
		}
		sema <- struct{}{}
		defer func() { <-sema }()

		origin := r.Header.Get("Origin")
		if allowedOrigins[origin] {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
			if reqHeaders := r.Header.Get("Access-Control-Request-Headers"); reqHeaders != "" {
				w.Header().Set("Access-Control-Allow-Headers", reqHeaders)
			}
		} else {
			log.Warnf("Http [%s]: Request without correct origin", clientIP)
			http.Error(w, "Not found", http.StatusNotFound)
			return
		}

		if r.Method == http.MethodOptions {
			log.Debugf("Http [%s]: Options requested", clientIP)
			w.WriteHeader(http.StatusNoContent)
			return
		}

		if r.Method != http.MethodPost {
			log.Warnf("Http [%s]: Disallowed method '%s'", clientIP, r.Method)
			http.Error(w, "Only POST allowed", http.StatusMethodNotAllowed)
			return
		}

		if perIpQueryCount[clientIP] >= maxQueriesPerSource {
			log.Warnf("Http [%s]: Too many queries", clientIP)
			http.Error(w, "Too many queries", http.StatusTooManyRequests)
			return
		}
		perIpQueryCount[clientIP]++

		defer func() { _ = r.Body.Close() }()
		body, err := io.ReadAll(r.Body)
		if err != nil {
			log.Warnf("Http [%s]: Failed to read body", clientIP)
			http.Error(w, "Failed to read body", http.StatusBadRequest)
			return
		}

		ipStr := strings.TrimSpace(string(body))
		ip := net.ParseIP(ipStr)
		if ip == nil {
			log.Infof("Http [%s]: Invalid IP address '%s'", clientIP, ipStr)
			http.Error(w, "Invalid IP address", http.StatusBadRequest)
			return
		}

		addr := appmessage.NewNetAddressIPPort(ip, uint16(peersDefaultPort))
		existingNode := amgr.GetNode(addr)
		if existingNode != nil {
			if amgr.IsGood(existingNode) {
				w.WriteHeader(http.StatusOK)
				log.Infof("Http [%s]: Peer '%s' exists and is verified OK", clientIP, ipStr)
				_, _ = w.Write([]byte(fmt.Sprintf("Peer '%s' exists and is verified OK\n", ipStr)))
			} else {
				w.WriteHeader(http.StatusBadRequest)
				log.Infof("Http [%s]: Peer '%s' could not be verified", clientIP, ipStr)
				_, _ = w.Write([]byte(fmt.Sprintf("Peer '%s' could not be verified\n", ipStr)))
			}
			return
		}

		msgVersion, err := pollPeer(netAdapter, addr)
		if err != nil {
			log.Infof("Http [%s]: Peer '%s' could not be verified, poll failed: %v", clientIP, ipStr, err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		amgr.AddAddresses([]*appmessage.NetAddress{addr})
		amgr.Attempt(addr)
		amgr.Good(addr, &msgVersion.UserAgent, nil)

		log.Infof("Http [%s]: Peer '%s' added and verified OK", clientIP, ipStr)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(fmt.Sprintf("Peer %s added and verified OK\n", ipStr)))
	})

	go func() {
		log.Infof("Starting HTTP control server on %s", listenAddr)
		if err := http.ListenAndServe(listenAddr, nil); err != nil {
			log.Errorf("HTTP control server failed: %v", err)
		}
	}()
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
	if cfg.HttpListen != "" {
		startHTTPServer(cfg.HttpListen, cfg.CorsOrigins)
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
