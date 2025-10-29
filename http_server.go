package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/kaspanet/dnsseeder/netadapter"
	"github.com/kaspanet/kaspad/app/appmessage"
)

func startHTTPServer(listenAddr string, corsOrigins []string, apiKey string) {
	allowedOrigins := make(map[string]bool, len(corsOrigins))
	for _, o := range corsOrigins {
		allowedOrigins[o] = true
	}
	netAdapter := newNetAdapter()

	const maxQueriesPerSourceInterval = 10 * time.Second
	const maxQueriesPerSourcePerInterval = 10
	const maxConcurrentQueries = 3
	var perIpQueryCountMutex sync.Mutex
	perIpQueryCount := make(map[string]int)
	// start background decay
	go func() {
		ticker := time.NewTicker(maxQueriesPerSourceInterval)
		defer ticker.Stop()
		for range ticker.C {
			perIpQueryCountMutex.Lock()
			for ip := range perIpQueryCount {
				if perIpQueryCount[ip] > 0 {
					perIpQueryCount[ip]--
				}
			}
			perIpQueryCountMutex.Unlock()
		}
	}()

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

		perIpQueryCountMutex.Lock()
		clientQueryCount := perIpQueryCount[clientIP]
		perIpQueryCountMutex.Unlock()
		if clientQueryCount >= maxQueriesPerSourcePerInterval {
			log.Warnf("Http [%s]: Too many queries", clientIP)
			http.Error(w, "Too many queries", http.StatusTooManyRequests)
			return
		}
		perIpQueryCountMutex.Lock()
		perIpQueryCount[clientIP]++
		perIpQueryCountMutex.Unlock()

		if r.Method == http.MethodGet {
			getPeers(w, r, apiKey)
		} else if r.Method == http.MethodPost {
			postPeer(w, r, clientIP, netAdapter, allowedOrigins)
		} else if r.Method == http.MethodOptions {
			log.Debugf("Http [%s]: Options requested", clientIP)
			w.WriteHeader(http.StatusNoContent)
		} else {
			log.Warnf("Http [%s]: Disallowed method '%s'", clientIP, r.Method)
			http.Error(w, "Only GET/POST allowed", http.StatusMethodNotAllowed)
		}
	})

	go func() {
		log.Infof("Starting HTTP control server on %s", listenAddr)
		if err := http.ListenAndServe(listenAddr, nil); err != nil {
			log.Errorf("HTTP control server failed: %v", err)
		}
	}()
}

type NodeView struct {
	Ip          *string   `json:"ip,omitempty"`
	Port        *uint16   `json:"port,omitempty"`
	Id          *string   `json:"id,omitempty"`
	UserAgent   *string   `json:"userAgent,omitempty"`
	LastSuccess time.Time `json:"lastSuccess,omitempty"`
}

func getPeers(w http.ResponseWriter, r *http.Request, apiKey string) {
	amgr.mtx.RLock()
	nodes := make([]*NodeView, 0, len(amgr.nodes))
	cutoff := time.Now().Add(-7 * 24 * time.Hour)
	for _, n := range amgr.nodes {
		if n.LastSuccess.After(cutoff) {
			node := &NodeView{
				Id:          n.Id,
				UserAgent:   n.UserAgent,
				LastSuccess: n.LastSuccess,
			}
			if apiKey != "" && apiKey == r.Header.Get("X-API-KEY") {
				if n.Addr != nil && n.Addr.IP != nil {
					ip := n.Addr.IP.String()
					port := n.Addr.Port
					node.Ip = &ip
					node.Port = &port
				}
			}
			nodes = append(nodes, node)
		}
	}
	amgr.mtx.RUnlock()

	sort.Slice(nodes, func(i, j int) bool {
		return nodes[i].LastSuccess.After(nodes[j].LastSuccess)
	})
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(nodes); err != nil {
		http.Error(w, "encoding error", http.StatusInternalServerError)
	}
}

func postPeer(w http.ResponseWriter, r *http.Request, clientIP string, netAdapter *netadapter.DnsseedNetAdapter, allowedOrigins map[string]bool) {
	origin := r.Header.Get("Origin")
	if allowedOrigins[origin] {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Vary", "Origin")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		if reqHeaders := r.Header.Get("Access-Control-Request-Headers"); reqHeaders != "" {
			w.Header().Set("Access-Control-Allow-Headers", reqHeaders)
		}
	} else if len(allowedOrigins) > 0 {
		log.Warnf("Http [%s]: Request without correct origin", clientIP)
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}
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
	msgVersion, err := pollPeer(netAdapter, addr)
	if err != nil {
		log.Infof("Http [%s]: Peer '%s' could not be verified, poll failed: %v", clientIP, ipStr, err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	amgr.AddAddresses([]*appmessage.NetAddress{addr})
	amgr.Attempt(addr)
	amgr.Good(addr, msgVersion.ID, &msgVersion.UserAgent, nil)

	log.Infof("Http [%s]: Peer '%s' added and verified OK", clientIP, ipStr)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(fmt.Sprintf("Peer %s added and verified OK\n", ipStr)))
}
