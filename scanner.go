package main

import (
	"bytes"
	"crypto/sha1"
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	MAIN_SERVER  = "www.easy4ipcloud.com"
	MAIN_PORT    = 8800
	USERNAME     = "cba1b29e32cb17aa46b8ff9e73c7f40b"
	USERKEY      = "996103384cdf19179e19243e959bbf8b"
	SOCKET_BUF   = 1024 * 1024
	SuffixCombos = 1 << 20
	hexChars     = "0123456789ABCDEF"
	BURST_LIMIT  = 64
	ACK_TIMEOUT  = 15 * time.Second
)

type dhResp struct {
	Code int
	CSeq int64
	Body string
}

type requestState struct {
	serial    string
	timestamp time.Time
}

// ScanStats содержит итоговую статистику выполнения сканирования
type ScanStats struct {
	TotalSent uint64
	TotalHits uint64
	Duration  time.Duration
}

type wsseGenerator struct {
	mu  sync.Mutex
	rng *rand.Rand
}

func newWSSEGenerator() *wsseGenerator {
	return &wsseGenerator{
		rng: rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

func (g *wsseGenerator) Gen() (digest, nonceStr, curdate string) {
	g.mu.Lock()
	nonce := g.rng.Int63n(1<<32) - (1 << 31)
	g.mu.Unlock()

	nonceStr = strconv.FormatInt(nonce, 10)
	curdate = time.Now().UTC().Format("2006-01-02T15:04:05Z")
	pwd := nonceStr + curdate + "DHP2P:" + USERNAME + ":" + USERKEY
	hash := sha1.Sum([]byte(pwd))
	digest = base64.StdEncoding.EncodeToString(hash[:])
	return
}

// ScanCloudPrefix выполняет асинхронное сканирование пространства серийных номеров по заданному префиксу
func ScanCloudPrefix(ctx context.Context, prefix string, maxWorkers int, rpsLimit int, onAlive func(serial string)) (*ScanStats, error) {
	startTime := time.Now()
	
	prefix = strings.ToUpper(strings.TrimSpace(prefix))
	if len(prefix) != 10 {
		return nil, fmt.Errorf("префикс должен быть ровно 10 символов (введено: %d)", len(prefix))
	}

	ips, err := net.LookupIP(MAIN_SERVER)
	if err != nil || len(ips) == 0 {
		return nil, fmt.Errorf("не удалось разрешить IP-адрес облака: %w", err)
	}
	targetIP := ips[0]

	raddr := &net.UDPAddr{IP: targetIP, Port: MAIN_PORT}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return nil, fmt.Errorf("ошибка создания сокета: %w", err)
	}
	defer conn.Close()

	_ = conn.SetWriteBuffer(SOCKET_BUF)
	_ = conn.SetReadBuffer(SOCKET_BUF)

	wsse := newWSSEGenerator()

	// 1. Предварительный Probe Handshake
	digest, nonceStr, curdate := wsse.Gen()
	probeReq := fmt.Sprintf("DHGET /probe/p2psrv HTTP/1.1\r\nCSeq: 1\r\nAuthorization: WSSE profile=\"UsernameToken\"\r\nX-WSSE: UsernameToken Username=\"%s\", PasswordDigest=\"%s\", Nonce=\"%s\", Created=\"%s\"\r\n\r\n",
		USERNAME, digest, nonceStr, curdate)

	if _, err := conn.Write([]byte(probeReq)); err != nil {
		return nil, fmt.Errorf("ошибка отправки Probe: %w", err)
	}

	buf := make([]byte, 2048)
	_ = conn.SetReadDeadline(time.Now().Add(4 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("облако не ответило на Probe: %w", err)
	}

	probeResp := parseDHResp(buf[:n])
	if probeResp.Code < 200 || probeResp.Code >= 400 {
		return nil, fmt.Errorf("неверный статус Probe от сервера: %d", probeResp.Code)
	}

	_ = conn.SetReadDeadline(time.Time{})

	lport := conn.LocalAddr().(*net.UDPAddr).Port
	var globalCSeq int64 = 2

	var stats ScanStats

	pendingRequests := make(map[int64]requestState)
	var mapMu sync.Mutex

	jobs := make(chan int, 5000)
	var wg sync.WaitGroup

	// Динамическое ограничение скорости на основе переданного rpsLimit
	rateTicker := time.NewTicker(time.Second / time.Duration(rpsLimit))
	defer rateTicker.Stop()
	throttle := make(chan struct{}, BURST_LIMIT)

	go func() {
		for range rateTicker.C {
			select {
			case throttle <- struct{}{}:
			default:
			}
		}
	}()

	// Контекст для остановки фоновых горутин чтения/очистки после завершения работы
	stopChan := make(chan struct{})

	// Фоновый поток чтения ответов
	go func() {
		readBuf := make([]byte, 65536)
		for {
			select {
			case <-stopChan:
				return
			default:
				_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
				readLen, readErr := conn.Read(readBuf)
				if readErr != nil {
					continue
				}

				resp := parseDHResp(readBuf[:readLen])
				if resp.Code == 100 {
					continue
				}

				mapMu.Lock()
				state, exists := pendingRequests[resp.CSeq]
				if exists {
					delete(pendingRequests, resp.CSeq)
				}
				mapMu.Unlock()

				if exists {
					hasLocalAddr := strings.Contains(resp.Body, "<LocalAddr>") && strings.Contains(resp.Body, "</LocalAddr>")
					if resp.Code >= 200 && resp.Code < 400 && hasLocalAddr {
						atomic.AddUint64(&stats.TotalHits, 1)
						if onAlive != nil {
							onAlive(state.serial)
						}
					}
				}
			}
		}
	}()

	// Периодическая очистка таймаутов
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stopChan:
				return
			case <-ticker.C:
				now := time.Now()
				mapMu.Lock()
				for cseq, state := range pendingRequests {
					if now.Sub(state.timestamp) > ACK_TIMEOUT {
						delete(pendingRequests, cseq)
					}
				}
				mapMu.Unlock()
			}
		}
	}()

	// Запуск пула воркеров
	for w := 0; w < maxWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var serialBuf [15]byte
			copy(serialBuf[:10], []byte(prefix)) // ИСПРАВЛЕНО: приведение string к []byte для корректного copy()

			rng := rand.New(rand.NewSource(time.Now().UnixNano()))

			for i := range jobs {
				<-throttle

				serialBuf[10] = hexChars[(i>>16)&0xF]
				serialBuf[11] = hexChars[(i>>12)&0xF]
				serialBuf[12] = hexChars[(i>>8)&0xF]
				serialBuf[13] = hexChars[(i>>4)&0xF]
				serialBuf[14] = hexChars[i&0xF]
				currentSerial := string(serialBuf[:])

				cseq := atomic.AddInt64(&globalCSeq, 1)

				aidVal := rng.Uint64()
				aid := make([]byte, 8)
				binary.LittleEndian.PutUint64(aid, aidVal)

				body := p2pChannelBody(lport, aid)
				d, nStr, cDate := wsse.Gen()

				reqStr := fmt.Sprintf("DHPOST /device/%s/p2p-channel HTTP/1.1\r\nCSeq: %d\r\nAuthorization: WSSE profile=\"UsernameToken\"\r\nX-WSSE: UsernameToken Username=\"%s\", PasswordDigest=\"%s\", Nonce=\"%s\", Created=\"%s\"\r\nContent-Type: \r\nContent-Length: %d\r\n\r\n%s",
					currentSerial, cseq, USERNAME, d, nStr, cDate, len(body), body)

				mapMu.Lock()
				pendingRequests[cseq] = requestState{
					serial:    currentSerial,
					timestamp: time.Now(),
				}
				mapMu.Unlock()

				_, err := conn.Write([]byte(reqStr))
				if err == nil {
					atomic.AddUint64(&stats.TotalSent, 1)
				}
			}
		}()
	}

	for i := 0; i < SuffixCombos; i++ {
		jobs <- i
	}
	close(jobs)

	wg.Wait()
	time.Sleep(ACK_TIMEOUT)
	close(stopChan)

	stats.Duration = time.Since(startTime)
	return &stats, nil
}

func parseDHResp(data []byte) dhResp {
	r := dhResp{}
	head := data
	rest := ""
	if i := bytes.Index(data, []byte("\r\n\r\n")); i >= 0 {
		head = data[:i]
		rest = string(data[i+4:])
	}
	lines := bytes.Split(head, []byte("\r\n"))
	for i, ln := range lines {
		if i == 0 {
			parts := bytes.SplitN(ln, []byte(" "), 3)
			if len(parts) >= 2 {
				r.Code, _ = strconv.Atoi(string(parts[1]))
			}
			continue
		}
		if j := bytes.IndexByte(ln, byte(':')); j > 0 {
			if bytes.EqualFold(ln[:j], []byte("CSeq")) {
				r.CSeq, _ = strconv.ParseInt(strings.TrimSpace(string(ln[j+1:])), 10, 64)
			}
		}
	}
	r.Body = rest
	return r
}

func p2pChannelBody(lport int, aid []byte) string {
	return fmt.Sprintf("<body><Identify>%x</Identify><IpEncrpt>true</IpEncrpt><LocalAddr>127.0.0.1:%d</LocalAddr><version>5.0.0</version></body>", aid, lport)
}
