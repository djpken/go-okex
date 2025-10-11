package ws

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/djpken/go-okex"
	"github.com/djpken/go-okex/events"
	"github.com/gorilla/websocket"
)

// RetryConfig configures the retry behavior for websocket connections
type RetryConfig struct {
	MaxRetries      int           // Maximum number of retries, 0 or negative for unlimited
	InitialInterval time.Duration // Initial retry interval
	MaxInterval     time.Duration // Maximum retry interval
	Multiplier      float64       // Backoff multiplier
}

// DefaultRetryConfig provides sensible defaults for retry behavior
var DefaultRetryConfig = RetryConfig{
	MaxRetries:      0, // Unlimited retries
	InitialInterval: 2 * time.Second,
	MaxInterval:     30 * time.Second,
	Multiplier:      2.0,
}

// subscription represents a channel subscription
type subscription struct {
	channels []okex.ChannelName
	args     []map[string]string
}

// ClientWs is the websocket api client
//
// https://www.okex.com/docs-v5/en/#websocket-api
type ClientWs struct {
	Cancel              context.CancelFunc
	DoneChan            chan interface{}
	StructuredEventChan chan interface{}
	RawEventChan        chan *events.Basic
	ErrChan             chan *events.Error
	SubscribeChan       chan *events.Subscribe
	UnsubscribeChan     chan *events.Unsubscribe
	LoginChan           chan *events.Login
	SuccessChan         chan *events.Success
	sendChan            map[bool]chan []byte
	url                 map[bool]okex.BaseURL
	conn                map[bool]*websocket.Conn
	dialer              *websocket.Dialer
	apiKey              string
	secretKey           []byte
	passphrase          string
	lastTransmit        map[bool]*time.Time
	mu                  map[bool]*sync.RWMutex
	AuthRequested       *time.Time
	Authorized          bool
	Private             *Private
	Public              *Public
	Trade               *Trade
	ctx                 context.Context
	retryConfig         RetryConfig
	retryCount          map[bool]int
	reconnecting        map[bool]bool
	reconnectMu         map[bool]*sync.Mutex
	subscriptions       map[bool][]subscription
	subscriptionsMu     map[bool]*sync.RWMutex
	connCtx             map[bool]context.Context
	connCancel          map[bool]context.CancelFunc
}

const (
	writeWait  = 3 * time.Second
	pongWait   = 30 * time.Second
	PingPeriod = (pongWait * 8) / 10
)

// NewClient returns a pointer to a fresh ClientWs
func NewClient(ctx context.Context, apiKey, secretKey, passphrase string, url map[bool]okex.BaseURL) *ClientWs {
	ctx, cancel := context.WithCancel(ctx)
	c := &ClientWs{
		apiKey:          apiKey,
		secretKey:       []byte(secretKey),
		passphrase:      passphrase,
		ctx:             ctx,
		Cancel:          cancel,
		url:             url,
		sendChan:        map[bool]chan []byte{true: make(chan []byte, 3), false: make(chan []byte, 3)},
		DoneChan:        make(chan interface{}),
		conn:            make(map[bool]*websocket.Conn),
		dialer:          websocket.DefaultDialer,
		lastTransmit:    make(map[bool]*time.Time),
		mu:              map[bool]*sync.RWMutex{true: {}, false: {}},
		retryConfig:     DefaultRetryConfig,
		retryCount:      map[bool]int{true: 0, false: 0},
		reconnecting:    map[bool]bool{true: false, false: false},
		reconnectMu:     map[bool]*sync.Mutex{true: {}, false: {}},
		subscriptions:   map[bool][]subscription{true: {}, false: {}},
		subscriptionsMu: map[bool]*sync.RWMutex{true: {}, false: {}},
		connCtx:         map[bool]context.Context{},
		connCancel:      map[bool]context.CancelFunc{},
	}
	c.Private = NewPrivate(c)
	c.Public = NewPublic(c)
	c.Trade = NewTrade(c)
	return c
}

// Connect into the server
//
// https://www.okex.com/docs-v5/en/#websocket-api-connect
func (c *ClientWs) Connect(p bool) error {
	if c.conn[p] != nil {
		return nil
	}
	err := c.dial(p)
	if err == nil {
		c.retryCount[p] = 0 // Reset retry count on successful connection
		return nil
	}

	// Retry with exponential backoff
	interval := c.retryConfig.InitialInterval
	for {
		// Check if max retries exceeded
		if c.retryConfig.MaxRetries > 0 && c.retryCount[p] >= c.retryConfig.MaxRetries {
			return fmt.Errorf("max retries (%d) exceeded: %w", c.retryConfig.MaxRetries, err)
		}

		c.retryCount[p]++

		select {
		case <-time.After(interval):
			err = c.dial(p)
			if err == nil {
				c.retryCount[p] = 0 // Reset retry count on successful connection
				return nil
			}
			// Calculate next interval with exponential backoff
			interval = time.Duration(float64(interval) * c.retryConfig.Multiplier)
			if interval > c.retryConfig.MaxInterval {
				interval = c.retryConfig.MaxInterval
			}
		case <-c.ctx.Done():
			return c.handleCancel("connect")
		}
	}
}

// Login
//
// https://www.okex.com/docs-v5/en/#websocket-api-login
func (c *ClientWs) Login() error {
	if c.Authorized {
		return nil
	}
	if c.AuthRequested != nil && time.Since(*c.AuthRequested).Seconds() < 30 {
		return nil
	}
	now := time.Now()
	c.AuthRequested = &now
	method := http.MethodGet
	path := "/users/self/verify"
	ts, sign := c.sign(method, path)
	args := []map[string]string{
		{
			"apiKey":     c.apiKey,
			"passphrase": c.passphrase,
			"timestamp":  ts,
			"sign":       sign,
		},
	}
	return c.Send(true, okex.LoginOperation, args)
}

// Subscribe
// Users can choose to subscribe to one or more channels, and the total length of multiple channels cannot exceed 4096 bytes.
//
// https://www.okex.com/docs-v5/en/#websocket-api-subscribe
func (c *ClientWs) Subscribe(p bool, ch []okex.ChannelName, args ...map[string]string) error {
	chCount := max(len(ch), 1)
	tmpArgs := make([]map[string]string, chCount*len(args))

	n := 0
	for i := 0; i < chCount; i++ {
		for _, arg := range args {
			tmpArgs[n] = make(map[string]string)
			for k, v := range arg {
				tmpArgs[n][k] = v
			}
			if len(ch) > 0 {
				tmpArgs[n]["channel"] = string(ch[i])
			}
			n++
		}
	}

	err := c.Send(p, okex.SubscribeOperation, tmpArgs)
	if err != nil {
		return err
	}

	// Save subscription for re-subscription on reconnect
	c.subscriptionsMu[p].Lock()
	c.subscriptions[p] = append(c.subscriptions[p], subscription{
		channels: ch,
		args:     args,
	})
	c.subscriptionsMu[p].Unlock()

	return nil
}

// Unsubscribe into channel(s)
//
// https://www.okex.com/docs-v5/en/#websocket-api-unsubscribe
func (c *ClientWs) Unsubscribe(p bool, ch []okex.ChannelName, args map[string]string) error {
	tmpArgs := make([]map[string]string, len(ch))
	for i, name := range ch {
		tmpArgs[i] = make(map[string]string)
		tmpArgs[i]["channel"] = string(name)
		for k, v := range args {
			tmpArgs[i][k] = v
		}
	}
	err := c.Send(p, okex.UnsubscribeOperation, tmpArgs)
	if err != nil {
		return err
	}

	// Remove subscription from tracker
	c.subscriptionsMu[p].Lock()
	filtered := make([]subscription, 0)
	for _, sub := range c.subscriptions[p] {
		// Check if this subscription matches the unsubscribe request
		matches := false
		for _, subCh := range sub.channels {
			for _, unsubCh := range ch {
				if subCh == unsubCh {
					matches = true
					break
				}
			}
			if matches {
				break
			}
		}
		if !matches {
			filtered = append(filtered, sub)
		}
	}
	c.subscriptions[p] = filtered
	c.subscriptionsMu[p].Unlock()

	return nil
}

// Send message through either connections
func (c *ClientWs) Send(p bool, op okex.Operation, args []map[string]string, extras ...map[string]string) error {
	if op != okex.LoginOperation {
		err := c.Connect(p)
		if err == nil {
			if p {
				err = c.WaitForAuthorization()
				if err != nil {
					return err
				}
			}
		} else {
			return err
		}
	}

	data := map[string]interface{}{
		"op":   op,
		"args": args,
	}
	for _, extra := range extras {
		for k, v := range extra {
			data[k] = v
		}
	}
	j, err := json.Marshal(data)
	if err != nil {
		return err
	}
	c.sendChan[p] <- j
	return nil
}

// SetChannels to receive certain events on separate channel
func (c *ClientWs) SetChannels(errCh chan *events.Error, subCh chan *events.Subscribe, unSub chan *events.Unsubscribe, lCh chan *events.Login, sCh chan *events.Success) {
	c.ErrChan = errCh
	c.SubscribeChan = subCh
	c.UnsubscribeChan = unSub
	c.LoginChan = lCh
	c.SuccessChan = sCh
}

// SetDialer sets a custom dialer for the WebSocket connection.
func (c *ClientWs) SetDialer(dialer *websocket.Dialer) {
	c.dialer = dialer
}

// SetRetryConfig sets a custom retry configuration for the WebSocket connection.
func (c *ClientWs) SetRetryConfig(config RetryConfig) {
	c.retryConfig = config
}

func (c *ClientWs) SetEventChannels(structuredEventCh chan interface{}, rawEventCh chan *events.Basic) {
	c.StructuredEventChan = structuredEventCh
	c.RawEventChan = rawEventCh
}

// WaitForAuthorization waits for the auth response and try to log in if it was needed
func (c *ClientWs) WaitForAuthorization() error {
	if c.Authorized {
		return nil
	}
	if err := c.Login(); err != nil {
		return err
	}
	ticker := time.NewTicker(time.Millisecond * 300)
	defer ticker.Stop()
	for range ticker.C {
		if c.Authorized {
			return nil
		}
	}
	return nil
}

func (c *ClientWs) dial(p bool) error {
	c.mu[p].Lock()
	conn, res, err := c.dialer.Dial(string(c.url[p]), nil)
	if err != nil {
		var statusCode int
		if res != nil {
			statusCode = res.StatusCode
		}
		c.mu[p].Unlock()
		return fmt.Errorf("error %d: %w", statusCode, err)
	}
	c.conn[p] = conn

	// Create connection-specific context
	connCtx, connCancel := context.WithCancel(c.ctx)
	c.connCtx[p] = connCtx
	c.connCancel[p] = connCancel
	c.mu[p].Unlock()

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			fmt.Printf("error closing body: %v\n", err)
		}
	}(res.Body)
	go func() {
		err := c.receiver(p)
		if err != nil {
			fmt.Printf("receiver error: %v\n", err)
			c.reconnect(p)
		}
	}()
	go func() {
		err := c.sender(p)
		if err != nil {
			fmt.Printf("sender error: %v\n", err)
			c.reconnect(p)
		}
	}()

	return nil
}

// reconnect handles the reconnection logic when the connection is lost
func (c *ClientWs) reconnect(p bool) {
	c.reconnectMu[p].Lock()
	// Check if already reconnecting
	if c.reconnecting[p] {
		c.reconnectMu[p].Unlock()
		return
	}
	c.reconnecting[p] = true
	c.reconnectMu[p].Unlock()

	// Cancel old connection context to stop sender/receiver goroutines
	c.mu[p].Lock()
	if c.connCancel[p] != nil {
		c.connCancel[p]()
	}

	// Close existing connection if any
	if c.conn[p] != nil {
		_ = c.conn[p].Close()
		c.conn[p] = nil
	}

	// Close old sendChan and create a new one
	oldSendChan := c.sendChan[p]
	c.sendChan[p] = make(chan []byte, 3)
	c.mu[p].Unlock()

	// Drain old sendChan to prevent goroutine leaks
	go func() {
		for range oldSendChan {
			// Drain the channel
		}
	}()
	close(oldSendChan)

	// Wait a bit for old goroutines to exit
	time.Sleep(100 * time.Millisecond)

	// Reset authorization state if it's a private connection
	if p {
		c.Authorized = false
		c.AuthRequested = nil
	}

	// Attempt to reconnect
	fmt.Printf("attempting to reconnect (private=%v)...\n", p)
	err := c.Connect(p)

	c.reconnectMu[p].Lock()
	c.reconnecting[p] = false
	c.reconnectMu[p].Unlock()

	if err != nil {
		fmt.Printf("reconnection failed (private=%v): %v\n", p, err)
		return
	}

	fmt.Printf("successfully reconnected (private=%v)\n", p)

	// Wait a bit for new sender goroutine to be ready
	time.Sleep(100 * time.Millisecond)

	// Re-subscribe to all previous subscriptions
	c.resubscribe(p)
}

// resubscribe re-subscribes to all saved subscriptions after reconnection
func (c *ClientWs) resubscribe(p bool) {
	c.subscriptionsMu[p].RLock()
	subs := make([]subscription, len(c.subscriptions[p]))
	copy(subs, c.subscriptions[p])
	c.subscriptionsMu[p].RUnlock()

	if len(subs) == 0 {
		return
	}

	fmt.Printf("re-subscribing to %d subscription(s) (private=%v)...\n", len(subs), p)

	// Clear subscriptions before re-subscribing to avoid duplication
	c.subscriptionsMu[p].Lock()
	c.subscriptions[p] = []subscription{}
	c.subscriptionsMu[p].Unlock()

	// Re-subscribe to each saved subscription
	for _, sub := range subs {
		err := c.Subscribe(p, sub.channels, sub.args...)
		if err != nil {
			fmt.Printf("failed to re-subscribe (private=%v): %v\n", p, err)
		}
	}

	fmt.Printf("re-subscription complete (private=%v)\n", p)
}

func (c *ClientWs) sender(p bool) error {
	ticker := time.NewTicker(time.Millisecond * 300)
	defer ticker.Stop()

	// Get connection-specific context
	c.mu[p].RLock()
	connCtx := c.connCtx[p]
	c.mu[p].RUnlock()

	for {
		select {
		case data := <-c.sendChan[p]:
			c.mu[p].RLock()
			conn := c.conn[p]
			if conn == nil {
				c.mu[p].RUnlock()
				return fmt.Errorf("connection is nil")
			}
			err := conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err != nil {
				c.mu[p].RUnlock()
				return err
			}
			w, err := conn.NextWriter(websocket.TextMessage)
			if err != nil {
				c.mu[p].RUnlock()
				return err
			}
			if _, err = w.Write(data); err != nil {
				c.mu[p].RUnlock()
				return err
			}
			now := time.Now()
			c.lastTransmit[p] = &now
			c.mu[p].RUnlock()
			if err := w.Close(); err != nil {
				return err
			}
		case <-ticker.C:
			c.mu[p].RLock()
			conn := c.conn[p]
			lastTransmit := c.lastTransmit[p]
			sendChan := c.sendChan[p]
			c.mu[p].RUnlock()
			if conn != nil && (lastTransmit == nil || (lastTransmit != nil && time.Since(*lastTransmit) > PingPeriod)) {
				select {
				case sendChan <- []byte("ping"):
				default:
					// Channel is full, skip ping
				}
			}
		case <-connCtx.Done():
			return fmt.Errorf("connection context cancelled")
		case <-c.ctx.Done():
			return c.handleCancel("sender")
		}
	}
}

func (c *ClientWs) receiver(p bool) error {
	// Get connection-specific context
	c.mu[p].RLock()
	connCtx := c.connCtx[p]
	c.mu[p].RUnlock()

	for {
		select {
		case <-connCtx.Done():
			return fmt.Errorf("connection context cancelled")
		case <-c.ctx.Done():
			return c.handleCancel("receiver")
		default:
			c.mu[p].RLock()
			conn := c.conn[p]
			if conn == nil {
				c.mu[p].RUnlock()
				return fmt.Errorf("connection is nil")
			}
			err := conn.SetReadDeadline(time.Now().Add(pongWait))
			if err != nil {
				c.mu[p].RUnlock()
				return err
			}
			mt, data, err := conn.ReadMessage()
			if err != nil {
				c.mu[p].RUnlock()
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
					_ = conn.Close()
				}
				return err
			}
			c.mu[p].RUnlock()
			now := time.Now()
			c.mu[p].Lock()
			c.lastTransmit[p] = &now
			c.mu[p].Unlock()
			if mt == websocket.TextMessage && string(data) != "pong" {
				e := &events.Basic{}
				if err := json.Unmarshal(data, &e); err != nil {
					return err
				}
				go func() {
					c.process(data, e)
				}()
			}
		}
	}
}

func (c *ClientWs) sign(method, path string) (string, string) {
	t := time.Now().UTC().Unix()
	ts := fmt.Sprint(t)
	s := ts + method + path
	p := []byte(s)
	h := hmac.New(sha256.New, c.secretKey)
	h.Write(p)
	return ts, base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func (c *ClientWs) handleCancel(msg string) error {
	go func() {
		c.DoneChan <- msg
	}()
	return fmt.Errorf("operation cancelled: %s", msg)
}

func (c *ClientWs) process(data []byte, e *events.Basic) bool {
	switch e.Event {
	case "error":
		e := events.Error{}
		_ = json.Unmarshal(data, &e)
		if c.ErrChan != nil {
			c.ErrChan <- &e
		}
		return true
	case "subscribe":
		e := events.Subscribe{}
		_ = json.Unmarshal(data, &e)
		if c.SubscribeChan != nil {
			c.SubscribeChan <- &e
		}
		if c.StructuredEventChan != nil {
			c.StructuredEventChan <- e
		}
		return true
	case "unsubscribe":
		e := events.Unsubscribe{}
		_ = json.Unmarshal(data, &e)
		if c.UnsubscribeChan != nil {
			c.UnsubscribeChan <- &e
		}
		if c.StructuredEventChan != nil {
			c.StructuredEventChan <- e
		}
		return true
	case "login":
		if time.Since(*c.AuthRequested).Seconds() > 30 {
			c.AuthRequested = nil
			_ = c.Login()
			break
		}
		c.Authorized = true
		e := events.Login{}
		_ = json.Unmarshal(data, &e)
		if c.LoginChan != nil {
			c.LoginChan <- &e
		}
		if c.StructuredEventChan != nil {
			c.StructuredEventChan <- e
		}
		return true
	}
	if c.Private.Process(data, e) {
		return true
	}
	if c.Public.Process(data, e) {
		return true
	}
	if e.ID != "" {
		if e.Code != 0 {
			ee := *e
			ee.Event = "error"
			return c.process(data, &ee)
		}
		e := events.Success{}
		_ = json.Unmarshal(data, &e)
		if c.SuccessChan != nil {
			c.SuccessChan <- &e
		}
		if c.StructuredEventChan != nil {
			c.StructuredEventChan <- e
		}
		return true
	}
	c.RawEventChan <- e
	return false
}
