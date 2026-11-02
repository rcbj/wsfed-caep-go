// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package wsfed

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

const pollMethod = "urn:ietf:rfc:8936"

// Logger receives receiver progress. Nil methods are skipped.
type Logger interface {
	Info(message string)
	Warn(message string)
	Error(message string)
}

type stdLog struct{}

func (stdLog) Info(message string)  { fmt.Println(message) }
func (stdLog) Warn(message string)  { fmt.Fprintln(os.Stderr, message) }
func (stdLog) Error(message string) { fmt.Fprintln(os.Stderr, message) }

// SignalEvent is one delivered security event.
type SignalEvent struct {
	Type     string
	Payload  any
	Subject  map[string]string
	JTI      string
	Sessions []string
	Ended    bool
	Iat      *float64
	Txn      *string
}

// EndFunc is called with the local sessions an event ends.
type EndFunc func(ids []string, event *SignalEvent) error

// HandlerFunc sees one event. A returned error is logged and the SET is still acknowledged.
type HandlerFunc func(event *SignalEvent) error

// TLSConfig is optional CA and mutual-TLS material for the transmitter.
type TLSConfig struct {
	CA   string
	Cert string
	Key  string
}

// ReceiverOptions tunes a poll receiver. Zero values take the defaults.
type ReceiverOptions struct {
	TLS              *TLSConfig
	Headers          func() map[string]string
	EventsRequested  []string
	EndOn            []string
	Index            *MemorySessionIndex
	SubjectAttribute string
	Description      string
	PollIntervalMs   int
	MaxEvents        int
	Log              Logger
}

type flight struct {
	done   chan struct{}
	result bool
	err    error
}

// SignalsReceiver polls a Shared Signals transmitter. The relying party does not start one.
type SignalsReceiver struct {
	Transmitter string

	onEnd            EndFunc
	tls              *tlsMaterial
	headers          func() map[string]string
	eventsRequested  []string
	endOn            []string
	index            *MemorySessionIndex
	subjectAttribute string
	description      string
	pollIntervalMs   int
	maxEvents        int
	log              Logger

	mu       sync.Mutex
	config   map[string]any
	stream   map[string]any
	keys     []map[string]any
	keysAt   time.Time
	running  bool
	ack      []string
	errs     map[string]map[string]string
	handlers map[string][]HandlerFunc
	inflight *flight
	stop     chan struct{}
	done     chan struct{}
	pollMu   sync.Mutex
}

// NewSignalsReceiver requires onEndSessions and an http(s) transmitter.
func NewSignalsReceiver(transmitter string, onEnd EndFunc, opts *ReceiverOptions) (*SignalsReceiver, error) {
	if onEnd == nil {
		return nil, fail("config", "onEndSessions is required")
	}
	if !(strings.HasPrefix(transmitter, "http://") || strings.HasPrefix(transmitter, "https://")) {
		return nil, fail("config", "transmitter must be an http(s) URL")
	}
	if opts == nil {
		opts = &ReceiverOptions{}
	}
	events := opts.EventsRequested
	if events == nil {
		events = append([]string{}, DefaultEventsRequested...)
	}
	endOn := opts.EndOn
	if endOn == nil {
		endOn = append([]string{}, DefaultEndingEvents...)
	}
	index := opts.Index
	if index == nil {
		index = NewMemorySessionIndex(0)
	}
	poll := opts.PollIntervalMs
	if poll == 0 {
		poll = 5000
	}
	maxEvents := opts.MaxEvents
	if maxEvents == 0 {
		maxEvents = 50
	}
	log := opts.Log
	if log == nil {
		log = stdLog{}
	}
	var tlsIn *tlsMaterial
	if opts.TLS != nil {
		tlsIn = &tlsMaterial{CA: opts.TLS.CA, Cert: opts.TLS.Cert, Key: opts.TLS.Key}
	}
	return &SignalsReceiver{
		Transmitter:      strings.TrimRight(transmitter, "/"),
		onEnd:            onEnd,
		tls:              tlsIn,
		headers:          opts.Headers,
		eventsRequested:  events,
		endOn:            endOn,
		index:            index,
		subjectAttribute: opts.SubjectAttribute,
		description:      opts.Description,
		pollIntervalMs:   poll,
		maxEvents:        maxEvents,
		log:              log,
		errs:             map[string]map[string]string{},
		handlers:         map[string][]HandlerFunc{},
	}, nil
}

// Stream is the poll stream, after Start.
func (r *SignalsReceiver) Stream() map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.stream
}

// Track remembers a local session.
func (r *SignalsReceiver) Track(localID string, login *Login, expiresAt *time.Time) {
	r.index.Add(TrackedFrom(localID, login, r.subjectAttribute, expiresAt))
}

// Untrack forgets a local session.
func (r *SignalsReceiver) Untrack(localID string) { r.index.Remove(localID) }

// On registers a handler for an event type. "*" sees every event.
func (r *SignalsReceiver) On(eventType string, handler HandlerFunc) *SignalsReceiver {
	r.mu.Lock()
	r.handlers[eventType] = append(r.handlers[eventType], handler)
	r.mu.Unlock()
	return r
}

func (r *SignalsReceiver) call(method, rawURL string, body any) (int, any, error) {
	headers := map[string]string{"accept": "application/json"}
	if r.headers != nil {
		for key, value := range r.headers() {
			headers[key] = value
		}
	}
	var payload *string
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return 0, nil, failCause("ssf", err.Error(), err)
		}
		text := string(raw)
		payload = &text
		headers["content-type"] = "application/json"
	}
	answer, err := send(rawURL, method, headers, payload, r.tls, "ssf")
	if err != nil {
		return 0, nil, err
	}
	var parsed any
	if answer.Body != "" {
		if err := json.Unmarshal([]byte(answer.Body), &parsed); err != nil {
			parsed = answer.Body
		}
	}
	return answer.Status, parsed, nil
}

func (r *SignalsReceiver) discover() (map[string]any, error) {
	rawURL := r.Transmitter + "/.well-known/ssf-configuration"
	status, parsed, err := r.call("GET", rawURL, nil)
	if err != nil {
		return nil, err
	}
	config, _ := parsed.(map[string]any)
	if status != 200 || config == nil || stringOf(config["configuration_endpoint"]) == "" || stringOf(config["jwks_uri"]) == "" {
		return nil, fail("ssf", rawURL+" answered "+itoa(status)+" without a usable transmitter configuration")
	}
	if supported, ok := config["delivery_methods_supported"].([]any); ok {
		found := false
		for _, item := range supported {
			if item == pollMethod {
				found = true
				break
			}
		}
		if !found {
			return nil, fail("ssf", "the transmitter does not offer poll delivery (RFC 8936)")
		}
	}
	return config, nil
}

func (r *SignalsReceiver) jwks(force bool) ([]map[string]any, error) {
	r.mu.Lock()
	if !force && len(r.keys) > 0 && time.Since(r.keysAt) < time.Hour {
		keys := r.keys
		r.mu.Unlock()
		return keys, nil
	}
	uri := stringOf(r.config["jwks_uri"])
	r.mu.Unlock()
	status, parsed, err := r.call("GET", uri, nil)
	if err != nil {
		return nil, err
	}
	body, _ := parsed.(map[string]any)
	var keys []map[string]any
	if body != nil {
		if list, ok := body["keys"].([]any); ok {
			for _, item := range list {
				if key, ok := item.(map[string]any); ok {
					keys = append(keys, key)
				}
			}
		}
	}
	if status != 200 || keys == nil && (body == nil || body["keys"] == nil) {
		return nil, fail("ssf", "the transmitter's JWKS answered "+itoa(status))
	}
	if keys == nil {
		keys = []map[string]any{}
	}
	r.mu.Lock()
	r.keys = keys
	r.keysAt = time.Now()
	r.mu.Unlock()
	return keys, nil
}

func (r *SignalsReceiver) ensureStream() (map[string]any, error) {
	endpoint := stringOf(r.config["configuration_endpoint"])
	status, parsed, err := r.call("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}
	if status == 200 {
		var all []any
		switch value := parsed.(type) {
		case []any:
			all = value
		case map[string]any:
			if value != nil {
				all = []any{value}
			}
		}
		for _, item := range all {
			stream, ok := item.(map[string]any)
			if !ok || stringOf(stream["stream_id"]) == "" {
				continue
			}
			delivery, _ := stream["delivery"].(map[string]any)
			if stringOf(delivery["method"]) == pollMethod {
				return stream, nil
			}
		}
	} else if status != 404 {
		raw, _ := json.Marshal(parsed)
		text := string(raw)
		if len(text) > 300 {
			text = text[:300]
		}
		return nil, fail("ssf", "listing the streams at "+endpoint+" answered "+itoa(status)+": "+text)
	}
	body := map[string]any{"delivery": map[string]any{"method": pollMethod}, "events_requested": r.eventsRequested}
	if r.description != "" {
		body["description"] = r.description
	}
	status, parsed, err = r.call("POST", endpoint, body)
	if err != nil {
		return nil, err
	}
	stream, _ := parsed.(map[string]any)
	if (status != 200 && status != 201) || stream == nil || stringOf(stream["stream_id"]) == "" {
		raw, _ := json.Marshal(parsed)
		text := string(raw)
		if len(text) > 300 {
			text = text[:300]
		}
		return nil, fail("ssf", "creating a stream at "+endpoint+" answered "+itoa(status)+": "+text)
	}
	return stream, nil
}

// Start discovers the transmitter and polls until Stop. A second Start while running does nothing.
func (r *SignalsReceiver) Start() error {
	r.mu.Lock()
	if r.running {
		r.mu.Unlock()
		return nil
	}
	r.mu.Unlock()
	config, err := r.discover()
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.config = config
	r.mu.Unlock()
	if _, err := r.jwks(true); err != nil {
		return err
	}
	stream, err := r.ensureStream()
	if err != nil {
		return err
	}
	delivery, _ := stream["delivery"].(map[string]any)
	if stringOf(delivery["endpoint_url"]) == "" {
		return fail("ssf", "the stream has no poll endpoint_url")
	}
	r.mu.Lock()
	if r.running {
		r.stream = stream
		r.mu.Unlock()
		return nil
	}
	r.stream = stream
	r.running = true
	r.stop = make(chan struct{})
	r.done = make(chan struct{})
	delivered, _ := stream["events_delivered"].([]any)
	r.log.Info(fmt.Sprintf("ssf: polling stream %s at %s, delivering %d event type(s)", stringOf(stream["stream_id"]), stringOf(delivery["endpoint_url"]), len(delivered)))
	go r.loop()
	r.mu.Unlock()
	return nil
}

// Stop waits until the background poll loop has finished, or 20 seconds.
func (r *SignalsReceiver) Stop() {
	r.mu.Lock()
	r.running = false
	if r.stop != nil {
		select {
		case <-r.stop:
		default:
			close(r.stop)
		}
	}
	done := r.done
	r.mu.Unlock()
	if done == nil {
		return
	}
	select {
	case <-done:
	case <-time.After(20 * time.Second):
	}
}

func (r *SignalsReceiver) loop() {
	defer close(r.done)
	for {
		r.mu.Lock()
		running := r.running
		stop := r.stop
		r.mu.Unlock()
		if !running {
			return
		}
		delay := r.pollIntervalMs
		more, err := r.PollOnce()
		if err != nil {
			r.log.Warn(fmt.Sprintf("ssf: poll failed: %v", err))
			delay = r.pollIntervalMs * 4
			if delay > 60000 {
				delay = 60000
			}
		} else if more {
			delay = 0
		}
		timer := time.NewTimer(time.Duration(delay) * time.Millisecond)
		select {
		case <-stop:
			timer.Stop()
			return
		case <-timer.C:
		}
		r.mu.Lock()
		running = r.running
		r.mu.Unlock()
		if !running {
			return
		}
	}
}

// PollOnce fetches one batch. Overlapping calls share one in-flight result.
func (r *SignalsReceiver) PollOnce() (bool, error) {
	r.pollMu.Lock()
	if r.inflight != nil {
		current := r.inflight
		r.pollMu.Unlock()
		<-current.done
		return current.result, current.err
	}
	current := &flight{done: make(chan struct{})}
	r.inflight = current
	r.pollMu.Unlock()
	result, err := r.pollNow()
	current.result = result
	current.err = err
	r.pollMu.Lock()
	if r.inflight == current {
		r.inflight = nil
	}
	r.pollMu.Unlock()
	close(current.done)
	return result, err
}

func (r *SignalsReceiver) pollNow() (bool, error) {
	r.mu.Lock()
	delivery, _ := r.stream["delivery"].(map[string]any)
	rawURL := stringOf(delivery["endpoint_url"])
	ack := append([]string{}, r.ack...)
	r.ack = nil
	setErrs := r.errs
	r.errs = map[string]map[string]string{}
	r.mu.Unlock()
	body := map[string]any{"maxEvents": r.maxEvents, "returnImmediately": true}
	if len(ack) > 0 {
		body["ack"] = ack
	}
	if len(setErrs) > 0 {
		body["setErrs"] = setErrs
	}
	status, parsed, err := r.call("POST", rawURL, body)
	if err != nil {
		r.restore(ack, setErrs)
		return false, err
	}
	if status != 200 {
		r.restore(ack, setErrs)
		raw, _ := json.Marshal(parsed)
		text := string(raw)
		if len(text) > 300 {
			text = text[:300]
		}
		return false, fail("ssf", "the poll answered "+itoa(status)+": "+text)
	}
	payload, _ := parsed.(map[string]any)
	sets, _ := payload["sets"].(map[string]any)
	for jti, token := range sets {
		text, _ := token.(string)
		if err := r.handle(jti, text); err != nil {
			description := err.Error()
			r.log.Warn("ssf: SET " + jti + " refused: " + description)
			code := "invalid_request"
			if asWs(err) != nil && asWs(err).Code == "signature" {
				code = "invalid_key"
			}
			r.mu.Lock()
			r.errs[jti] = map[string]string{"err": code, "description": description}
			r.mu.Unlock()
			continue
		}
		r.mu.Lock()
		r.ack = append(r.ack, jti)
		r.mu.Unlock()
	}
	more, _ := payload["moreAvailable"].(bool)
	return more, nil
}

func (r *SignalsReceiver) restore(ack []string, setErrs map[string]map[string]string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ack = append(ack, r.ack...)
	merged := map[string]map[string]string{}
	for key, value := range setErrs {
		merged[key] = value
	}
	for key, value := range r.errs {
		merged[key] = value
	}
	r.errs = merged
}

func (r *SignalsReceiver) handle(jti, token string) error {
	keys, err := r.jwks(false)
	if err != nil {
		return err
	}
	header, payload, err := VerifyCompactJWS(token, keys)
	if err != nil {
		message := err.Error()
		if strings.Contains(message, "publishes no") || strings.Contains(message, "does not verify") {
			keys, refreshErr := r.jwks(true)
			if refreshErr != nil {
				return err
			}
			header, payload, err = VerifyCompactJWS(token, keys)
		}
		if err != nil {
			return err
		}
	}
	if typ, ok := header["typ"]; ok && typ != nil && strings.ToLower(fmt.Sprint(typ)) != "secevent+jwt" {
		return fail("validation", "the SET's typ is "+fmt.Sprint(header["typ"]))
	}
	r.mu.Lock()
	issuer := stringOf(r.config["issuer"])
	stream := r.stream
	r.mu.Unlock()
	if stringOf(payload["iss"]) != issuer {
		return fail("validation", "the SET was issued by "+fmt.Sprint(payload["iss"])+", not "+issuer)
	}
	want := stream["aud"]
	var wantList []string
	switch value := want.(type) {
	case nil:
	case []any:
		for _, item := range value {
			wantList = append(wantList, fmt.Sprint(item))
		}
	case string:
		if value != "" {
			wantList = []string{value}
		}
	default:
		if value != nil && fmt.Sprint(value) != "" {
			wantList = []string{fmt.Sprint(value)}
		}
	}
	var audList []string
	switch value := payload["aud"].(type) {
	case nil:
	case []any:
		for _, item := range value {
			audList = append(audList, fmt.Sprint(item))
		}
	default:
		audList = []string{fmt.Sprint(value)}
	}
	if len(wantList) > 0 {
		hit := false
		for _, item := range audList {
			for _, wanted := range wantList {
				if item == wanted {
					hit = true
				}
			}
		}
		if !hit {
			return fail("validation", "the SET is for "+strings.Join(audList, ", ")+", not this stream")
		}
	}
	if payload["jti"] != nil && stringOf(payload["jti"]) != jti {
		return fail("validation", "the SET's jti is not the one it was delivered under")
	}
	events, ok := payload["events"].(map[string]any)
	if !ok || len(events) == 0 {
		return fail("validation", "the SET carries no events")
	}
	for eventType, body := range events {
		var sub any
		if payload["sub_id"] != nil {
			sub = payload["sub_id"]
		} else if item, ok := body.(map[string]any); ok {
			sub = item["subject"]
		}
		subject := SubjectOf(sub, issuer)
		sessions := r.sessionsFor(eventType, subject)
		ends := contains(r.endOn, eventType) && len(sessions) > 0
		event := &SignalEvent{Type: eventType, Payload: body, Subject: subject, JTI: jti, Sessions: sessions, Ended: ends}
		if n, ok := payload["iat"].(float64); ok {
			event.Iat = &n
		}
		if txn, ok := payload["txn"].(string); ok {
			event.Txn = &txn
		}
		if ends {
			if err := r.onEnd(sessions, event); err != nil {
				r.log.Error(fmt.Sprintf("ssf: onEndSessions threw for %s (SET %s is still acknowledged): %v", eventType, jti, err))
				event.Ended = false
			}
			if event.Ended {
				for _, localID := range sessions {
					r.index.Remove(localID)
				}
			}
		}
		r.mu.Lock()
		handlers := append([]HandlerFunc{}, r.handlers[eventType]...)
		handlers = append(handlers, r.handlers["*"]...)
		r.mu.Unlock()
		for _, handler := range handlers {
			func() {
				defer func() {
					if recovered := recover(); recovered != nil {
						r.log.Error(fmt.Sprintf("ssf: a handler for %s threw (SET %s is still acknowledged): %v", eventType, jti, recovered))
					}
				}()
				if err := handler(event); err != nil {
					r.log.Error(fmt.Sprintf("ssf: a handler for %s threw (SET %s is still acknowledged): %v", eventType, jti, err))
				}
			}()
		}
	}
	return nil
}

func (r *SignalsReceiver) sessionsFor(eventType string, subject map[string]string) []string {
	if eventType == Event["verification"] || eventType == Event["stream_updated"] {
		return nil
	}
	if subject["idp_session"] != "" {
		found := r.index.ByIdPSession(subject["idp_session"])
		if len(found) > 0 || eventType == Event["session_revoked"] {
			return found
		}
	}
	if subject["person"] != "" {
		return r.index.ByPerson(subject["person"])
	}
	if subject["email"] != "" {
		return r.index.ByEmail(subject["email"])
	}
	return nil
}

func contains(list []string, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}

// Verify asks the transmitter to send a verification event.
func (r *SignalsReceiver) Verify(state string) error {
	r.mu.Lock()
	endpoint := ""
	if r.config != nil {
		endpoint = stringOf(r.config["verification_endpoint"])
	}
	streamID := stringOf(r.stream["stream_id"])
	r.mu.Unlock()
	if endpoint == "" {
		return fail("ssf", "the transmitter publishes no verification_endpoint")
	}
	body := map[string]any{"stream_id": streamID}
	if state != "" {
		body["state"] = state
	}
	status, _, err := r.call("POST", endpoint, body)
	if err != nil {
		return err
	}
	if status != 200 && status != 204 {
		return fail("ssf", "verification answered "+itoa(status))
	}
	return nil
}
