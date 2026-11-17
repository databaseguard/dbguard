// Package pipeline is DBGuard's event backbone. Producers call Ingest; a
// small worker pool enriches each event with workload identity and wire
// metadata, evaluates it against policy, runs the detector stack, records
// metrics and finally fans out to the audit store, alert sinks and stream
// subscribers (the admin API's SSE endpoint and the CLI tail).
//
// Stages run synchronously per event inside a worker:
//
//	1 enrich     resolver identity, engine guess, SQL table/column parse
//	2 policy     Engine.Evaluate verdict, actions, severity, rule ids
//	3 detectors  Detector.Evaluate findings merged onto the event
//	4 finalize   metrics (events, rule matches, actions, latency)
//	5 fan-out    audit store, alert sinks (bounded, 5s timeout), subscribers
//
// The pipeline is safe for concurrent Ingest; Shutdown order is: cancel the
// Run context, then Close (which flushes the audit store).
package pipeline

import (
	"context"
	"log/slog"
	"runtime"
	"sync"
	"time"

	"github.com/databaseguard/dbguard/internal/alert"
	"github.com/databaseguard/dbguard/internal/audit"
	"github.com/databaseguard/dbguard/internal/config"
	"github.com/databaseguard/dbguard/internal/detect"
	"github.com/databaseguard/dbguard/internal/enrich"
	"github.com/databaseguard/dbguard/internal/events"
	"github.com/databaseguard/dbguard/internal/metrics"
	"github.com/databaseguard/dbguard/internal/policy"
	"github.com/databaseguard/dbguard/internal/proto"
)

// Pipeline tunables.
const (
	ingestBuffer     = 8192 // Ingest backlog before drops
	auditQueue       = 8192 // audit writer backlog before drops
	alertTimeout     = 5 * time.Second
	alertMaxInflight = 64  // max concurrent sink deliveries
	maxWorkers       = 4   // worker pool cap
	defaultSubBuffer = 128 // per-subscriber buffer when none requested
)

// Pipeline connects producers to the enrichment/policy/detection stages and
// the fan-out targets. Construct with NewPipeline; run with Run; stop by
// cancelling the Run context and calling Close.
type Pipeline struct {
	cfg   config.Config
	eng   *policy.Engine
	res   enrich.Resolver
	dets  []detect.Detector
	sinks []alert.Sink
	store audit.Store
	rec   metrics.Recorder
	log   *slog.Logger

	ch       chan *events.Event // ingest queue (never closed)
	auditCh  chan *events.Event // audit writer queue (closed by Close)
	alertSem chan struct{}      // bounds concurrent sink deliveries

	subsMu  sync.Mutex
	subs    map[int]chan *events.Event
	nextSub int

	workerWg  sync.WaitGroup
	auditWg   sync.WaitGroup
	closeOnce sync.Once
}

// NewPipeline wires a pipeline from its collaborators. Nil optional
// collaborators are replaced with safe defaults (noop resolver, discard
// store/recorder, empty policy engine). The single audit writer goroutine
// is started here; worker goroutines start with Run.
func NewPipeline(cfg config.Config, eng *policy.Engine, res enrich.Resolver, dets []detect.Detector,
	sinks []alert.Sink, store audit.Store, rec metrics.Recorder, log *slog.Logger) *Pipeline {
	if log == nil {
		log = slog.Default()
	}
	if eng == nil {
		eng = policy.New(log)
	}
	if res == nil {
		res = enrich.NewNoop()
	}
	if store == nil {
		store = audit.NewNoop()
	}
	if rec == nil {
		rec = metrics.NewNoop()
	}
	p := &Pipeline{
		cfg:      cfg,
		eng:      eng,
		res:      res,
		dets:     dets,
		sinks:    sinks,
		store:    store,
		rec:      rec,
		log:      log,
		ch:       make(chan *events.Event, ingestBuffer),
		auditCh:  make(chan *events.Event, auditQueue),
		alertSem: make(chan struct{}, alertMaxInflight),
		subs:     make(map[int]chan *events.Event),
	}
	p.auditWg.Add(1)
	go p.auditWriter()
	return p
}

// Ingest queues one event for processing. It never blocks: when the backlog
// is full the event is dropped, counted via metrics (IncEvent "dropped") and
// logged. Zero ID/Time are filled in.
func (p *Pipeline) Ingest(ev *events.Event) {
	if ev == nil {
		return
	}
	if ev.ID == "" {
		ev.ID = events.NewID()
	}
	if ev.Time.IsZero() {
		ev.Time = time.Now().UTC()
	}
	select {
	case p.ch <- ev:
	default:
		p.rec.IncEvent("dropped", string(events.SevInfo))
		p.log.Warn("pipeline: ingest buffer full, dropping event",
			"type", ev.Type, "pid", ev.PID, "session", ev.SessionID)
	}
}

// Run starts the worker pool (min(maxWorkers, NumCPU) goroutines) consuming
// the ingest queue and blocks until ctx is cancelled or Close is called.
// Call it exactly once, in its own goroutine.
func (p *Pipeline) Run(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	workers := runtime.NumCPU()
	if workers > maxWorkers {
		workers = maxWorkers
	}
	if workers < 1 {
		workers = 1
	}
	p.workerWg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer p.workerWg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case ev, ok := <-p.ch:
					if !ok {
						return
					}
					p.process(ev)
				}
			}
		}()
	}
	p.workerWg.Wait()
	return nil
}

// process runs stages 1-5 for one event.
func (p *Pipeline) process(ev *events.Event) {
	start := time.Now()
	p.enrichStage(ev)
	dec := p.policyStage(ev)
	p.detectStage(ev)
	p.finalizeStage(ev, dec, start)
	p.fanoutStage(ev)
}

// enrichStage (stage 1): workload identity, engine guess, SQL metadata.
func (p *Pipeline) enrichStage(ev *events.Event) {
	id := p.res.Resolve(ev.PID, ev.CgroupID)
	if id.ContainerID != "" {
		ev.ContainerID = id.ContainerID
	}
	if id.PodName != "" {
		ev.PodName = id.PodName
	}
	if id.Namespace != "" {
		ev.Namespace = id.Namespace
	}
	if len(id.Labels) > 0 {
		if ev.Labels == nil {
			ev.Labels = make(map[string]string, len(id.Labels))
		}
		for k, v := range id.Labels {
			if _, ok := ev.Labels[k]; !ok {
				ev.Labels[k] = v
			}
		}
	}
	// Cilium security identity for the client IP (optional; present only when
	// identity.cilium_enabled and the local Cilium agent knows the IP). This is
	// the L3-identity → L7-statement binding: the audit record carries the pod
	// identity that ran the query, not just its (ephemeral) IP.
	if ev.ClientIP != "" && ev.CiliumID == "" {
		if l, ok := p.res.(enrich.CiliumLookup); ok {
			if cid, labels, ok := l.LookupForIP(ev.ClientIP); ok && cid != "" {
				ev.CiliumID = cid
				ev.CiliumLabels = labels
				ev.MetaSet("cilium_identity", cid)
			}
		}
	}
	if ev.Engine == "" && ev.ServerPort > 0 {
		if eng := proto.GuessEngine(ev.ServerPort); eng != proto.EngineUnknown {
			ev.Engine = string(eng)
		}
	}
	if ev.SQL != "" {
		if ev.SQLLen == 0 {
			ev.SQLLen = len(ev.SQL)
		}
		ev.Tables = proto.ExtractTables(ev.SQL)
		switch ev.Engine {
		case "postgres", "mysql":
			ev.Columns = proto.ExtractColumns(ev.SQL)
		}
	}
	ev.MetaSet("session_key", events.SessionKey(ev.ClientIP, ev.ClientPort, ev.ServerPort))
}

// policyStage (stage 2): firewall verdict. Returns the raw decision so the
// finalize stage can count rule matches.
func (p *Pipeline) policyStage(ev *events.Event) policy.Decision {
	pctx := &policy.Context{
		Engine:         ev.Engine,
		User:           ev.User,
		Database:       ev.Database,
		ClientIP:       ev.ClientIP,
		SQL:            ev.SQL,
		Tables:         ev.Tables,
		Columns:        ev.Columns,
		SessionID:      ev.SessionID,
		PID:            ev.PID,
		Labels:         ev.Labels,
		CiliumIdentity: ev.CiliumID, // set by the enrich stage (runs before this)
		CiliumLabels:   ev.CiliumLabels,
		Now:            ev.Time,
	}
	dec := p.eng.Evaluate(pctx)
	ev.Allowed = dec.Allowed
	for _, a := range dec.Actions {
		ev.AddAction(a)
	}
	if len(dec.RuleIDs) > 0 {
		ev.RuleID = dec.RuleIDs[0]
		if len(dec.RuleNames) > 0 {
			ev.RuleName = dec.RuleNames[0]
		}
	}
	if dec.Severity.Order() > ev.Severity.Order() {
		ev.Severity = dec.Severity
	}
	// belt and braces: any enforcement action implies a blocked statement
	for _, a := range ev.Actions {
		if isDenyAction(a) {
			ev.Allowed = false
			break
		}
	}
	return dec
}

// detectStage (stage 3): merge detector findings, count them per module.
func (p *Pipeline) detectStage(ev *events.Event) {
	for _, d := range p.dets {
		for _, f := range d.Evaluate(ev) {
			if hasFinding(ev.Findings, f) {
				continue
			}
			ev.Findings = append(ev.Findings, f)
			p.rec.IncFinding(d.Name(), f.Kind)
		}
	}
}

// finalizeStage (stage 4): metrics for the processed event.
func (p *Pipeline) finalizeStage(ev *events.Event, dec policy.Decision, start time.Time) {
	p.rec.IncEvent(string(ev.Type), string(ev.Severity))
	for _, id := range dec.RuleIDs {
		p.rec.IncRuleMatch(id)
	}
	for _, a := range ev.Actions {
		p.rec.IncAction(string(a))
	}
	p.rec.ObservePipelineLatency(time.Since(start).Seconds())
}

// fanoutStage (stage 5): audit trail first (so slow sinks can never starve
// it), then alert sinks under a bounded semaphore, then stream subscribers.
func (p *Pipeline) fanoutStage(ev *events.Event) {
	if p.cfg.Audit.Enabled {
		select {
		case p.auditCh <- ev:
		default:
			p.log.Warn("pipeline: audit queue full, event not persisted", "id", ev.ID)
		}
	}
	if alert.IsAlertWorthy(ev, events.ParseSeverity(p.cfg.Alerts.MinSeverity)) {
		for _, s := range p.sinks {
			select {
			case p.alertSem <- struct{}{}:
				go func(sink alert.Sink, ev *events.Event) {
					defer func() { <-p.alertSem }()
					ctx, cancel := context.WithTimeout(context.Background(), alertTimeout)
					defer cancel()
					if err := sink.Send(ctx, ev); err != nil {
						p.log.Warn("pipeline: alert sink delivery failed",
							"sink", sink.Name(), "event", ev.ID, "err", err)
					}
				}(s, ev.Clone())
			default:
				p.log.Warn("pipeline: alert fan-out busy, dropping delivery", "sink", s.Name(), "event", ev.ID)
			}
		}
	}
	p.publish(ev)
}

// publish pushes a clone of the event to every subscriber (drop on slow
// consumers so the pipeline never blocks on the SSE path).
func (p *Pipeline) publish(ev *events.Event) {
	p.subsMu.Lock()
	defer p.subsMu.Unlock()
	for _, ch := range p.subs {
		select {
		case ch <- ev.Clone():
		default:
		}
	}
}

// Subscribe registers a live event consumer for SSE / tail support. The
// returned cancel func unregisters and closes the channel; it is safe to
// call more than once. Subscribers must be registered before Close.
func (p *Pipeline) Subscribe(buffered int) (<-chan *events.Event, func()) {
	if buffered <= 0 {
		buffered = defaultSubBuffer
	}
	p.subsMu.Lock()
	defer p.subsMu.Unlock()
	id := p.nextSub
	p.nextSub++
	ch := make(chan *events.Event, buffered)
	p.subs[id] = ch
	var once sync.Once
	return ch, func() {
		p.subsMu.Lock()
		defer p.subsMu.Unlock()
		if _, ok := p.subs[id]; ok {
			delete(p.subs, id)
			once.Do(func() { close(ch) })
		}
	}
}

// auditWriter is the single goroutine draining the audit queue into the
// store; it exits once Close closes the queue.
func (p *Pipeline) auditWriter() {
	defer p.auditWg.Done()
	for ev := range p.auditCh {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := p.store.Append(ctx, ev); err != nil {
			p.log.Warn("pipeline: audit append failed", "event", ev.ID, "err", err)
		}
		cancel()
	}
}

// Close stops the pipeline: it waits for in-flight workers (cancel the Run
// context first), drains the audit queue into the store, flushes the store
// and closes all subscriber channels. Idempotent.
func (p *Pipeline) Close() error {
	p.closeOnce.Do(func() {
		p.workerWg.Wait()
		close(p.auditCh)
		p.auditWg.Wait()
		if err := p.store.Close(); err != nil {
			p.log.Warn("pipeline: audit store close failed", "err", err)
		}
		p.subsMu.Lock()
		for id, ch := range p.subs {
			close(ch)
			delete(p.subs, id)
		}
		p.subsMu.Unlock()
	})
	return nil
}

// isDenyAction reports whether the action enforces a block.
func isDenyAction(a events.Action) bool {
	switch a {
	case events.ActDeny, events.ActDrop, events.ActReset, events.ActKill,
		events.ActFreeze, events.ActQuarantine:
		return true
	}
	return false
}

// hasFinding reports whether an identical finding was already merged.
func hasFinding(fs []events.Finding, f events.Finding) bool {
	for _, x := range fs {
		if x.Kind == f.Kind && x.Start == f.Start && x.End == f.End && x.Detail == f.Detail {
			return true
		}
	}
	return false
}
