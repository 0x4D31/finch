package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	cblog "github.com/charmbracelet/log"

	"github.com/0x4D31/finch/internal/rules"
	"github.com/0x4D31/finch/internal/sse"
	"github.com/0x4D31/finch/internal/watch"
	suricata "github.com/0x4d31/galah/pkg/suricata"
)

// Loader manages rule engines and Suricata rule sets.
type Loader struct {
	mu          sync.RWMutex
	engineMap   map[string]*rules.Engine
	suricataMap map[string]*atomic.Pointer[suricata.RuleSet]
	watchMap    map[string]context.CancelFunc
	defaultAct  rules.Action
}

// NewLoader creates a Loader for the given default rule action.
func NewLoader(defaultAction string) *Loader {
	return &Loader{
		engineMap:   make(map[string]*rules.Engine),
		suricataMap: make(map[string]*atomic.Pointer[suricata.RuleSet]),
		watchMap:    make(map[string]context.CancelFunc),
		defaultAct:  rules.Action(defaultAction),
	}
}

// LoadEngine loads rules from path and watches for changes.
func (l *Loader) LoadEngine(path string) (*rules.Engine, error) {
	p, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("abs %s: %w", path, err)
	}
	p, err = filepath.EvalSymlinks(p)
	if err != nil {
		return nil, fmt.Errorf("eval symlinks %s: %w", p, err)
	}
	l.mu.RLock()
	eng, ok := l.engineMap[p]
	watching := false
	if ok {
		_, watching = l.watchMap[p]
	}
	l.mu.RUnlock()
	if ok {
		if !watching {
			wCtx, cancel := context.WithCancel(context.Background())
			errCh, err := watch.Watch(wCtx, p, func() error { return eng.LoadFromFile(p) })
			if err != nil {
				cancel()
				return nil, fmt.Errorf("watch rules %s: %w", p, err)
			}
			go func() {
				for e := range errCh {
					cblog.Errorf("rules reload %s failed: %v", p, e)
				}
			}()
			l.mu.Lock()
			l.watchMap[p] = cancel
			l.mu.Unlock()
		}
		return eng, nil
	}
	eng = &rules.Engine{DefaultAction: l.defaultAct}
	if err := eng.LoadFromFile(p); err != nil {
		return nil, fmt.Errorf("load rules %s: %w", p, err)
	}
	wCtx, cancel := context.WithCancel(context.Background())
	errCh, err := watch.Watch(wCtx, p, func() error { return eng.LoadFromFile(p) })
	if err != nil {
		cancel()
		return nil, fmt.Errorf("watch rules %s: %w", p, err)
	}
	go func() {
		for e := range errCh {
			cblog.Errorf("rules reload %s failed: %v", p, e)
		}
	}()
	l.mu.Lock()
	l.engineMap[p] = eng
	l.watchMap[p] = cancel
	l.mu.Unlock()
	return eng, nil
}

// LoadSuricata loads Suricata rules from dir and watches for changes.
func (l *Loader) LoadSuricata(dir string) (*atomic.Pointer[suricata.RuleSet], error) {
	p, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("abs %s: %w", dir, err)
	}
	p, err = filepath.EvalSymlinks(p)
	if err != nil {
		return nil, fmt.Errorf("eval symlinks %s: %w", p, err)
	}
	info, err := os.Stat(p)
	if err != nil {
		return nil, fmt.Errorf("suricata rules dir %s: %w", p, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("suricata rules dir %s: not a directory", p)
	}
	l.mu.RLock()
	ptr, ok := l.suricataMap[p]
	l.mu.RUnlock()
	if ok {
		return ptr, nil
	}
	rs := suricata.NewRuleSet()
	if err := rs.LoadRules(p); err != nil {
		return nil, fmt.Errorf("load suricata %s: %w", p, err)
	}
	cblog.Infof("loaded %d rules from %s", len(rs.Rules), p)
	ptr = &atomic.Pointer[suricata.RuleSet]{}
	ptr.Store(rs)
	wCtx, cancel := context.WithCancel(context.Background())
	errCh, err := watch.Watch(wCtx, p, func() error {
		rs := suricata.NewRuleSet()
		if err := rs.LoadRules(p); err != nil {
			return err
		}
		cblog.Infof("loaded %d rules from %s", len(rs.Rules), p)
		ptr.Store(rs)
		return nil
	})
	if err != nil {
		cancel()
		return nil, fmt.Errorf("watch suricata %s: %w", p, err)
	}
	go func() {
		for e := range errCh {
			cblog.Errorf("suricata reload %s failed: %v", p, e)
		}
	}()
	l.mu.Lock()
	l.suricataMap[p] = ptr
	l.watchMap[p] = cancel
	l.mu.Unlock()
	return ptr, nil
}

// CancelWatchers stops all active watchers.
func (l *Loader) CancelWatchers() {
	l.mu.RLock()
	for _, cancel := range l.watchMap {
		cancel()
	}
	l.mu.RUnlock()
}

// CancelWatcher stops watching the specified path if active.
func (l *Loader) CancelWatcher(path string) {
	p, err := filepath.Abs(path)
	if err != nil {
		return
	}
	p, err = filepath.EvalSymlinks(p)
	if err != nil {
		return
	}
	l.mu.Lock()
	if cancel, ok := l.watchMap[p]; ok {
		cancel()
		delete(l.watchMap, p)
	}
	l.mu.Unlock()
}

// RemoveWatch is an alias for CancelWatcher for backward compatibility.
func (l *Loader) RemoveWatch(path string) { l.CancelWatcher(path) }

// NewSSEServer creates an SSE hub and server bound to addr.
func NewSSEServer(addr string) (*sse.Server, *sse.Hub) {
	hub := sse.NewHub()
	srv := sse.NewServer(addr, hub)
	return srv, hub
}

// ReloadEngines reloads all loaded rule engines from disk.
func (l *Loader) ReloadEngines() {
	l.mu.RLock()
	defer l.mu.RUnlock()
	for path, eng := range l.engineMap {
		if err := eng.LoadFromFile(path); err != nil {
			cblog.Errorf("manual reload %s failed: %v", path, err)
		} else {
			cblog.Infof("rules reloaded for %s via SIGHUP", path)
		}
	}
}

// UnloadEngine stops watching the provided rule file and removes it from the loader.
func (l *Loader) UnloadEngine(path string) {
	p, err := filepath.Abs(path)
	if err == nil {
		if rp, e := filepath.EvalSymlinks(p); e == nil {
			p = rp
		}
	}

	l.mu.Lock()
	if cancel, ok := l.watchMap[p]; ok {
		cancel()
		delete(l.watchMap, p)
	}
	delete(l.engineMap, p)
	l.mu.Unlock()
}

// UnloadSuricata stops watching the provided Suricata rules directory and removes it.
func (l *Loader) UnloadSuricata(dir string) {
	p, err := filepath.Abs(dir)
	if err == nil {
		if rp, e := filepath.EvalSymlinks(p); e == nil {
			p = rp
		}
	}

	l.mu.Lock()
	if cancel, ok := l.watchMap[p]; ok {
		cancel()
		delete(l.watchMap, p)
	}
	delete(l.suricataMap, p)
	l.mu.Unlock()
}
