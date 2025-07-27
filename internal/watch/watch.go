package watch

import (
	"context"
	"os"
	"time"

	cblog "github.com/charmbracelet/log"
	"github.com/fsnotify/fsnotify"
)

const (
	retryInterval    = 50 * time.Millisecond
	retryMaxInterval = 5 * time.Second
)

// Watch monitors path for modifications and invokes onChange on each change.
// It continues watching even if the file or directory is recreated, using
// exponential backoff to retry. The watcher stops when ctx is canceled. Any
// errors encountered while handling events are sent on the returned channel,
// which is closed when the watcher exits.
func Watch(ctx context.Context, path string, onChange func() error) (<-chan error, error) {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	if err := w.Add(path); err != nil {
		_ = w.Close()
		return nil, err
	}

	errCh := make(chan error, 1)

	go func() {
		defer func() {
			_ = w.Close()
			close(errCh)
		}()
		for {
			select {
			case ev, ok := <-w.Events:
				if !ok {
					return
				}
				if ev.Op&(fsnotify.Create|fsnotify.Write) != 0 {
					if err := onChange(); err != nil {
						select {
						case errCh <- err:
						default:
						}
						cblog.Errorf("watch change: %v", err)
					}
				}
				if ev.Op&(fsnotify.Rename|fsnotify.Remove) != 0 {
					backoff := retryInterval
					for {
						select {
						case <-ctx.Done():
							return
						default:
						}
						time.Sleep(backoff)
						if _, err := os.Stat(path); err == nil {
							if err := w.Add(path); err == nil {
								if err := onChange(); err != nil {
									select {
									case errCh <- err:
									default:
									}
									cblog.Errorf("watch change: %v", err)
								}
								break
							}
						}
						if backoff < retryMaxInterval {
							backoff *= 2
							if backoff > retryMaxInterval {
								backoff = retryMaxInterval
							}
						}
					}
				}
			case err := <-w.Errors:
				if err != nil {
					select {
					case errCh <- err:
					default:
					}
					cblog.Errorf("watch error: %v", err)
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	return errCh, nil
}
