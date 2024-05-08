// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2024 Matthew Penner

package certwatcher

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"

	"github.com/matthewpi/certwatcher/internal/ocsp"
	"github.com/matthewpi/certwatcher/internal/sets"
	"github.com/matthewpi/certwatcher/internal/wait"
)

// Options controls options for a [Watcher]. Changes to Options are ignored
// after being provided to a [Watcher].
type Options struct {
	// Debounce is the duration to wait before triggering a reload, it's purpose
	// is to ensure that if multiple watched files are updated during it's
	// duration, that multiple full reloads are not triggered.
	Debounce time.Duration

	// DontStaple controls whether OCSP stapling should be disabled when loading
	// certificates, by default it is enabled.
	DontStaple bool

	// Logger to use for the [Watcher] instance.
	Logger *slog.Logger
}

// Watcher watches for changes to TLS certificate files on disk and attempts to
// automatically reload the certificate. This is used to allow the graceful
// rotation of certificates.
//
// Watcher is also capable of performing OCSP stapling when (re)loading
// certificates.
type Watcher struct {
	options  Options
	certPath string
	keyPath  string

	cert     atomic.Pointer[tls.Certificate]
	debounce debounced

	fsWatcher *fsnotify.Watcher

	logger *slog.Logger

	meter                   metric.Meter
	reconfigureTotalCounter metric.Int64Counter
	reconfigureErrorCounter metric.Int64Counter
}

// New creates a new certwatcher [Watcher], capable of reloading certificates on
// the fly.
//
// After calling New, you will want to configure it with Watcher.Reconfigure()
// and then run Watcher.Start().
func New(options Options) (*Watcher, error) {
	d := options.Debounce
	if d < 10*time.Millisecond {
		d = 100 * time.Millisecond
	}
	w := &Watcher{
		options:  options,
		logger:   options.Logger,
		meter:    otel.Meter("github.com/matthewpi/certwatcher"),
		debounce: debounce(d),
	}
	if w.logger == nil {
		w.logger = slog.Default()
	}

	var err error
	w.reconfigureTotalCounter, err = w.meter.Int64Counter("certwatcher.reconfigure.total")
	if err != nil {
		return nil, fmt.Errorf("certwatcher: failed to create otel meter: %w", err)
	}
	w.reconfigureErrorCounter, err = w.meter.Int64Counter("certwatcher.reconfigure.errors")
	if err != nil {
		return nil, fmt.Errorf("certwatcher: failed to create otel meter: %w", err)
	}
	w.fsWatcher, err = fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("certwatcher: failed to create fswatcher: %w", err)
	}
	return w, nil
}

// GetCertificate satisfies tls.Config#GetCertificate. This function should be
// used on a tls.Config to use the certificate loaded by certwatcher.
func (w *Watcher) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return w.cert.Load(), nil
}

// GetClientCertificate satisfies tls.Config#GetClientCertificate. This function
// should be used on a tls.Config to use the certificate loaded by certwatcher.
func (w *Watcher) GetClientCertificate(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return w.cert.Load(), nil
}

// Reconfigure reconfigures the [Watcher] to watch the given `certPath` and
// `keyPath`.
//
// This method is both used for initial configuration and for reconfiguration
// if the certificate paths need to be changed (e.g. config hot-reloading).
func (w *Watcher) Reconfigure(ctx context.Context, certPath, keyPath string) error {
	// Load the certificate from disk.
	w.reconfigureTotalCounter.Add(ctx, 1)
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		w.reconfigureErrorCounter.Add(ctx, 1)
		return fmt.Errorf("certwatcher: failed to load x509 certificate: %w", err)
	}
	if cert.Leaf == nil {
		cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return fmt.Errorf("certwatcher: failed to parse leaf certificate: %w", err)
		}
	}

	fields := make([]slog.Attr, 2, 4)
	fields[0] = slog.String("cert_path", certPath)
	fields[1] = slog.String("key_path", keyPath)

	now := time.Now()
	notBefore := cert.Leaf.NotBefore
	if !notBefore.IsZero() && now.Before(notBefore) {
		w.logger.LogAttrs(ctx, slog.LevelWarn, "certificate isn't valid yet", fields...)
	}
	notAfter := cert.Leaf.NotAfter
	if !notAfter.IsZero() && now.After(notAfter) {
		w.logger.LogAttrs(ctx, slog.LevelWarn, "certificate has expired", fields...)
	}
	fields = append(
		fields,
		slog.String("not_before", notBefore.Format(time.DateTime)),
		slog.String("not_after", notAfter.Format(time.DateTime)),
	)

	// Attempt to staple the certificate only if we were able to load its leaf.
	cert, err = w.staple(ctx, cert)
	if err != nil {
		w.logger.LogAttrs(ctx, slog.LevelWarn, "failed to staple certificate", slog.Any("err", err))
	}

	// Update the certificate we are serving.
	// We use swap, so we can display a helpful message if this is the first
	// time a certificate was loaded or if it was a reload.
	if wCert := w.cert.Swap(&cert); wCert == nil {
		w.logger.LogAttrs(ctx, slog.LevelInfo, "certificate loaded", fields...)
	} else {
		w.logger.LogAttrs(ctx, slog.LevelInfo, "certificate reloaded", fields...)
	}

	// Configure the filesystem watcher based off the paths given, this will
	// ensure the paths are watched properly. If the paths are changed, this
	// will remove the old paths and start watching only the new ones.
	return w.configureFsWatcher(ctx, certPath, keyPath)
}

// staple attempts to perform OCSP stapling on the supplied certificate.
func (w *Watcher) staple(ctx context.Context, cert tls.Certificate) (tls.Certificate, error) {
	// If stapling is disabled, return the supplied certificate.
	if w.options.DontStaple {
		return cert, nil
	}

	// If the certificate is already stapled, return it.
	if cert.OCSPStaple != nil {
		w.logger.DebugContext(ctx, "certificate was already stapled")
		return cert, nil
	}

	// Attempt to staple the certificate.
	s := ocsp.Stapler{Certificate: cert}

	w.logger.LogAttrs(
		ctx,
		slog.LevelInfo,
		"attempting to staple certificate...",
		slog.Any("ocsp_servers", cert.Leaf.OCSPServer),
		slog.Any("issuing_certificate_url", cert.Leaf.IssuingCertificateURL),
	)
	if err := s.Staple(ctx); err != nil {
		if errors.Is(err, ocsp.ErrNoOCSPServer) {
			w.logger.InfoContext(ctx, "certificate has no ocsp servers, cannot staple")
			return cert, nil
		}
		return cert, fmt.Errorf("certwatcher: error stapling certificate: %w", err)
	}

	// Update the certificate with the stapled one.
	cert = s.Certificate
	if cert.OCSPStaple == nil {
		w.logger.WarnContext(ctx, "certificate was not stapled")
	} else {
		w.logger.InfoContext(ctx, "stapled certificate")
	}
	return cert, nil
}

// configureFsWatcher configures the fswatcher to watch the given paths. If any
// files are already being watched, they will be removed from the watcher before
// watching the newly provided paths.
func (w *Watcher) configureFsWatcher(ctx context.Context, certPath, keyPath string) error {
	// Skip any configuration if the paths haven't changed.
	// (Initial configuration will have w.certPath and w.keyPath as empty)
	if w.certPath == certPath && w.keyPath == keyPath {
		return nil
	}

	// Before trying to configure the filesystem watcher, make sure it exists.
	if w.fsWatcher == nil {
		return nil
	}

	// Stop watching any existing files.
	if wl := w.fsWatcher.WatchList(); len(wl) > 0 {
		if err := w.remove(ctx, wl...); err != nil {
			return err
		}
	}

	// Start watching the new files.
	if err := w.add(ctx, certPath, keyPath); err != nil {
		return err
	}

	// Update the paths stored on the struct, these are used to detect if the
	// paths we are watching have changed to avoid unnecessarily reconfiguring
	// the filesystem watcher.
	w.certPath = certPath
	w.keyPath = keyPath

	return nil
}

// add attempts to add paths to the fsnotify watcher in a consistent way.
func (w *Watcher) add(ctx context.Context, paths ...string) error {
	return w.forPaths(ctx, w.fsWatcher.Add, paths...)
}

// remove attempts to remove paths to the fsnotify watcher in a consistent way.
func (w *Watcher) remove(ctx context.Context, paths ...string) error {
	return w.forPaths(ctx, w.fsWatcher.Remove, paths...)
}

// forPaths is used to consistently do actions with paths and the watcher.
//
// Its job is to handle inconsistency with paths that may be in the process of
// being added or removed from the filesystem and may cause errors if we try
// to add or remove from the watcher.
//
// To do this, we use a Set to hold the list of paths we need to perform an
// action on. Then we use a backoff to retry the action multiple times until
// a timeout is reached.
func (w *Watcher) forPaths(ctx context.Context, fn func(string) error, paths ...string) error {
	set := sets.New(paths...)
	var watchErr error
	err := wait.PollUntilContextTimeout(
		ctx,
		1*time.Second,
		10*time.Second,
		true,
		func(_ context.Context) (done bool, err error) {
			for _, f := range set.UnsortedList() {
				if err := fn(f); err != nil {
					watchErr = err
					// We want to keep trying, so don't return the error.
					return false, nil //nolint:nilerr
				}
				// We've successfully done what we needed to do with the path,
				// remove it from the set.
				set.Delete(f)
			}
			return true, nil
		},
	)
	if err != nil {
		return errors.Join(err, watchErr)
	}
	return nil
}

// Start starts listening for fsnotify events and will automatically reload the
// certificate when necessary.
func (w *Watcher) Start(ctx context.Context) {
	if w.fsWatcher == nil {
		panic("fsWatcher is nil")
		return
	}

	// Close the filesystem watcher whenever the context is canceled.
	defer w.fsWatcher.Close()

	// Run the watcher, blocks until context is cancelled or until the
	// filesystem watcher is closed.
	w.watch(ctx)
}

// watch watches for incoming events from fsnotify and passes them off to
// handleEvent.
func (w *Watcher) watch(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-w.fsWatcher.Events:
			if !ok {
				return
			}
			w.handleEvent(ctx, event)
		case err, ok := <-w.fsWatcher.Errors:
			if !ok {
				return
			}
			w.logger.LogAttrs(ctx, slog.LevelError, "an error occurred while watching files", slog.Any("err", err))
		}
	}
}

// handleEvent handles incoming fsnotify events to detect when we need to reload
// the watched certificate files.
func (w *Watcher) handleEvent(ctx context.Context, event fsnotify.Event) {
	// Filter operations that may modify the file's content.
	switch {
	case event.Op.Has(fsnotify.Create):
	case event.Op.Has(fsnotify.Write):
	case event.Op.Has(fsnotify.Remove):
	default:
		// Explicitly ignore all other event types.
		return
	}

	// If the file was removed, re-watch it.
	if event.Op.Has(fsnotify.Remove) {
		// The handles a case where a file is deleted, then replaced with new
		// content.
		if err := w.fsWatcher.Add(event.Name); err != nil {
			w.logger.LogAttrs(ctx, slog.LevelError, "failed to re-watch file", slog.Any("err", err))
		}
	}

	// Debounce the reload to prevent multiple back-to-back events from
	// triggering more than one reload in a small time-frame.
	w.debounce(func() {
		w.logger.LogAttrs(ctx, slog.LevelInfo, "reloading...")
		if err := w.Reconfigure(ctx, w.certPath, w.keyPath); err != nil {
			w.logger.LogAttrs(ctx, slog.LevelError, "failed to reload certificate", slog.Any("err", err))
		}
	})
}
