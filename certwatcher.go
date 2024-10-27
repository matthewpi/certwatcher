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
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
	goocsp "golang.org/x/crypto/ocsp"

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

	// certμ is used to guard writes to [cert].
	//
	// We use both a [sync.Mutex] and [atomic.Pointer] for [cert] for two
	// different reasons.
	//
	// The [atomic.Pointer] protects against race-conditions and is perfect for
	// protecting data that is written infrequently but constantly being read.
	//
	// The [sync.Mutex] is used to guard multiple simultaneous reconfigurations
	// of [cert]. There are multiple ways that [cert] could be modified, and we
	// don't want to have multiple updates running simultaneously, not because
	// they will cause a race-condition, but because it can lead to
	// unpredictable outcomes.
	certμ    sync.Mutex
	cert     atomic.Pointer[tls.Certificate]
	ocsp     *goocsp.Response
	debounce debounced

	fsWatcher *fsnotify.Watcher

	logger *slog.Logger

	meter                   metric.Meter
	reconfigureTotalCounter metric.Int64Counter
	reconfigureErrorCounter metric.Int64Counter
	stapleTotalCounter      metric.Int64Counter
	stapleErrorCounter      metric.Int64Counter
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
	w.stapleTotalCounter, err = w.meter.Int64Counter("certwatcher.ocsp.staple.total")
	if err != nil {
		return nil, fmt.Errorf("certwatcher: failed to create otel meter: %w", err)
	}
	w.stapleErrorCounter, err = w.meter.Int64Counter("certwatcher.ocsp.staple.errors")
	if err != nil {
		return nil, fmt.Errorf("certwatcher: failed to create otel meter: %w", err)
	}
	w.fsWatcher, err = fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("certwatcher: failed to create fswatcher: %w", err)
	}
	return w, nil
}

// Certificate returns the most recently loaded [*tls.Certificate].
func (w *Watcher) Certificate() *tls.Certificate {
	return w.cert.Load()
}

// GetCertificate satisfies [tls.Config.GetCertificate]. This function should be
// used on a tls.Config to use the certificate loaded by certwatcher.
func (w *Watcher) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return w.cert.Load(), nil
}

// GetClientCertificate satisfies [tls.Config.GetClientCertificate]. This function
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
	// Lock the certificate so nothing else tries to refresh or reconfigure it.
	w.certμ.Lock()
	defer w.certμ.Unlock()

	// Increment the reconfigure counter.
	w.reconfigureTotalCounter.Add(ctx, 1)

	// Load the certificate from disk and parse it's leaf.
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		// Increment the error counter.
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

	certPtr := &cert

	// Staple the certificate.
	if err := w.staple(ctx, certPtr); err != nil {
		w.logger.LogAttrs(ctx, slog.LevelWarn, "failed to staple certificate", slog.Any("err", err))
	}

	// Update the certificate we are serving.
	// We use swap, so we can display a helpful message if this is the first
	// time a certificate was loaded or if it was a reload.
	if wCert := w.cert.Swap(certPtr); wCert == nil {
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
func (w *Watcher) staple(ctx context.Context, cert *tls.Certificate) error {
	// If stapling is disabled, don't do anything.
	if w.options.DontStaple {
		return nil
	}

	// Attempt to staple the certificate.
	w.logger.LogAttrs(
		ctx,
		slog.LevelInfo,
		"attempting to staple certificate...",
		slog.Any("ocsp_servers", cert.Leaf.OCSPServer),
		slog.Any("issuing_certificate_url", cert.Leaf.IssuingCertificateURL),
	)

	// Staple the certificate.
	res, err := ocsp.Staple(ctx, cert)
	if err != nil {
		if errors.Is(err, ocsp.ErrNoOCSPServer) {
			w.logger.LogAttrs(ctx, slog.LevelInfo, "certificate has no ocsp servers, unable to staple")
			return nil
		}
		return fmt.Errorf("certwatcher: error stapling certificate: %w", err)
	}

	// Store the new OCSP response.
	if res == nil {
		w.ocsp = nil
		return nil
	}
	w.ocsp = res.Response

	var status string
	switch res.Status {
	case goocsp.Good:
		status = "Good"
	case goocsp.Revoked:
		status = "Revoked"
	case goocsp.Unknown:
		status = "Unknown"
	case goocsp.ServerFailed:
		status = "ServerFailed"
	}

	// OCSPStaple will only be set if `status` is Good.
	if cert.OCSPStaple == nil {
		w.logger.LogAttrs(ctx, slog.LevelWarn, "certificate was not stapled", slog.Group("ocsp", slog.String("status", status)))
	} else {
		w.logger.LogAttrs(ctx, slog.LevelInfo, "certificate stapled", slog.Group("ocsp",
			slog.String("status", status), slog.Time("produced_at", res.ProducedAt),
			slog.Time("this_update", res.ThisUpdate), slog.Time("next_update", res.NextUpdate),
			slog.String("hash_algorithm", res.IssuerHash.String()),
			slog.String("signature_algorithm", res.SignatureAlgorithm.String()),
		))
	}

	return nil
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
					return false, nil
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
		w.logger.LogAttrs(ctx, slog.LevelError, "filesystem watcher is not configured, unable to start certwatcher")
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
	// If stapling is enabled, start a go-routine that will re-staple the
	// certificate.
	if !w.options.DontStaple {
		go w.waitForOCSPRefresh(ctx)
	}

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

// waitForOCSPRefresh waits for OCSP refreshes so we can keep the certificate's
// OCSP stapling up-to-date.
func (w *Watcher) waitForOCSPRefresh(ctx context.Context) {
	refreshAt := ocsp.RefreshTime(w.ocsp).Sub(time.Now())

	t := time.NewTimer(refreshAt)
	defer func() {
		if !t.Stop() {
			<-t.C
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			// Refresh the OCSP stapling on the certificate and reset the timer.
			t.Reset(w.refreshOCSP(ctx))
		}
	}
}

// refreshOCSP refreshes the OCSP stapling for the actively loaded certificate.
func (w *Watcher) refreshOCSP(ctx context.Context) time.Duration {
	// Lock the certificate so nothing else tries to refresh or reconfigure it.
	w.certμ.Lock()
	defer w.certμ.Unlock()

	// Increment the staple total counter.
	w.stapleTotalCounter.Add(ctx, 1)

	// Check when the next OCSP refresh is.
	refreshTime := ocsp.RefreshTime(w.ocsp)

	// Check if we need to refresh the OCSP staple on the certificate.
	now := time.Now()
	if !now.Before(refreshTime) {
		return refreshTime.Sub(now)
	}

	// Clone the currently loaded certificate.
	//
	// We need to clone the certificate to avoid a race condition with
	// OCSPStaple. That's the entire point of using an [atomic.Pointer] for
	// cert, it allows us to return a TLS certificate to users, and swap in a
	// new one without affecting the old certificate. If we modify the
	// certificate in-place, we might as well just remove the [atomic.Pointer]
	// and pray we don't update the certificate while it's being used.
	currentCert := w.cert.Load()
	cert := &tls.Certificate{
		Certificate:                  currentCert.Certificate,
		PrivateKey:                   currentCert.PrivateKey,
		SupportedSignatureAlgorithms: currentCert.SupportedSignatureAlgorithms,
		SignedCertificateTimestamps:  currentCert.SignedCertificateTimestamps,
		Leaf:                         currentCert.Leaf,
		// OCSPStaple is intentionally omitted here.
	}

	// Staple the cloned certificate.
	if err := w.staple(ctx, cert); err != nil {
		w.logger.LogAttrs(ctx, slog.LevelWarn, "failed to re-staple certificate", slog.Any("err", err))

		// Increment the staple error counter.
		w.stapleErrorCounter.Add(ctx, 1)

		// Return a fixed duration here so we can retry later.
		//
		// We could also use a backoff if we wanted better control, but OCSP
		// staples usually last multiple hours, so a retrying after a little
		// while (even multiple times) should be more than sufficient.
		return 30 * time.Second
	}

	// Store the newly cloned and stapled certificate.
	w.cert.Store(cert)

	// Return the next refresh time.
	return ocsp.RefreshTime(w.ocsp).Sub(time.Now())
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
