package otlp

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"strings"
	"time"

	"go.opentelemetry.io/collector/pdata/plog/plogotlp"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/engine"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/errs"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
)

// MaxBodyBytes is the request size limit, applied to the body as sent and
// again after gzip decompression.
const MaxBodyBytes = 4 << 20

// Applier applies a Batch. engine.Core satisfies it.
type Applier interface {
	Apply(ctx context.Context, b batch.Batch, mode engine.Mode) (engine.Receipt, error)
}

// Metrics counts records. metrics.Set satisfies it.
type Metrics interface {
	OTLPRecords(accepted, rejected int)
}

// Config configures a Server. Applier is required.
type Config struct {
	Applier Applier
	// Authorize resolves the caller of a request. A nil error admits it;
	// errs.Forbidden maps to 403 and any other error to 401. Nil admits all.
	Authorize func(r *http.Request) error
	// Ready returns an error (mapped to 503) when the engine cannot take
	// writes. Nil means always ready.
	Ready   func() error
	Metrics Metrics
	Logger  *slog.Logger
	Clock   func() time.Time
}

// Server is the OTLP/HTTP receiver.
type Server struct {
	cfg Config
	srv *http.Server
}

// New returns a Server.
func New(cfg Config) *Server {
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	s := &Server{cfg: cfg}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/logs", s.handleLogs)
	s.srv = &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	return s
}

// Handler returns the HTTP handler, for tests and embedding.
func (s *Server) Handler() http.Handler { return s.srv.Handler }

// Serve serves on l until Shutdown. It returns nil after a clean shutdown.
func (s *Server) Serve(l net.Listener) error {
	if err := s.srv.Serve(l); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// Shutdown stops the listener and waits for in-flight requests.
func (s *Server) Shutdown(ctx context.Context) error { return s.srv.Shutdown(ctx) }

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.cfg.Authorize != nil {
		if err := s.cfg.Authorize(r); err != nil {
			if errors.Is(err, errs.Forbidden) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			w.Header().Set("WWW-Authenticate", `Bearer realm="bellu-graph"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}
	if s.cfg.Ready != nil {
		if err := s.cfg.Ready(); err != nil {
			http.Error(w, "graph engine not ready", http.StatusServiceUnavailable)
			return
		}
	}
	ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if ct != "application/x-protobuf" && ct != "application/json" {
		http.Error(w, "unsupported content type", http.StatusUnsupportedMediaType)
		return
	}
	body, status, msg := readBody(w, r)
	if status != 0 {
		http.Error(w, msg, status)
		return
	}
	req := plogotlp.NewExportRequest()
	var err error
	if ct == "application/json" {
		err = req.UnmarshalJSON(body)
	} else {
		err = req.UnmarshalProto(body)
	}
	if err != nil {
		http.Error(w, "cannot decode request: "+err.Error(), http.StatusBadRequest)
		return
	}

	items, rejs := Convert(req.Logs(), s.cfg.Clock())
	accepted := 0
	for _, it := range items {
		_, err := s.cfg.Applier.Apply(r.Context(), it.Batch, it.Mode)
		switch {
		case err == nil:
			accepted += it.Records
		case errors.Is(err, errs.Unavailable):
			s.record(accepted, rejectedCount(rejs)+it.Records)
			http.Error(w, "graph engine not ready", http.StatusServiceUnavailable)
			return
		case errors.Is(err, errs.Validation):
			rejs = append(rejs, Rejection{Records: it.Records, Reason: err.Error()})
		default:
			s.cfg.Logger.Error("otlp apply failed", "collector", it.Batch.Collector, "error", err.Error())
			s.record(accepted, rejectedCount(rejs)+it.Records)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	}
	s.record(accepted, rejectedCount(rejs))

	resp := plogotlp.NewExportResponse()
	if len(rejs) > 0 {
		ps := resp.PartialSuccess()
		ps.SetRejectedLogRecords(int64(rejectedCount(rejs)))
		reasons := make([]string, len(rejs))
		for i, rj := range rejs {
			reasons[i] = rj.Reason
		}
		ps.SetErrorMessage(strings.Join(reasons, "; "))
	}
	var out []byte
	if ct == "application/json" {
		out, err = resp.MarshalJSON()
	} else {
		out, err = resp.MarshalProto()
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", ct)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(out)
}

func (s *Server) record(accepted, rejected int) {
	if s.cfg.Metrics != nil {
		s.cfg.Metrics.OTLPRecords(accepted, rejected)
	}
}

func rejectedCount(rejs []Rejection) int {
	n := 0
	for _, r := range rejs {
		n += r.Records
	}
	return n
}

// readBody reads the (optionally gzip) body under the size limit. A non-zero
// status means the request failed.
func readBody(w http.ResponseWriter, r *http.Request) ([]byte, int, string) {
	var src io.Reader = http.MaxBytesReader(w, r.Body, MaxBodyBytes)
	switch strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Encoding"))) {
	case "", "identity":
	case "gzip":
		zr, err := gzip.NewReader(src)
		if err != nil {
			return nil, tooLarge(err, http.StatusBadRequest), "invalid gzip body"
		}
		defer zr.Close()
		src = zr
	default:
		return nil, http.StatusUnsupportedMediaType, "unsupported content encoding"
	}
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, io.LimitReader(src, MaxBodyBytes+1)); err != nil {
		st := tooLarge(err, http.StatusBadRequest)
		return nil, st, "cannot read body"
	}
	if buf.Len() > MaxBodyBytes {
		return nil, http.StatusRequestEntityTooLarge, "request body too large"
	}
	return buf.Bytes(), 0, ""
}

func tooLarge(err error, fallback int) int {
	var mbe *http.MaxBytesError
	if errors.As(err, &mbe) {
		return http.StatusRequestEntityTooLarge
	}
	return fallback
}
