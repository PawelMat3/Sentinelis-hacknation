// Package store is the persistence layer (SQLite in WAL mode via the pure-Go
// modernc driver - no CGO, single static binary). Sensitive columns are
// encrypted with crypto.Keyring before they reach the database.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"asi/internal/crypto"
)

var ErrNotFound = errors.New("not found")

type Store struct {
	DB  *sql.DB
	K   *crypto.Keyring
	Now func() time.Time
	// ingestMu serialises scan result ingestion (SQLite has a single writer;
	// this avoids lock contention between parallel chunk workers).
	ingestMu sync.Mutex
}

// Open opens/creates the database, runs migrations and loads (or creates) the
// data-encryption key wrapped with kek.
func Open(path string, kek []byte) (*Store, error) {
	dsn := "file:" + filepath.ToSlash(path) +
		"?_pragma=busy_timeout(20000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)&_txlock=immediate"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(8)
	db.SetConnMaxIdleTime(5 * time.Minute)
	s := &Store{DB: db, Now: time.Now}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	if err := s.loadKey(kek); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.DB.Close() }

func (s *Store) now() int64 { return s.Now().Unix() }

func (s *Store) migrate() error {
	if _, err := s.DB.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL)`); err != nil {
		return err
	}
	var cur int
	s.DB.QueryRow(`SELECT COALESCE(MAX(version),0) FROM schema_migrations`).Scan(&cur)
	for i := cur; i < len(migrations); i++ {
		tx, err := s.DB.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(migrations[i]); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %d: %w", i+1, err)
		}
		if _, err := tx.Exec(`INSERT INTO schema_migrations(version, applied_at) VALUES(?,?)`, i+1, time.Now().Unix()); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) loadKey(kek []byte) error {
	var wrapped string
	err := s.DB.QueryRow(`SELECT value FROM meta WHERE key='dek'`).Scan(&wrapped)
	var dek []byte
	switch {
	case errors.Is(err, sql.ErrNoRows):
		dek = crypto.RandomKey()
		w, err := crypto.WrapKey(kek, dek)
		if err != nil {
			return err
		}
		if _, err := s.DB.Exec(`INSERT INTO meta(key,value) VALUES('dek',?),('kek_check',?)`, w, crypto.KeyCheck(kek)); err != nil {
			return err
		}
	case err != nil:
		return err
	default:
		dek, err = crypto.UnwrapKey(kek, wrapped)
		if err != nil {
			return err
		}
	}
	k, err := crypto.NewKeyring(dek)
	if err != nil {
		return err
	}
	s.K = k
	return nil
}

// RotateKEK re-wraps the data key with a new master key.
func (s *Store) RotateKEK(oldKEK, newKEK []byte) error {
	var wrapped string
	if err := s.DB.QueryRow(`SELECT value FROM meta WHERE key='dek'`).Scan(&wrapped); err != nil {
		return err
	}
	dek, err := crypto.UnwrapKey(oldKEK, wrapped)
	if err != nil {
		return err
	}
	w, err := crypto.WrapKey(newKEK, dek)
	if err != nil {
		return err
	}
	_, err = s.DB.Exec(`UPDATE meta SET value=? WHERE key='dek'`, w)
	if err == nil {
		_, err = s.DB.Exec(`INSERT OR REPLACE INTO meta(key,value) VALUES('kek_check',?)`, crypto.KeyCheck(newKEK))
	}
	return err
}

// --- helpers -------------------------------------------------------------

func jsonStr(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

type queryer interface {
	QueryContext(ctx context.Context, q string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, q string, args ...any) *sql.Row
	ExecContext(ctx context.Context, q string, args ...any) (sql.Result, error)
}

func placeholders(n int) string {
	if n <= 0 {
		return ""
	}
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}

func int64s(ids []int64) []any {
	out := make([]any, len(ids))
	for i, v := range ids {
		out[i] = v
	}
	return out
}

func parseTags(s string) []string {
	var t []string
	json.Unmarshal([]byte(s), &t)
	if t == nil {
		t = []string{}
	}
	return t
}

// NormalizeTags trims, lowercases and de-duplicates tags.
func NormalizeTags(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, t := range in {
		t = strings.ToLower(strings.TrimSpace(t))
		t = strings.Map(func(r rune) rune {
			if r == ' ' {
				return '-'
			}
			if r < 32 || strings.ContainsRune(`"'<>&;`, r) {
				return -1
			}
			return r
		}, t)
		if t == "" || len(t) > 40 || seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, t)
	}
	return out
}

func itoa(i int64) string { return strconv.FormatInt(i, 10) }
