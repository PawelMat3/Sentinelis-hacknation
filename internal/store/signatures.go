package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"asi/internal/fingerprint"
)

// SyncBuiltinSignatures inserts new built-in signatures and refreshes their
// definitions, preserving the analyst's enabled/disabled choice.
func (s *Store) SyncBuiltinSignatures(ctx context.Context) error {
	for _, sg := range fingerprint.Builtin() {
		if err := sg.Compile(); err != nil {
			return err
		}
		_, err := s.DB.ExecContext(ctx, `INSERT INTO signatures(name, category, description, enabled, builtin, definition, created_by, created_at, updated_at)
			VALUES(?,?,?,1,1,?,'system',?,?) ON CONFLICT(name) DO UPDATE SET category=excluded.category, description=excluded.description,
			definition=excluded.definition WHERE signatures.builtin=1`,
			sg.Name, sg.Category, sg.Description, jsonStr(sg.Def), s.now(), s.now())
		if err != nil {
			return err
		}
	}
	return nil
}

func scanSig(row interface{ Scan(...any) error }) (*fingerprint.Signature, error) {
	var sg fingerprint.Signature
	var en, bi int
	var def string
	if err := row.Scan(&sg.ID, &sg.Name, &sg.Category, &sg.Description, &en, &bi, &def); err != nil {
		return nil, err
	}
	sg.Enabled, sg.Builtin = en == 1, bi == 1
	json.Unmarshal([]byte(def), &sg.Def)
	return &sg, nil
}

func (s *Store) ListSignatures(ctx context.Context) ([]*fingerprint.Signature, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT id, name, category, description, enabled, builtin, definition FROM signatures ORDER BY builtin, category, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*fingerprint.Signature{}
	for rows.Next() {
		sg, err := scanSig(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sg)
	}
	return out, rows.Err()
}

func (s *Store) GetSignature(ctx context.Context, id int64) (*fingerprint.Signature, error) {
	sg, err := scanSig(s.DB.QueryRowContext(ctx, `SELECT id, name, category, description, enabled, builtin, definition FROM signatures WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return sg, err
}

func (s *Store) CreateSignature(ctx context.Context, sg *fingerprint.Signature, user string) (int64, error) {
	if err := sg.Compile(); err != nil {
		return 0, err
	}
	if sg.Category == "" {
		sg.Category = "custom"
	}
	res, err := s.DB.ExecContext(ctx, `INSERT INTO signatures(name, category, description, enabled, builtin, definition, created_by, created_at, updated_at) VALUES(?,?,?,?,0,?,?,?,?)`,
		sg.Name, sg.Category, sg.Description, b2i(sg.Enabled), jsonStr(sg.Def), user, s.now(), s.now())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// UpdateSignature: built-in signatures may only be enabled/disabled.
func (s *Store) UpdateSignature(ctx context.Context, sg *fingerprint.Signature) error {
	cur, err := s.GetSignature(ctx, sg.ID)
	if err != nil {
		return err
	}
	if cur.Builtin {
		_, err = s.DB.ExecContext(ctx, `UPDATE signatures SET enabled=?, updated_at=? WHERE id=?`, b2i(sg.Enabled), s.now(), sg.ID)
		return err
	}
	if err := sg.Compile(); err != nil {
		return err
	}
	_, err = s.DB.ExecContext(ctx, `UPDATE signatures SET name=?, category=?, description=?, enabled=?, definition=?, updated_at=? WHERE id=?`,
		sg.Name, sg.Category, sg.Description, b2i(sg.Enabled), jsonStr(sg.Def), s.now(), sg.ID)
	return err
}

func (s *Store) DeleteSignature(ctx context.Context, id int64) error {
	cur, err := s.GetSignature(ctx, id)
	if err != nil {
		return err
	}
	if cur.Builtin {
		return errors.New("built-in signatures can be disabled but not deleted")
	}
	_, err = s.DB.ExecContext(ctx, `DELETE FROM signatures WHERE id=?`, id)
	return err
}

// LoadSignatureSet compiles all enabled signatures.
func (s *Store) LoadSignatureSet(ctx context.Context) (*fingerprint.Set, error) {
	sigs, err := s.ListSignatures(ctx)
	if err != nil {
		return nil, err
	}
	set, _ := fingerprint.NewSet(sigs)
	return set, nil
}
