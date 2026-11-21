package store

import (
	"context"
	"strings"
)

// Scope selects which dataset read queries return. Demo data is everything
// produced by jobs using the simulator engine ("sim"); real data is the rest
// (nmap/native scans, imports, manual entries). It lets an operator test on
// real targets without the simulated network drowning the results.
type Scope string

const (
	ScopeAll  Scope = "all"
	ScopeReal Scope = "real"
	ScopeDemo Scope = "demo"
)

type scopeKey struct{}

// ParseScope maps a header/query value to a scope; anything unknown means all.
func ParseScope(v string) Scope {
	switch Scope(strings.ToLower(strings.TrimSpace(v))) {
	case ScopeReal:
		return ScopeReal
	case ScopeDemo:
		return ScopeDemo
	}
	return ScopeAll
}

// WithScope attaches a dataset scope to ctx. Contexts without one (scheduler,
// executor, CLI) see all data.
func WithScope(ctx context.Context, sc Scope) context.Context {
	return context.WithValue(ctx, scopeKey{}, sc)
}

func scopeOf(ctx context.Context) Scope {
	if sc, ok := ctx.Value(scopeKey{}).(Scope); ok {
		return sc
	}
	return ScopeAll
}

const demoJobIDs = `(SELECT id FROM jobs WHERE engine='sim')`

// jobScope returns a condition on a job id column (NULL/0 = not a demo job),
// or "" when no filtering applies.
func jobScope(ctx context.Context, col string) string {
	switch scopeOf(ctx) {
	case ScopeReal:
		return `COALESCE(` + col + `,0) NOT IN ` + demoJobIDs
	case ScopeDemo:
		return `COALESCE(` + col + `,0) IN ` + demoJobIDs
	}
	return ""
}

// hostScope returns a condition on a hosts table alias (hosts belong to the
// job that first discovered them).
func hostScope(ctx context.Context, alias string) string {
	return jobScope(ctx, alias+".job_id")
}

// andCond appends " AND cond" when cond is set.
func andCond(cond string) string {
	if cond == "" {
		return ""
	}
	return " AND " + cond
}

// addWhere merges cond into an optional " WHERE ..." clause.
func addWhere(where, cond string) string {
	if cond == "" {
		return where
	}
	if where == "" {
		return " WHERE " + cond
	}
	return where + " AND " + cond
}

// HasDemoData reports whether any simulator job exists.
func (s *Store) HasDemoData(ctx context.Context) bool {
	return s.count(ctx, `SELECT COUNT(*) FROM jobs WHERE engine='sim'`) > 0
}
