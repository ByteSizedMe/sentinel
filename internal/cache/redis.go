package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/bytesizedme/sentinel/internal/rbac"
	"github.com/redis/go-redis/v9"
)

// quietLogger drops go-redis's own log lines (e.g. dial failures) so the only
// cache message in our logs is the generic one written by CachedStore.
type quietLogger struct{}

func (quietLogger) Printf(context.Context, string, ...interface{}) {}

// genKey holds the current generation. It has a TTL like every other key.
const (
	genKey = keyPrefix + "gen"
	genTTL = 24 * time.Hour
)

// Redis is the Redis-backed Cache.
type Redis struct {
	client *redis.Client
	ttl    time.Duration
	now    func() time.Time
}

var _ Cache = (*Redis)(nil)

// NewRedis wraps a client. Decisions live for ttl.
func NewRedis(client *redis.Client, ttl time.Duration) *Redis {
	return &Redis{client: client, ttl: ttl, now: time.Now}
}

// NewRedisClient parses a REDIS_URL and configures short timeouts and no
// retries: when Redis is slow or down we want to give up fast and ask Postgres.
// It does not connect; the first command does.
func NewRedisClient(redisURL string) (*redis.Client, error) {
	redis.SetLogger(quietLogger{})
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		// Do not include redisURL: it may contain a password.
		return nil, fmt.Errorf("cache: invalid REDIS_URL: %w", err)
	}
	opts.DialTimeout = 300 * time.Millisecond
	opts.ReadTimeout = 300 * time.Millisecond
	opts.WriteTimeout = 300 * time.Millisecond
	opts.MaxRetries = -1 // disabled
	return redis.NewClient(opts), nil
}

// entry is the stored JSON value. Only Postgres-derived facts plus the stamp.
type entry struct {
	Gen     int64  `json:"g"`
	Allowed bool   `json:"a"`
	Role    string `json:"r,omitempty"`
}

// Get reads the generation and the decision in ONE round trip (MGET).
func (r *Redis) Get(ctx context.Context, userID, action, resource string) (Result, error) {
	vals, err := r.client.MGet(ctx, genKey, decisionKey(userID, action, resource)).Result()
	if err != nil {
		return Result{}, err
	}

	gen, ok := parseGen(vals[0])
	if !ok {
		// No generation yet (first use, or it expired): create one. Nothing can
		// be cached under an unknown generation, so this lookup is a miss.
		gen, err = r.initGen(ctx)
		if err != nil {
			return Result{}, err
		}
		return Result{Gen: gen}, nil
	}

	raw, _ := vals[1].(string)
	if raw == "" {
		return Result{Gen: gen}, nil // miss (never stored, or expired)
	}
	var e entry
	if err := json.Unmarshal([]byte(raw), &e); err != nil || Generation(e.Gen) != gen {
		return Result{Gen: gen}, nil // corrupt or from an older generation: miss
	}
	return Result{Hit: true, Decision: rbac.Decision{Allowed: e.Allowed, MatchedRole: e.Role}, Gen: gen}, nil
}

// Set stores the decision with a TTL, stamped with the generation from Get.
func (r *Redis) Set(ctx context.Context, userID, action, resource string, d rbac.Decision, gen Generation) error {
	raw, err := json.Marshal(entry{Gen: int64(gen), Allowed: d.Allowed, Role: d.MatchedRole})
	if err != nil {
		return err
	}
	return r.client.Set(ctx, decisionKey(userID, action, resource), raw, r.ttl).Err()
}

// Invalidate moves the generation forward, which strands every older entry.
// SETNX + INCR + EXPIRE run as one transaction. If the key had vanished, SETNX
// recreates it from the clock first, so the new value can never equal a
// generation used before.
func (r *Redis) Invalidate(ctx context.Context) error {
	_, err := r.client.TxPipelined(ctx, func(p redis.Pipeliner) error {
		p.SetNX(ctx, genKey, r.now().UnixNano(), genTTL)
		p.Incr(ctx, genKey)
		p.Expire(ctx, genKey, genTTL)
		return nil
	})
	return err
}

// initGen creates the generation from the clock if it does not exist, then
// reads it back (another process may have created it first).
func (r *Redis) initGen(ctx context.Context) (Generation, error) {
	if err := r.client.SetNX(ctx, genKey, r.now().UnixNano(), genTTL).Err(); err != nil {
		return 0, err
	}
	s, err := r.client.Get(ctx, genKey).Result()
	if err != nil {
		return 0, err
	}
	gen, ok := parseGen(s)
	if !ok {
		return 0, fmt.Errorf("cache: unreadable generation")
	}
	return gen, nil
}

// parseGen reads a generation from a Redis reply (string, or nil if missing).
func parseGen(v any) (Generation, bool) {
	s, ok := v.(string)
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, false
	}
	return Generation(n), true
}
