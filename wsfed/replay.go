// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package wsfed

import (
	"fmt"
	"sync"
	"time"
)

// MemoryReplayCache remembers accepted assertion ids so a bearer assertion is one-time.
type MemoryReplayCache struct {
	mu      sync.Mutex
	entries map[string]int64
	max     int
}

func NewMemoryReplayCache(maxEntries int) *MemoryReplayCache {
	if maxEntries <= 0 {
		maxEntries = 10000
	}
	return &MemoryReplayCache{entries: map[string]int64{}, max: maxEntries}
}

// CheckAndRecord reports whether assertionID is still live. A new id is recorded until expiresAt.
func (c *MemoryReplayCache) CheckAndRecord(assertionID string, expiresAt time.Time) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now().UTC().UnixMilli()
	if until, ok := c.entries[assertionID]; ok && until > now {
		return true, nil
	}
	if len(c.entries) >= c.max {
		for key, value := range c.entries {
			if value <= now {
				delete(c.entries, key)
			}
		}
		if len(c.entries) >= c.max {
			return false, fmt.Errorf("the replay cache holds %d live assertions and cannot record another", c.max)
		}
	}
	c.entries[assertionID] = expiresAt.UTC().UnixMilli()
	return false, nil
}
