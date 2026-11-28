package config

import (
	"fmt"
	"strconv"
	"strings"
)

// Defaults and bounds for the data.* keys (Requirements 13.4, 13.5).
const (
	DefaultDataSampleLimit = 100
	MinDataSampleLimit     = 1
	MaxDataSampleLimit     = 10000
)

// Data holds the data.* configuration keys.
type Data struct {
	// SampleLimit is data.sample_limit (BELLUCODE_DATA_SAMPLE_LIMIT): the most
	// objects read per data store when sampling is on. 1 to 10,000, default 100.
	SampleLimit int
	// SampleStores is data.sample_stores (BELLUCODE_DATA_SAMPLE_STORES, comma
	// separated Entity_IDs): the stores that opted in to sampling. Sampling is
	// off for every store not listed, so the default is off.
	SampleStores []string
}

// DefaultData returns the defaults: limit 100, sampling off everywhere.
func DefaultData() Data { return Data{SampleLimit: DefaultDataSampleLimit} }

// Validate checks the bounds of SampleLimit.
func (c Data) Validate() error {
	if c.SampleLimit < MinDataSampleLimit || c.SampleLimit > MaxDataSampleLimit {
		return fmt.Errorf("invalid data.sample_limit %d: want an integer from 1 to 10000", c.SampleLimit)
	}
	return nil
}

// LoadData reads the data.* keys through env on top of prev. An invalid
// data.sample_limit is rejected with an error naming the range and prev is
// returned unchanged, so the previous limit stays in force. An empty value
// counts as unset.
func LoadData(env func(string) (string, bool), prev Data) (Data, error) {
	c := prev
	get := func(key string) string {
		v, _ := env(envName(key))
		return strings.TrimSpace(v)
	}
	if v := get("data.sample_limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return prev, fmt.Errorf("invalid data.sample_limit %q: want an integer from 1 to 10000", v)
		}
		c.SampleLimit = n
		if err := c.Validate(); err != nil {
			return prev, err
		}
	}
	if v := get("data.sample_stores"); v != "" {
		c.SampleStores = nil
		for _, id := range strings.Split(v, ",") {
			if id = strings.TrimSpace(id); id != "" {
				c.SampleStores = append(c.SampleStores, id)
			}
		}
	}
	return c, nil
}
