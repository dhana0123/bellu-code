package config

import (
	"strings"
	"testing"
)

func TestLoadDataSampleLimit(t *testing.T) {
	env := func(v string) func(string) (string, bool) {
		return func(k string) (string, bool) { return v, k == "BELLUCODE_DATA_SAMPLE_LIMIT" }
	}
	if c, err := LoadData(env(""), DefaultData()); err != nil || c.SampleLimit != 100 || len(c.SampleStores) != 0 {
		t.Fatalf("default: %+v %v", c, err)
	}
	for _, ok := range []string{"1", "10000"} {
		if c, err := LoadData(env(ok), DefaultData()); err != nil || c.SampleLimit < 1 {
			t.Fatalf("%s: %+v %v", ok, c, err)
		}
	}
	prev := Data{SampleLimit: 250}
	for _, bad := range []string{"0", "10001", "-5", "abc", "1.5"} {
		c, err := LoadData(env(bad), prev)
		if err == nil || !strings.Contains(err.Error(), "1 to 10000") || c.SampleLimit != 250 {
			t.Fatalf("%s: %+v %v", bad, c, err)
		}
	}
}
