package vulnmatch

import "testing"

func TestOSVComparator(t *testing.T) {
	c, ok := osvCompare("pypi", "1.0rc1", "1.0")
	if !OSVEnabled {
		if ok {
			t.Fatal("the OSV comparator answered without the osvmatch tag")
		}
		return
	}
	if !ok || c != -1 {
		t.Fatalf("pypi 1.0rc1 vs 1.0 = %d, %v", c, ok)
	}
	if c, ok := osvCompare("nuget", "1.0.0-beta", "1.0.0"); !ok || c != -1 {
		t.Fatalf("nuget = %d, %v", c, ok)
	}
	if _, ok := osvCompare("deb", "1", "2"); ok {
		t.Fatal("deb is not an OSV-ordered ecosystem here")
	}
}
