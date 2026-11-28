package exposure

import "testing"

func TestClassify(t *testing.T) {
	open := Path{Confirmed: true, Origin: "0.0.0.0/0", Evidence: []string{"sg-rule-1"}}
	tests := []struct {
		name  string
		paths []Path
		want  string
	}{
		{"none", nil, Unknown},
		{"open v4", []Path{open}, Internet},
		{"open v6", []Path{{Confirmed: true, Origin: "::/0", Evidence: []string{"r"}}}, Internet},
		{"open without evidence", []Path{{Confirmed: true, Origin: "0.0.0.0/0"}}, Unknown},
		{"unconfirmed open ignored", []Path{{Origin: "0.0.0.0/0", Evidence: []string{"r"}}}, Unknown},
		{"private", []Path{{Confirmed: true, Origin: "10.0.0.0/8"}}, Internal},
		{"in account", []Path{{Confirmed: true, InAccount: true}}, Internal},
		{"private plus open", []Path{{Confirmed: true, Origin: "10.0.0.0/8"}, open}, Internet},
		{"public cidr", []Path{{Confirmed: true, Origin: "8.8.8.0/24"}}, Unknown},
		{"private plus public cidr", []Path{{Confirmed: true, Origin: "10.0.0.0/8"}, {Confirmed: true, Origin: "8.8.8.0/24"}}, Unknown},
	}
	for _, tt := range tests {
		got := Classify(tt.paths)
		if got.Value != tt.want || !got.Valid() {
			t.Errorf("%s: got %+v, want %s", tt.name, got, tt.want)
		}
	}
}
