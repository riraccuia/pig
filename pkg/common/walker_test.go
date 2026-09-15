package common

import "testing"

type taggedMeta struct {
	Name string `toml:"name" default:"from-tag" optional:"true" desc:"tag desc"`
}

func (taggedMeta) DescribeFields() map[string]FieldMeta {
	return map[string]FieldMeta{
		"name": {Default: "from-meta", Optional: false, Desc: "meta desc"},
	}
}

type taggedOnly struct {
	Name string `toml:"name" default:"from-tag" optional:"true" desc:"tag desc"`
}

func TestDescribeFieldsWinsOverTags(t *testing.T) {
	docs := MapStruct(taggedMeta{})
	if len(docs) != 1 {
		t.Fatalf("len=%d docs=%+v", len(docs), docs)
	}
	d := docs[0]
	if d.Default != "from-meta" || d.Optional || d.Description != "meta desc" {
		t.Fatalf("got %+v", d)
	}
}

func TestTagFallback(t *testing.T) {
	docs := MapStruct(taggedOnly{})
	if len(docs) != 1 {
		t.Fatalf("len=%d docs=%+v", len(docs), docs)
	}
	d := docs[0]
	if d.Default != "from-tag" || !d.Optional || d.Description != "tag desc" {
		t.Fatalf("got %+v", d)
	}
}
