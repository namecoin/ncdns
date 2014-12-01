package util_test

import "testing"
import "github.com/hlandau/ncdns/util"

type item struct {
	input        string
	expectedHead string
	expectedRest string
}

var items = []item{
	item{"", "", ""},
	item{"a", "a", ""},
	item{"alpha", "alpha", ""},
	item{"alpha.beta", "beta", "alpha"},
	item{"alpha.beta.gamma", "gamma", "alpha.beta"},
	item{"alpha.beta.gamma.delta", "delta", "alpha.beta.gamma"},
	item{"alpha.beta.gamma.delta.", "delta", "alpha.beta.gamma"},
}

func TestSplitDomainHead(t *testing.T) {
	for i := range items {
		head, rest := util.SplitDomainHead(items[i].input)
		if head != items[i].expectedHead {
			t.Errorf("Input \"%s\": head \"%s\" does not equal expected value \"%s\"", items[i].input, head, items[i].expectedHead)
		}
		if rest != items[i].expectedRest {
			t.Errorf("Input \"%s\": rest \"%s\" does not equal expected value \"%s\"", items[i].input, rest, items[i].expectedRest)
		}
	}
}
