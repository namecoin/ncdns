package util_test

import "testing"
import "github.com/hlandau/ncdns/util"

type item struct {
	input            string
	expectedHead     string
	expectedRest     string
	expectedTail     string
	expectedTailRest string
}

var items = []item{
	item{"", "", "", "", ""},
	item{"a", "a", "", "a", ""},
	item{"alpha", "alpha", "", "alpha", ""},
	item{"alpha.beta", "beta", "alpha", "alpha", "beta"},
	item{"alpha.beta.gamma", "gamma", "alpha.beta", "alpha", "beta.gamma"},
	item{"alpha.beta.gamma.delta", "delta", "alpha.beta.gamma", "alpha", "beta.gamma.delta"},
	item{"alpha.beta.gamma.delta.", "delta", "alpha.beta.gamma", "alpha", "beta.gamma.delta."},
}

func TestSplitDomainHead(t *testing.T) {
	for i := range items {
		head, rest := util.SplitDomainHead(items[i].input)
		tail, trest := util.SplitDomainTail(items[i].input)
		if head != items[i].expectedHead {
			t.Errorf("Input \"%s\": head \"%s\" does not equal expected value \"%s\"", items[i].input, head, items[i].expectedHead)
		}
		if rest != items[i].expectedRest {
			t.Errorf("Input \"%s\": rest \"%s\" does not equal expected value \"%s\"", items[i].input, rest, items[i].expectedRest)
		}
		if tail != items[i].expectedTail {
			t.Errorf("Input \"%s\": tail \"%s\" does not equal expected value \"%s\"", items[i].input, tail, items[i].expectedTail)
		}
		if trest != items[i].expectedTailRest {
			t.Errorf("Input \"%s\": tail rest \"%s\" does not equal expected value \"%s\"", items[i].input, trest, items[i].expectedTailRest)
		}
	}
}
