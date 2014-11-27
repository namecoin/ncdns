package util_test

import "testing"
import "github.com/hlandau/ncdns/util"

type item struct {
	input         string
	expectedHead  string
	expectedRest  string
	expectedError error
}

var items = []item{
	item{"", "", "", nil},
	item{"a", "a", "", nil},
	item{"alpha", "alpha", "", nil},
	item{"alpha.beta", "beta", "alpha", nil},
	item{"alpha.beta.gamma", "gamma", "alpha.beta", nil},
	item{"alpha.beta.gamma.delta", "delta", "alpha.beta.gamma", nil},
	item{"alpha.beta.gamma.delta.", "delta", "alpha.beta.gamma", nil},
}

func TestSplitDomainHead(t *testing.T) {
	for i := range items {
		head, rest, err := util.SplitDomainHead(items[i].input)
		if head != items[i].expectedHead {
			t.Errorf("Input \"%s\": head \"%s\" does not equal expected value \"%s\"", items[i].input, head, items[i].expectedHead)
		}
		if rest != items[i].expectedRest {
			t.Errorf("Input \"%s\": rest \"%s\" does not equal expected value \"%s\"", items[i].input, rest, items[i].expectedRest)
		}
		if err != items[i].expectedError {
			t.Errorf("Input \"%s\": error \"%s\" does not equal expected value \"%s\"", items[i].input, err, items[i].expectedError)
		}
	}
}
