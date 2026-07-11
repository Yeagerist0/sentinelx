package audit

import "testing"

func TestChainVerifiesAndDetectsTampering(t *testing.T) {
	l := New()
	l.Append("event", "e1", []byte("a"))
	l.Append("detection", "d1", []byte("b"))
	l.Append("investigation", "1", []byte("c"))

	if ok, seq := l.Verify(); !ok {
		t.Fatalf("fresh chain should verify, broke at %d", seq)
	}
	if l.Len() != 3 {
		t.Fatalf("want 3 entries, got %d", l.Len())
	}

	// Tamper with a middle entry's payload hash — the chain must catch it.
	l.entries[1].PayloadHash = "forged"
	ok, seq := l.Verify()
	if ok {
		t.Fatal("verification passed on tampered chain")
	}
	if seq != 2 {
		t.Fatalf("want first-bad-seq 2, got %d", seq)
	}
}

func TestHeadAdvances(t *testing.T) {
	l := New()
	h0 := l.Head()
	l.Append("event", "e1", []byte("x"))
	if l.Head() == h0 {
		t.Fatal("head did not advance after append")
	}
}
