package judge

var Judge = map[int]string{
	0: "ok",
	3: "junk",
	6: "proxy",
	9: "bot",
}

type Result struct {
	Verdict string
	Name    string
}

var RESULTS = map[int]Result{
	0: {Verdict: "ok", Name: "Clean"},
	3: {Verdict: "junk", Name: "Potentially unwanted"},
	6: {Verdict: "proxy", Name: "Proxy"},
	9: {Verdict: "bot", Name: "Bot"},
}
