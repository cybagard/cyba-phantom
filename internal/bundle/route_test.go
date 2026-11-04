package bundle

import (
	"fmt"
	"maps"
	"strings"
	"testing"

	"github.com/cybagard/cyba-phantom/internal/event"
)

// slotsOf gives the headers member of a route with one slot for each name.
func slotsOf(names ...string) string {
	var s []string
	for _, n := range names {
		s = append(s, `{"name":"`+n+`","trap":"t"}`)
	}
	return `"headers":[` + strings.Join(s, ",") + `]`
}

// T-U-08: a load that fails at the route step gives one bundle_rejected event.
// The reason is content_invalid. The detail has the fixed members only. The log
// line has the same members. No marker text of the route map is in the record,
// the log or the error. The marker is in an unknown member name, a path and a
// template name. Each marker has an ESC byte in the JSON text.
func TestTU08RouteRejectionEvent(t *testing.T) {
	mark := markerName + markerData + `\u001b`
	route := func(path, tmpl string) string {
		return `{"routes":[{"path":"` + path + `","template":"` + tmpl + `",` + ty + `}]}`
	}
	for name, text := range map[string]string{
		"member name":   `{"routes":[{` + pa + `,` + ti + `,` + ty + `}],"` + mark + `":1}`,
		"path":          route("/"+mark, hostDir+"index.tmpl"),
		"template name": route("/a", hostDir+mark+".tmpl"),
	} {
		t.Run(name, func(t *testing.T) {
			e := running(t)
			p := e.observe(e.l)
			arch := build(append([]ent{tf("manifest.json", mf(ver(3)))}, site(text)...)...)
			e.write("bundle/current.cbnd", arch)
			e.write("bundle/current.sig", e.sign(arch))
			_, err := e.l.LoadFrom(SourceFetch)
			evs, raw := p.take(t)
			lines := logLines(t, p.buf.String())
			if err != ErrContentInvalid || len(evs) != 1 || len(lines) != 1 {
				t.Fatalf("err %v, %d events, %d log lines; want content_invalid, 1, 1", err, len(evs), len(lines))
			}
			if evs[0].Kind() != event.KindBundleRejected {
				t.Errorf("kind %v", evs[0].Kind())
			}
			want := map[string]string{"source": "fetch", "sha256": fileSum(t, e), "reason": "content_invalid"}
			if got := detail(t, evs[0]); !maps.Equal(got, want) {
				t.Errorf("detail %v, want %v", got, want)
			}
			logWant := map[string]string{"level": "WARN", "msg": "bundle rejected"}
			maps.Copy(logWant, want)
			if !maps.Equal(lines[0], logWant) {
				t.Errorf("log %v, want %v", lines[0], logWant)
			}
			for _, s := range []string{raw[0], p.buf.String(), err.Error()} {
				for _, m := range []string{markerName, markerData, "\x1b", `\u001b`, `\x1b`} {
					if strings.Contains(s, m) {
						t.Errorf("marker %q in %q", m, s)
					}
				}
			}
		})
	}
}

// T-U-08: a bundle gives exactly one code. The steps run in this order: the
// template parse, the execution check, the route map, the seed.
func TestTU08StepOrder(t *testing.T) {
	badRoutes := tf(hostDir+routeMapName, "x")
	seeded := func(e *env) { e.l = e.seedLoader(nil) }
	for _, text := range []string{"{{if}}", "{{.Title}}"} {
		loadRaw(t, ErrTemplateParse, nil, tf(vhostFile, text), badRoutes)
	}
	// A good route map gives the seed error, so the seed step does refuse.
	loadRaw(t, ErrSeedInvalid, seeded, tf(vhostFile, "ok"), tf(hostDir+routeMapName, routeJSON(vhostFile)))
	loadRaw(t, ErrContentInvalid, seeded, tf(vhostFile, "ok"), badRoutes)
}

// T-U-08: a header slot name that is a reserved name, in any ASCII case, gives
// content_invalid. A name that starts with a reserved start does too.
func TestTU08HeaderSlotNamesRefused(t *testing.T) {
	for _, n := range []string{
		"X-Content-Type-Options", "X-Frame-Options", "X-XSS-Protection", "X-Sendfile",
		"X-content-type-options", "X-frame-options", "X-xss-protection", "X-sendfile",
		"X-CONTENT-TYPE-OPTIONS", "X-FRAME-OPTIONS", "X-XSS-PROTECTION", "X-SENDFILE",
		"x-frame-options", "x-sendfile",
		"X-Accel-Redirect", "x-accel-buffering", "X-ACCEL-Buffering", "X-accel-x", "X-Accel-",
		"X-Forwarded-For", "X-FORWARDED-HOST", "X-forwarded-proto", "x-forwarded-for", "X-Forwarded-",
	} {
		refuse(t, doc(pa, ti, ty, slotsOf(n)))
	}
}

// T-U-08: names that are near a reserved name load.
func TestTU08HeaderSlotNamesNearReserved(t *testing.T) {
	for _, n := range []string{
		"X-Accel", "X-Accelerate", "X-Forwarded", "X-ForwardedFor", "X-Sendfile-Type", "X-Frame-Options2",
		"X-Content-Type-Option", "X-Content-Type-Options2", "X-XSS-Protection2", "X-Sendfil", "X-Acce-l",
	} {
		t.Run(n, func(t *testing.T) { loadRaw(t, nil, nil, site(doc(pa, ti, ty, slotsOf(n)))...) })
	}
}

// T-U-08: two header slots of one route with names that are equal in ASCII case
// give content_invalid. The same name in two routes loads.
func TestTU08HeaderSlotDuplicates(t *testing.T) {
	for _, names := range [][]string{
		{"X-A", "X-a"}, {"X-A", "x-a"}, {"X-A", "X-A"}, {"X-a-b", "X-A-B"}, {"X-A", "X-B", "X-C", "X-a"},
		{"X-A", "X-B", "X-b"}, {"X-A", "X-B", "X-C", "X-D", "X-A"},
	} {
		refuse(t, doc(pa, ti, ty, slotsOf(names...)))
	}
	other := fmt.Sprintf(`{"path":"/b",%s,%s,%s}`, ti, ty, slotsOf("X-A"))
	for _, text := range []string{
		doc(pa, ti, ty, slotsOf("X-A", "X-B")), doc(pa, ti, ty, slotsOf("X-A", "X-B", "X-C", "X-D")),
		rt(`{`+pa+`,`+ti+`,`+ty+`,`+slotsOf("X-A")+`}`, other),
	} {
		loadRaw(t, nil, nil, site(text)...)
	}
}

// cbDoc gives a route map with one callback route at /a. The route has the
// callback object cb and these other members.
func cbDoc(cb string, more ...string) string {
	return doc(append([]string{pa, `"callback":` + cb}, more...)...)
}

// loads loads each route map and fails when one is refused.
func loads(t *testing.T, texts ...string) {
	t.Helper()
	for _, text := range texts {
		t.Run(fmt.Sprintf("%.200s", text), func(t *testing.T) { loadRaw(t, nil, nil, site(text)...) })
	}
}

// T-U-25: a callback of 1 to 4 positions loads, and the parsed positions are
// kept. A route with no asset answers with no body and has no type.
func TestTU25CallbackPositions(t *testing.T) {
	for cb, want := range map[string]Callback{
		`{"segment":true}`:         {Segment: true},
		`{"query":"q"}`:            {Query: "q"},
		`{"header":"X-H"}`:         {Header: "X-H"},
		`{"body":"b_-9"}`:          {Body: "b_-9"},
		`{"body":"b","query":"q"}`: {Query: "q", Body: "b"},
		`{"segment":true,"query":"q","header":"X-H","body":"b"}`: {true, "q", "X-H", "b"},
	} {
		t.Run(cb, func(t *testing.T) {
			b := loadRaw(t, nil, nil, site(cbDoc(cb))...)
			rm, _ := b.Routes("h.example")
			if got := rm.Routes[0]; got.Callback == nil || *got.Callback != want || got.Asset != "" || got.Type != "" {
				t.Errorf("route %+v, want callback %+v and no asset", got, want)
			}
		})
	}
}

// T-U-25: a callback route with an asset and a type loads and keeps both.
func TestTU25CallbackAsset(t *testing.T) {
	b := loadRaw(t, nil, nil, site(cbDoc(`{"query":"q"}`, png, `"type":"image/png"`))...)
	rm, _ := b.Routes("h.example")
	if r := rm.Routes[0]; r.Asset != hostDir+"a.png" || r.Type != "image/png" {
		t.Errorf("route %+v", r)
	}
}

// T-U-25: a callback that is not an object of 1 to 4 valid positions gives
// content_invalid.
func TestTU25CallbackRefused(t *testing.T) {
	for _, cb := range []string{
		`{}`, `null`, `true`, `"query"`, `[]`, `1`, `[{"query":"q"}]`,
		`{"segment":false}`, `{"segment":"true"}`, `{"segment":1}`, `{"segment":null}`, `{"segment":false,"query":"q"}`,
		`{"Segment":true}`, `{"Query":"q"}`, `{"other":"q"}`, `{"query":"q","other":"q"}`,
		`{"query":"q","query":"r"}`, `{"segment":true,"segment":true}`,
		`{"query":null}`, `{"query":1}`, `{"body":null}`, `{"header":null}`,
	} {
		refuse(t, cbDoc(cb))
	}
}

// T-U-25: query and body need 1 to 32 bytes of A-Z a-z 0-9 _ -.
func TestTU25CallbackParamForm(t *testing.T) {
	for _, member := range []string{"query", "body"} {
		for _, v := range []string{"a", strings.Repeat("a", 32), "A-z_09"} {
			loads(t, cbDoc(`{"`+member+`":"`+v+`"}`))
		}
		for _, v := range []string{"", strings.Repeat("a", 33), "a b", "a.b", "a/b", "a=b", "aé", `a\u0000`} {
			refuse(t, cbDoc(`{"`+member+`":"`+v+`"}`))
		}
	}
}

// T-U-25: the header position has the rules of a header slot name.
func TestTU25CallbackHeaderName(t *testing.T) {
	for _, n := range []string{"X-A", "X-Accel", "X-Forwarded", "X-" + strings.Repeat("a", 32)} {
		loads(t, cbDoc(`{"header":"`+n+`"}`))
	}
	for _, n := range []string{"X-", "A", "Y-A", "X-Frame-Options", "x-frame-options", "X-Accel-A", "X-Forwarded-For", "X-a b", "X-" + strings.Repeat("a", 33)} {
		refuse(t, cbDoc(`{"header":"`+n+`"}`))
	}
}

// T-U-25: a callback route has no template and no headers. It has an asset
// and a type, or no asset and no type.
func TestTU25CallbackRouteForm(t *testing.T) {
	cb := `{"query":"q"}`
	refuse(t,
		cbDoc(cb, ti, ty), cbDoc(cb, ti), cbDoc(cb, png, ty, slotsOf("X-A")), cbDoc(cb, slotsOf("X-A")),
		cbDoc(cb, ty), cbDoc(cb, png), cbDoc(cb, `"asset":"`+hostDir+`none.png"`, ty),
		cbDoc(cb, png, `"type":"text/x"`), cbDoc(cb, `"asset":"`+hostDir+`index.tmpl"`, ty),
		cbDoc(cb, `"type":"image/png"`), cbDoc(cb, `"template":null`),
	)
	loads(t, cbDoc(cb), cbDoc(cb, png, ty))
}

// T-U-25: a route with no callback keeps its rules.
func TestTU25NoCallbackKeepsRules(t *testing.T) {
	refuse(t, doc(pa, ty), doc(pa, ti), doc(pa, ti, png, ty), doc(pa, `"callback":null`, ti, ty))
	loads(t, doc(pa, ti, ty), doc(pa, png, ty))
}

// beaconDoc gives a route map with the routes and then a beacon.
func beaconDoc(beacon string, routes ...string) string {
	return strings.TrimSuffix(rt(routes...), "}") + `,"beacon":` + beacon + `}`
}

// T-U-25: a beacon with two valid paths loads, also before the routes in the
// JSON text.
func TestTU25BeaconLoads(t *testing.T) {
	route := `{` + pa + `,` + ti + `,` + ty + `}`
	seg := `{"path":"/s","callback":{"segment":true}}`
	cbRoute := `{"path":"/c","callback":{"query":"q"}}`
	text := beaconDoc(`{"script":"/b.js","post":"/b/p"}`, route, seg)
	loads(t, text, beaconDoc(`{"post":"/b/p","script":"/b.js"}`, route, seg),
		`{"beacon":{"script":"/b.js","post":"/b/p"},"routes":[`+route+`,`+seg+`]}`,
		beaconDoc(`{"script":"/b.js","post":"/b/p"}`, route, cbRoute),
		// Below a route with no segment position.
		beaconDoc(`{"script":"/a/x","post":"/a/y/z"}`, route),
		beaconDoc(`{"script":"/c/x","post":"/c/y"}`, route, cbRoute),
		// Only the start of a name is shared, not a whole segment.
		beaconDoc(`{"script":"/sx","post":"/s.js"}`, route, seg),
	)
	b := loadRaw(t, nil, nil, site(text)...)
	if rm, _ := b.Routes("h.example"); rm.Beacon == nil || *rm.Beacon != (Beacon{"/b.js", "/b/p"}) {
		t.Errorf("beacon %+v", rm.Beacon)
	}
}

// T-U-25: a beacon is refused when it is not an object with the two paths.
// It is refused when a path has an invalid form or is a route path.
func TestTU25BeaconRefused(t *testing.T) {
	route := `{` + pa + `,` + ti + `,` + ty + `}`
	for _, b := range []string{
		`null`, `true`, `"/b"`, `[]`, `{}`, `{"script":"/b"}`, `{"post":"/b"}`,
		`{"script":"/b","post":null}`, `{"script":null,"post":"/b"}`, `{"script":"/b","post":1}`,
		`{"script":"/b","post":"/c","other":"/d"}`, `{"Script":"/b","post":"/c"}`,
		`{"script":"/b","script":"/d","post":"/c"}`,
		`{"script":"/b","post":"/b"}`,
		`{"script":"b","post":"/c"}`, `{"script":"/b","post":""}`, `{"script":"/b/","post":"/c"}`,
		`{"script":"/b","post":"/c//d"}`, `{"script":"/b","post":"/c/../d"}`, `{"script":"/b?x","post":"/c"}`,
		`{"script":"/b","post":"/` + strings.Repeat("c", 256) + `"}`,
		`{"script":"/a","post":"/c"}`, `{"script":"/c","post":"/a"}`,
	} {
		refuse(t, beaconDoc(b, route))
	}
	cbRoute := `{"path":"/k","callback":{"query":"q"}}`
	refuse(t, beaconDoc(`{"script":"/k","post":"/c"}`, route, cbRoute), beaconDoc(`{"script":"/c","post":"/k"}`, cbRoute, route))
	// The beacon before the routes does not change the result.
	refuse(t, `{"beacon":{"script":"/a","post":"/c"},"routes":[`+route+`]}`)
}

// T-U-25: a beacon path below the path of a route that has a segment position
// is refused, at any depth. Each path but "/" is below the root route.
func TestTU25BeaconBelowSegment(t *testing.T) {
	seg := `{"path":"/s","callback":{"segment":true}}`
	segDeep := `{"path":"/s/t","callback":{"segment":true,"query":"q"}}`
	root := `{"path":"/","callback":{"segment":true}}`
	for _, c := range []struct{ b, routes string }{
		{`{"script":"/s/x","post":"/c"}`, seg},
		{`{"script":"/c","post":"/s/x"}`, seg},
		{`{"script":"/s/x/y","post":"/c"}`, seg},
		{`{"script":"/s/t/x","post":"/c"}`, segDeep},
		{`{"script":"/s/t/x","post":"/c"}`, seg + "," + segDeep},
		{`{"script":"/x","post":"/c"}`, root},
		{`{"script":"/c","post":"/x/y"}`, root},
	} {
		refuse(t, beaconDoc(c.b, c.routes), `{"beacon":`+c.b+`,"routes":[`+c.routes+`]}`)
	}
	// A path above a deeper segment route is not below it.
	loads(t, beaconDoc(`{"script":"/s/x","post":"/c"}`, segDeep))
	// A beacon path "/" is the path of the root route.
	refuse(t, beaconDoc(`{"script":"/","post":"/c"}`, root))
	loads(t, beaconDoc(`{"script":"/x","post":"/c"}`, `{"path":"/","callback":{"query":"q"}}`))
}

// T-U-25: a caller cannot change the kept callback or beacon through the copy
// that Routes returns.
func TestTU25RoutesCopy(t *testing.T) {
	text := beaconDoc(`{"script":"/b.js","post":"/b/p"}`, `{"path":"/s","callback":{"segment":true,"query":"q"}}`)
	b := loadRaw(t, nil, nil, site(text)...)
	rm, _ := b.Routes("h.example")
	rm.Routes[0].Callback.Query = "changed"
	rm.Routes[0].Callback.Segment = false
	rm.Beacon.Script = "/changed"
	rm.Beacon.Post = "/changed"
	again, _ := b.Routes("h.example")
	if cb := *again.Routes[0].Callback; cb != (Callback{Segment: true, Query: "q"}) {
		t.Errorf("callback %+v changed", cb)
	}
	if *again.Beacon != (Beacon{"/b.js", "/b/p"}) {
		t.Errorf("beacon %+v changed", *again.Beacon)
	}
}
