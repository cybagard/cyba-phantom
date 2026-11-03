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
