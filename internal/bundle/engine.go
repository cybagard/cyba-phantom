package bundle

import "slices"

// EngineVersion is the version of this engine. A manifest whose min_engine is
// above it gives ErrMinEngine. A release changes this constant.
const EngineVersion = "1.0.0"

// CheckEngine gives ErrMinEngine when min_engine of the manifest is above
// EngineVersion. The check compares the parts as numbers, from the major part
// to the patch part. An equal version passes.
func (m *Manifest) CheckEngine() error {
	engine, ok := parseEngine(EngineVersion)
	if !ok {
		// EngineVersion is a constant of this package; a test covers its form.
		return ErrMinEngine
	}
	return checkEngine(m.MinEngine, engine)
}

func checkEngine(minEngine, engine [3]int) error {
	if slices.Compare(minEngine[:], engine[:]) > 0 {
		return ErrMinEngine
	}
	return nil
}
