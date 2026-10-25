//go:build ignore

// Package excludedpkg has a folder and no Go file for any platform. Thus go
// list reports an error for it and still gives its folder.
package excludedpkg
