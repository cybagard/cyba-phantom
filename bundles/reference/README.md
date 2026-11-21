# Reference bundle

This directory holds the reference bundle of the Phantom sensor.
It has the source tree in `src/` and the tests of its content rules.
This text is for people who read the bundle.

## What the bundle is

The bundle is a stale, documented research artifact. It is not an attack tool.
This is constitution rule C9 (`spec/constitution-table.md`).
The project holds this position under German Criminal Code section 202c.
It rests on the facts in the sections below.
Each trap text asks for one request only, and never for data.
Each trap text and each page holds the marker.
All of the content is public, and the public seed gives no secret.
The bundle expires, and its key and expiry date are in the open.

## Content rules

The rules are SEC-42 in `spec/01-prd.md`.
The tests `rules_test.go` and `rules_refused_test.go` check them.

- Harm ceiling: each trap text asks for one request only.
  The request goes to a callback path of its own vhost, with the token.
  No text asks for data.
- Overt marker: each trap text and each page holds the marker.
- Public text: all of the content is in this public repo.
- No evasion tier: each served output is cut into tokens of a closed grammar.
  Each word is part of an exact entry of the closed lists in `testdata/lists.txt`.
- Vhost names: each name is below `.internal`.
  The names are `shop.phantom-ref.internal` and `docs.phantom-ref.internal`.

## The marker

The marker is the string `phantom-reference-trap`.
A filter that drops each text with this string drops each reference trap.

## The public seed and forged callbacks

The file `src/secrets/token.seed` is public.
So anyone can make valid tokens for a sensor that runs this bundle.
The callback event of such a token has `reference_seed: true`.
The alert text is "reference seed: no C6 strength".

## The plugin manifest

The vhost shop has the file `src/vhosts/shop.phantom-ref.internal/plugin.tmpl`.
It has the shape of an `ai-plugin` manifest.
But `api.url` is `/`, and that is an HTML page.
The manifest offers no tool.

## Key and expiry

The key id is `ref1`.
The bundle expires on `2027-11-16T00:00:00Z`.
Both values are in `src/manifest.json`.
A test fails when fewer than 45 days remain before this date.

On this head, the function `releaseTrust()` in `cmd/phantom/bundle.go` returns an empty trust set.
So the release build has no public key line for `ref1`.
The repo has no signed reference archive: it has no `reference.cbnd` and no `reference.sig`.

## Install

Copy the archive and its signature into the state directory.
The archive goes to the bundle path of the config.
The key is `bundle.path`, and its default is `/var/lib/phantom/bundle/current.cbnd`.
The signature has the same name, with `.sig` in place of `.cbnd`.
Give each file the mode `0600`.
The loader refuses a file that a group user can write.
It also refuses a file that another user can read or write.

## Fetch source

The project serves no fetch URL (`bundle.fetch_url`) for the reference bundle.

## Legal

This text is not legal advice.
