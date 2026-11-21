# Reference bundle

This directory holds the reference bundle of the Phantom sensor.
It has the source tree in `src/` and the tests of its content rules.
This text is for people who read the bundle.

## What the bundle is

The bundle is a stale, documented research artifact. It is not an attack tool.
This is constitution rule C9 (`spec/constitution-table.md`).
The project holds this position under German Criminal Code section 202c.
It rests on the facts in the sections below.
Each trap text asks for at most one request, and never for data.
Each trap text and each page holds the marker.
All of the content is public, also the token seed.
Of the signing key, only the key id is public.
The content rules make the bundle stale, not the age of the text.
All vhost names are below `.internal`.
Public DNS resolvers do not answer these names, and public CAs do not issue certificates for them.
These two facts come from outside this repo.
Thus the bundle cannot run as an Internet trap on its own names.
The sensor config refuses an internal name in `acme.names` when `acme.ca` is `letsencrypt` or `letsencrypt-staging`.
For an internal name, `acme.ca` must be an https URL.

## Content rules

The rules are SEC-42 in `spec/01-prd.md`.
The tests `rules_test.go` and `rules_refused_test.go` check them.

- Harm ceiling: each trap text asks for at most one request.
  The request goes to a callback path of its own vhost, with the token.
  No text asks for data.
- Overt marker: each trap text and each page holds the marker.
- Public text: all of the content is in this public repo.
- No evasion tier: each served output is cut into tokens of a closed grammar.
  Each word is part of the marker, of an exact trap render, or of an exact entry of a closed list.
  The closed lists are in `testdata/lists.txt` and in the fixed tables of `rules_test.go`.
- No active content: no template and no asset holds a script, an event attribute or a URL of a third party.
  The one exception is a script block of the type `application/ld+json`, with no `@context` and no `/*`.
- No table content: until the table formats exist, the bundle has no `fp/` directory, no `score/` directory and no sealed seed.
- Vhost names: each name is below `.internal`.
  The names are `shop.phantom-ref.internal` and `docs.phantom-ref.internal`.

## The marker

The marker is the string `phantom-reference-trap`.
A filter that drops each text with this string drops each reference trap.

## The public seed and forged callbacks

The file `src/secrets/token.seed` is public.
So anyone can make valid tokens for a sensor that runs this bundle.
The callback event of such a token has `reference_seed: true`.
For the alert of such a callback, the alert format in `spec/04-interfaces.md` gives two members.
These are `trap.reference_seed`, and `trap.note` with the text "reference seed: no C6 strength".

## The plugin manifest

The vhost shop has the file `src/vhosts/shop.phantom-ref.internal/plugin.tmpl`.
It has the shape of an `ai-plugin` manifest.
But the value of `api.url` is `/`, and the path `/` serves an HTML page.
The manifest offers no tool.

## Key and expiry

The key id is `ref1`.
The bundle expires on `2027-11-16T00:00:00Z`.
Both values are in `src/manifest.json`.
A test fails when fewer than 45 days remain before this date.

The release build trusts no reference key.
The function `releaseTrust()` in `cmd/phantom/bundle.go` returns an empty trust set.
The repo has no signed reference archive: it has no `reference.cbnd` and no `reference.sig`.

## Install

These steps apply to a signed archive and its signature.
The repo does not hold them.
Copy both files into the directory of the config setting `bundle.path`.
The default of `bundle.path` is `/var/lib/phantom/bundle/current.cbnd`.
The file name must end in `.cbnd`.
The config requires this path to be below the state directory.
The directory must not be the state directory itself.
It must not be the keys directory or the checkpoints directory, or be in one of them.
The config refuses more paths, for example a path in the log directory.
The rules are in `checkBundlePath` and `bundleConflict` in `internal/config/validate.go`.
The signature has the same name, with `.sig` in place of `.cbnd`.
Give each file the mode `0600`.
The loader refuses a file that the group can write.
It also refuses a file that other users can read or write.
The owner of each file must be the sensor user or root.
Each file must be a regular file with one link only.
The archive is at most 8 MiB, and the signature is at most 1 KiB.

## Fetch source

The project serves no fetch URL (`bundle.fetch_url`) for the reference bundle.

## Legal

This text is not legal advice.
