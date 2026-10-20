# Third-party firmware — provenance and licensing

This file is about other people's bytes. [`LICENSE`](LICENSE) is about ours.

## What this repository contains

Our own code is MIT, as `LICENSE` says.  **No firmware image, CMSIS header, or build
artifact of anyone else is committed here.**  `.gitignore` excludes `samples/` and
`socdb-src/` on purpose, and every check that needs real firmware downloads it, verifies it,
and leaves it in the working directory of whoever ran that check.  What this repository
publishes about third-party data is a URL, a release tag, and sha256 digests.

## What gets downloaded for verification

| thing | value |
|---|---|
| upstream | `openmv/openmv` |
| release | `v5.0.1` (not a prerelease; one asset) |
| asset | `firmware_v5.0.1.zip`, 90,999,894 bytes |
| asset sha256 | `1338b9607b57d88cf1de5aee115ea0e18cb17d06ff4d8dc55d6c022dba66dbc8` |
| fetched by | `python tools/get_sample.py --all` |
| re-checked by | `python tools/get_sample.py --all --check` |

The archive carries every OpenMV target, so extraction selects by path and each file used by
the scanner is pinned by its own sha256 in `tools/get_sample.py` (`BOARDS`).  A byte that
differs from its pin aborts the fetch: `verification/*.md` describes specific bytes, and a
moved byte moves every number in those documents.

The boards used today are the `OPENMV2` directory (an STM32F427 camera) and the `OPENMV3`
directory (an STM32F765 one).

## What upstream says about its licence — quoted, not paraphrased

From `openmv/openmv` `README.md`, section "Licensing", at commit
`6f2cef58960ed10dc583bc2e5e75f8d1ab0272de` (README blob
`72da32310c3c24a61880afbc829422edddaf04ca`, 9,255 bytes, read 2026-10-18):

> Most of the code in the repository is licensed under the MIT license, with the following
> exceptions:
>
> * Some image library code is licensed under the GPL. This includes AGAST, LSD, and ZBAR.
>   GPL code can be completely disabled in a build by defining `OMV_NO_GPL` in the
>   `imlib_config.h` files.
> * Third-party libraries and drivers in `lib` and `drivers` are licensed under various
>   permissive licenses. Please consult the LICENSE file in each driver/library subdirectory
>   for more details.
> * Some drivers, modules, and libraries in OpenMV are proprietary and available for
>   non-commercial use only. These proprietary components can be disabled during the build
>   process. Official OpenMV hardware and licensed devices may use the proprietary code. For
>   commercial licensing options, contact openmv@openmv.io.

## What we could not establish, and therefore do not claim

This repository does **not** describe these firmware images as "MIT".  Two things we checked
and did not resolve:

- The default branch of `openmv/openmv` has no `LICENSE` file where we looked: the root
  listing (`contents/?ref=master`) has no entry named `LICENSE`, the `/license` API endpoint
  for that repository returns *Not Found*, and the repository object's `license` field is
  `null` — GitHub's own licence detection finds nothing.  The project README's badge links to
  `blob/master/LICENSE`.
- Inside the release archive there is exactly one licence file, `WINC1500/LICENSE`
  (1,427 bytes), which sits in a WiFi-module firmware directory we never fetch.

So the truthful characterisation is upstream's own, and it is about its *source*, not about
the bytes we download: most of that source is MIT, with GPL image-library components, various
permissive third-party licences, and some components upstream declares proprietary and
non-commercial-only.  A release artifact does not tell us which of those a given
`firmware.bin` contains, and we will not guess — which is the same rule this tool applies to a
chip it cannot separate.

## How we use them, and why that shape was chosen

- **Purpose:** they are an oracle, not a product.  `firmprint verify` scores our findings
  against the ELF's own symbol table, and `python tools/make_verification.py` turns the
  result into `verification/*.md`.  Nothing here re-publishes, re-hosts, patches, or
  embeds their bytes.
- **Ephemeral:** downloaded on demand by a person or a CI runner, verified per file, and
  never committed.  Anything that wants to run the verification downloads from upstream
  under upstream's terms — deliberately, because that keeps the licence decision where it
  belongs.
- **Cited:** every claim in `verification/` and in the case documents names the pinned bytes
  it came from, so a reader can re-fetch and re-check instead of trusting us.

## Adding a board

Before another board's firmware joins the answer key, add to this file: the directory name
in the archive, the true part it carries, the files and their sha256, and **what you actually
checked about its licence** — including where a licence was absent.  "It came from the same
release" is not evidence of a licence, and neither is a badge on someone else's README.
