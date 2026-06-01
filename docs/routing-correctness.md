# Routing Correctness

## Objective

The route table is the most important correctness surface in the repository. A small change in rule order can alter the entire behavior of the config because route rules are evaluated in order. This document keeps the current single-config model, but makes route behavior easier to audit.

## Current routing risks

| Risk | Why it matters | Simple handling |
|---|---|---|
| Rule order drift | Earlier rules can shadow later rules | Validate route order and add rule tags |
| Missing outbound target | A route points to a nonexistent outbound | CI validation fails |
| Missing inbound target | A route references a nonexistent inbound | CI validation fails |
| Unclear catch-all behavior | Unsupported traffic may be direct or blocked unexpectedly | Document final rules and test them |
| Duplicate tag names | Debug output becomes ambiguous | CI validation fails |
| Static CIDR without rationale | Future reviewers cannot know why it exists | Add comment in the route intent table |
| Protocol ambiguity | TCP and UDP may behave differently | Explicitly document network field and UDP policy |
| Geosite/GeoIP drift | Same config behaves differently with different data versions | Record geosite/geoip hashes in release evidence |

## Rule tagging convention

Add `ruleTag` to every rule. This has near-zero runtime cost and provides large operational value.

Suggested format:

```text
rNNN_<action>_<scope>_<protocol_optional>
```

Examples:

```text
r010_block_ads
r020_repack_dns_cloudflare
r025_repack_dns_google
r030_dns_port53
r040_direct_private_regional
r100_repack_googlevideo_h11
r110_block_unmatched_h11
r120_repack_google_h2
r130_repack_fastly_h2
r140_repack_meta_h2
r150_repack_fastly_ip_h2
r160_block_unmatched_h2
r200_redirect_googlevideo_tcp443_h11
r210_redirect_group_tcp443_h2
r300_block_static_bad_ranges
r310_direct_private_regional_ip
r320_redirect_fastly_ip_tcp443_h2
r900_direct_global_catchall
r999_block_final
```

## Route intent table

Maintain this table in `docs/routing-correctness.md`. The machine-readable source of truth is `configs/route-intent.json`, verified by:

```bash
python scripts/route_intent_sync.py Xray-config/MITM-DomainFronting.json
```

| Rule tag | Match | Outbound | Intent | Expected failure behavior |
|---|---|---|---|---|
| `r010_block_ads` | ad-category domains | `block` | Reduce ad/tracker traffic | False positive may break some login pages |
| `r020_repack_dns_cloudflare` | Cloudflare DNS resolver inbound | Cloudflare DNS repack outbound | Keep primary DNS path reachable | Google fallback should handle primary timeout |
| `r025_repack_dns_google` | Google DNS resolver inbound | Google DNS repack outbound | Keep secondary DNS path reachable | Local resolver remains last-resort/private fallback |
| `r030_dns_port53` | port 53 | `dns-out` | Handle plain DNS | Local DNS may still be environment-dependent |
| `r040_direct_private_regional` | private/regional domains | `direct` | Avoid breaking local/regional services | Depends on geosite data |
| `r100_repack_googlevideo_h11` | Googlevideo through h11 inbound | google repack | Keep video media path working | Breaks if provider/SNI behavior changes |
| `r110_block_unmatched_h11` | unmatched h11 decrypted traffic | `block` | Prevent accidental unsupported h11 behavior | User sees unsupported site failure |
| `r120_repack_google_h2` | Google through h2 inbound | google repack | Keep Google-family h2 path working | Depends on geosite data |
| `r130_repack_fastly_h2` | Fastly/Reddit/CNN/Buzzfeed through h2 | fastly repack | Keep Fastly-backed targets working | Provider or IP drift can break |
| `r140_repack_meta_h2` | Meta through h2 | meta repack | Keep Meta-family targets working | App-specific CA/pinning can still fail |
| `r150_repack_fastly_ip_h2` | Fastly IPs through h2 | fastly repack | Cover IP-based Fastly classification | GeoIP drift risk |
| `r160_block_unmatched_h2` | unmatched h2 decrypted traffic | `block` | Avoid undefined decrypted handling | Unsupported site failure |
| `r200_redirect_googlevideo_tcp443_h11` | TCP/443 googlevideo | local h11 tunnel | Enter local decrypt/repack path | Port conflict breaks flow |
| `r210_redirect_group_tcp443_h2` | TCP/443 service groups | local h2 tunnel | Enter local decrypt/repack path | Port conflict breaks flow |
| `r300_block_static_bad_ranges` | documented static IP ranges | `block` | Preserve known bad-range behavior | Must have rationale |
| `r310_direct_private_regional_ip` | private/regional IPs | `direct` | Preserve LAN/regional reachability | GeoIP drift risk |
| `r320_redirect_fastly_ip_tcp443_h2` | Fastly IP TCP/443 | local h2 tunnel | Cover Fastly IP path | GeoIP drift risk |
| `r900_direct_global_catchall` | all IPv4/IPv6 | `direct` | Current simple fallback behavior | May hide unsupported targeted breakage |
| `r999_block_final` | all remaining ports | `block` | Explicit final fallback | Should rarely match |

## Required validation checks

`python scripts/validate_config.py Xray-config/MITM-DomainFronting.json` should verify:

- JSON parses.
- Inbound tags are unique.
- Outbound tags are unique.
- Every route `outboundTag` exists.
- Every route `inboundTag` exists.
- Every route has a `ruleTag` or is reported as missing.
- Every `ruleTag` is unique and follows `rNNN_name` format.
- Current route order matches the documented rule-tag sequence.
- TCP/443 redirect rules are present.
- Redirect outbounds point to the matching loopback tunnel ports.
- DNS port 53 rule is present.
- Final catch-all is explicit.
- Local inbounds are loopback-bound or are reported as a high-priority warning.
- Static non-catchall CIDRs are listed in the documented rationale set.

`python scripts/route_policy_tests.py` should verify:

- The base config keeps its documented direct global catch-all.
- Profile configs have exactly one explicit UDP/443 policy rule.
- Strict profile blocks the global catch-all and UDP/443.
- Balanced and compatibility profiles keep direct fallback and direct UDP/443 with documented warning.
- Debug profile keeps access logs disabled and blocks UDP/443 to surface QUIC mismatch.

## Keep the current simple behavior

This document does not replace the primary single-config workflow. Generated strict/balanced/compatibility/debug profiles are optional artifacts derived from the primary config. The recommended minimum is:

1. Keep one config.
2. Add rule tags.
3. Add validation.
4. Document direct catch-all behavior clearly.
5. Run validation before every release.

## Config-src boundary (phase 1)

The user import path remains `Xray-config/MITM-DomainFronting.json`. `config-src/manifest.json` declares the primary source and validation steps (`validate_config`, `route_intent_sync`, `route_policy_tests`, `transport_experiment_validate`). Run:

```bash
python scripts/config_src_validate.py --run-steps
python scripts/config_src_build.py
```

Phase 2 merges fragments under `config-src/fragments/` into `build/config/MITM-DomainFronting.json` (gitignored) via `scripts/config_src_merge.py`. With an empty `fragments` array the compiled artifact is a validated copy.
