# Localization reconciliation

Compared on 2026-09-19 against main
`0441b02cbc8678b3d6c57a513f1c8a1ce0bb5122`. Only `app.py`, `db.py`,
`schema.sql` and `requirements.txt` were read from `/opt/sovereign-core-auth`
on the operator-confirmed production host. No database, environment, logs,
backups or virtualenv were read or copied for this task. Production was not changed.

## Complete substantive difference classification

A = legitimate production feature missing in Git; B = superseded code;
C = environment/deployment concern; D = security or compatibility risk;
E = unresolved difference requiring a stop.

| Difference | Class | Resolution |
|---|---|---|
| `get_request_lang`, Danish/English catalog and `tr_auth` | A | Preserve both languages and request-local selection; no mutable global catalog/state. |
| Language inherited from the destination query when absent on the auth page | A, D | Preserve only from an exact trusted origin. Explicit invalid, empty or repeated selections use Danish rather than inheriting. Accept only exact `da`/`en`; live lowercasing/trimming is intentionally not preserved. |
| `build_auth_query` and language-bearing auth links | A, D | Preserve navigation with `urlencode`; live's unescaped `#`/`=`/`?` and percent-preserving construction is replaced with complete parameter encoding. |
| Root labels, login/account labels and status messages | A | Localize HTML and script values in their respective safe contexts. Root navigation continues to carry language only. |
| Register labels/status and login/register links | A, D | Preserve and complete localization of headings, email and disabled-registration message; repair live's literal `{lang}` and lost query on the disabled-registration page. |
| Account profile/password/reset warning, admin link and logout navigation | A, D | Preserve translated UI; retain selected language through forced password change too. Preserve the original destination through account login, which live dropped. |
| Admin translated labels, filters, actions and reset status | A, D | Use explicit template slots and HTML-safe JSON, not live's runtime global substring replacement. Mobile labels use escaped `data-label` attributes with CSS `attr(data-label)`. Keep machine values and the current entitlement controls/CSRF unchanged; localize their human labels too. |
| Launcher integration | A | Ordinary trusted `return_to` to `apps.innosocia.dk`, optionally supplying `lang`; no separate launcher API or entitlement behavior exists in this difference. |
| Language cookies/sessions/API changes | No difference | Live localization has no language cookie/session storage or translated API contracts; none are introduced. |
| Prefix-based `return_to` validation | B, D | Reject live implementation; preserve exact-origin, control-character and backslash checks from main. |
| `request.url`/`request.base_url` login destinations | D | Use canonical auth origin and known route with encoded destination/language, independent of request Host. |
| Python `repr` interpolated into JavaScript | B, D | Reject; retain HTML-safe JSON for destinations and use it for translated script strings. |
| Unescaped account values and raw return link | B, D | Reject; preserve profile escaping and escape the validated return URL in the HTML attribute. |
| Broad admin text replacement | D | Reject; it can affect script text and translations by substring. Explicit slots preserve stable roles, action keys and filters. |
| Missing admin no-store/CORS isolation and CSRF checks | B, D | Keep main's response policies, token endpoint and all CSRF-protected actions. |
| Missing validate entitlements/fail-closed handling and SQLite error handler | B, D | Keep main unchanged. |
| Missing admin catalog/entitlement API and DOM controls | B | Keep PR #10 implementation, including safe `textContent` rendering. |
| Naive datetime parsing in live | B, D | Keep timezone-aware validation from main. |
| Live fixed database path versus explicit path support | B, C | Keep main's configuration support; production path/service details are not copied into runtime configuration. |
| Live implicit database creation and unverified foreign keys | B, D | Keep existing-file requirement, foreign-key enforcement and verification. |
| Live schema execution and individual connection/write helpers | B, D | Keep atomic migration, rollback/closure handling, explicit transactions and operator CLI from main. |
| Missing `apps`, `user_apps`, constraints/index and Writer catalog insertion | B | Keep main's additive schema, no automatic grants. |
| `requirements.txt` | Identical | No dependency changes. |
| Account CSS indentation and blank lines | Formatting only | Do not port. |

There are no unresolved class E differences in these four files. All other API
function bodies and runtime constants in `app.py` are the same as main; the
localization port leaves the current API function bodies unchanged. `db.py`,
`schema.sql` and `requirements.txt` remain byte-identical to main.

## Source identity (code only)

| Live file | SHA-256 |
|---|---|
| `app.py` | `b80aa41b0c77401b6417a5f0ccb7ed78b27556884f616dd6d14ada150c3183bd` |
| `db.py` | `2c10e8a1b28038c644572c4e3527abcda1751b6e06d172084d90c6caed1e62a6` |
| `schema.sql` | `40b20f603a3fa4bbef87528067910ecb18ec911a907e045bca05920f8f91a6ad` |
| `requirements.txt` | `e1e640b340ff07a07787c66f1cbfb032ba01346b2c7bb5901979a4f94c9a637f` |

## Verification scope

Regression coverage includes language selection/fallback and query round trips,
all five pages, denied/disabled states, hostile HTML/script/profile/translation
values, login/register/logout/reset navigation, launcher return, API contracts,
and entitlement grant/revoke with CSRF on isolated test databases. Rendered
JavaScript is syntax-checked and its relevant handlers are exercised with Node
DOM/fetch doubles. Gunicorn imports the WSGI app and health is exercised with all
SQLite connections blocked. These checks do not claim a real browser or live
production smoke test. Node must be installed to run the localization tests.

Deployment remains a separate operator action using the documented backup,
migration and rollback procedure. No PR, merge or deployment is part of this task.
