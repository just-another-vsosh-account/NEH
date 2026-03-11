# NGX_HTTP_NEH_MODULE(7)

## NAME

`ngx_http_neh_module` - Nginx access-phase module for NEH URL or port knocking, honeypot diversion, host-bound access cookies, and temporary blocking.

## SYNOPSIS

```nginx
load_module /etc/nginx/modules/ngx_http_neh_module.so;

server {
    listen 80;
    listen 18081;
    listen 18082;
    listen 18083;

    neh_enable on;
    neh_knock_type uri;
    neh_sequence /start /verify /grant;
    neh_port_sequence 18081 18082 18083;
    neh_protected_uri /admin;
    neh_honeypot_uri /__neh_honeypot__;
    neh_cookie_name neh_access;
    neh_bind_host on;
    neh_timeout 30s;
    neh_access_window 60s;
    neh_block_threshold 4;
    neh_block_duration 120s;
    neh_randomize_sequence off;
    neh_random_secret neh-demo-seed;
    neh_sequence_count 3;
    neh_path_prefix knock;
}
```

## DESCRIPTION

`ngx_http_neh_module` protects a hidden target by requiring a knock sequence before access to the protected URI is granted.

Supported knock modes:

- `uri`: client must request a configured sequence of paths
- `port`: client must hit a configured sequence of listening ports

When the sequence is completed:

- a temporary access window is opened
- a host-bound access cookie is issued
- requests to the protected URI are allowed only while the grant is valid

When validation fails:

- the request can be redirected to the honeypot
- repeated failures can trigger a temporary block state
- events are exposed via Nginx variables for SIEM logging

## DIRECTIVES

### `neh_enable`

Syntax:

```nginx
neh_enable on | off;
```

Enables or disables the module in the current location context.

### `neh_knock_type`

Syntax:

```nginx
neh_knock_type uri | port;
```

Selects the knock mode.

- `uri`: use `neh_sequence`
- `port`: use `neh_port_sequence`

Alias also supported:

```nginx
neh_knok_type uri | port;
```

### `neh_sequence`

Syntax:

```nginx
neh_sequence /step1 /step2 /step3 ...;
```

Defines the URI knock sequence for `neh_knock_type uri`.

Example:

```nginx
neh_sequence /start /verify /grant;
```

### `neh_port_sequence`

Syntax:

```nginx
neh_port_sequence 18081 18082 18083 ...;
```

Defines the port knock sequence for `neh_knock_type port`.

The Nginx server must also `listen` on those ports.

### `neh_protected_uri`

Syntax:

```nginx
neh_protected_uri /admin;
```

URI that becomes available only after successful knock validation.

### `neh_honeypot_uri`

Syntax:

```nginx
neh_honeypot_uri /__neh_honeypot__;
```

Internal URI used for redirecting suspicious or denied traffic to the honeypot backend.

### `neh_cookie_name`

Syntax:

```nginx
neh_cookie_name neh_access;
```

Name of the issued access cookie.

Behavior:

- cookie is `HttpOnly`
- cookie uses `SameSite=Strict`
- no `Domain` attribute is set, so it stays host-only

### `neh_bind_host`

Syntax:

```nginx
neh_bind_host on | off;
```

When enabled, the module binds granted access to the host used during the successful sequence. Using the same token on a different host causes denial/block handling.

### `neh_timeout`

Syntax:

```nginx
neh_timeout 30s;
```

Maximum time allowed between knock steps before the sequence resets.

### `neh_access_window`

Syntax:

```nginx
neh_access_window 60s;
```

Duration of temporary access after a successful sequence.

### `neh_block_threshold`

Syntax:

```nginx
neh_block_threshold 4;
```

Number of failures after which a temporary block is activated.

### `neh_block_duration`

Syntax:

```nginx
neh_block_duration 120s;
```

Length of the temporary block after the threshold is exceeded.

### `neh_randomize_sequence`

Syntax:

```nginx
neh_randomize_sequence on | off;
```

Enables deterministic random URI generation based on host and secret instead of explicit `neh_sequence`.

Use this only with `neh_knock_type uri`.

### `neh_random_secret`

Syntax:

```nginx
neh_random_secret your-secret-value;
```

Seed used to generate deterministic random URI knock paths.

### `neh_sequence_count`

Syntax:

```nginx
neh_sequence_count 3;
```

Number of generated random URI steps when `neh_randomize_sequence on`.

### `neh_path_prefix`

Syntax:

```nginx
neh_path_prefix knock;
```

Prefix used when generated random URI paths are built.

Example generated path shape:

```text
/knock-deadbeef
```

## VARIABLES

The module exposes these variables for access logs and SIEM pipelines:

- `$neh_event`
- `$neh_decision`
- `$neh_note`
- `$neh_step`

Typical values:

- `event`: `knock_progress`, `knock_success`, `protected_allowed`, `protected_denied`, `request_blocked`
- `decision`: `await_next`, `grant_window`, `pass`, `honeypot`, `blocked`
- `note`: `sequence_ok`, `cookie_valid`, `cookie_missing`, `cookie_invalid`, `host_mismatch`, `threshold_exceeded`

## URI MODE EXAMPLE

```nginx
server {
    listen 80;
    server_name _;

    neh_enable on;
    neh_knock_type uri;
    neh_sequence /start /verify /grant;
    neh_protected_uri /admin;
    neh_honeypot_uri /__neh_honeypot__;
    neh_cookie_name neh_access;
    neh_bind_host on;
    neh_timeout 30s;
    neh_access_window 60s;
}
```

Client flow:

1. `GET /start`
2. `GET /verify`
3. `GET /grant`
4. `GET /admin`

## PORT MODE EXAMPLE

```nginx
server {
    listen 80;
    listen 18081;
    listen 18082;
    listen 18083;
    server_name _;

    neh_enable on;
    neh_knock_type port;
    neh_port_sequence 18081 18082 18083;
    neh_protected_uri /admin;
    neh_honeypot_uri /__neh_honeypot__;
}
```

Client flow:

1. request port `18081`
2. request port `18082`
3. request port `18083`
4. open `/admin` on the protected listener

## RANDOM URI MODE EXAMPLE

```nginx
server {
    listen 80;
    server_name _;

    neh_enable on;
    neh_knock_type uri;
    neh_randomize_sequence on;
    neh_random_secret neh-prod-secret;
    neh_sequence_count 3;
    neh_path_prefix knock;
}
```

In this mode, explicit `neh_sequence` is not required. Paths are derived deterministically from:

- random secret
- host
- step number

## SIEM INTEGRATION

Recommended log fields:

- `host`
- `remote_addr`
- `uri`
- `event`
- `decision`
- `note`
- `step`

These fields are already used by the current project’s JSON access log.

## NOTES

- Port knock mode requires exposed listener ports in both Nginx and Docker Compose.
- Cookie validation is checked on access to the protected URI.
- Host binding is enforced only when `neh_bind_host on`.
- Blocking is stateful per source IP.

## FILES

- `nginx-module/ngx_http_neh_module.c`
- `nginx-module/config`
- `nginx/nginx.conf`

## SEE ALSO

- [setup_neh.py](/home/ilyastarcek/vsosh/setuper/setup_neh.py)
- [NEH_SETUP_MAN.md](/home/ilyastarcek/vsosh/setuper/NEH_SETUP_MAN.md)
