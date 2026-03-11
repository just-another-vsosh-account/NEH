load_module /etc/nginx/modules/ngx_http_neh_module.so;

worker_processes auto;

events {{
    worker_connections 1024;
}}

http {{
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;

    log_format neh_json escape=json
      '{{'
        '"ts":"$time_iso8601",'
        '"host":"$host",'
        '"remote_addr":"$remote_addr",'
        '"method":"$request_method",'
        '"uri":"$uri",'
        '"status":$status,'
        '"event":"$neh_event",'
        '"decision":"$neh_decision",'
        '"note":"$neh_note",'
        '"step":"$neh_step",'
        '"user_agent":"$http_user_agent"'
      '}}';

    access_log /var/log/neh/nginx-events.jsonl neh_json;
    error_log /var/log/neh/nginx-error.log info;

    sendfile on;
    keepalive_timeout 65;

    upstream protected_backend {{
        server protected-app:{protected_app_port};
    }}

    upstream honeypot_backend {{
        server honeypot:{honeypot_port};
    }}

    server {{
        listen 80;
{nginx_listens}        server_name _;

        neh_enable on;
        neh_knock_type {neh_knock_type};
        neh_sequence {neh_sequence};
        neh_port_sequence {neh_port_sequence};
        neh_protected_uri {neh_protected_uri};
        neh_honeypot_uri {neh_honeypot_uri};
        neh_cookie_name {neh_cookie_name};
        neh_bind_host {neh_bind_host};
        neh_timeout {neh_timeout};
        neh_access_window {neh_access_window};
        neh_block_threshold {neh_block_threshold};
        neh_block_duration {neh_block_duration};
        neh_randomize_sequence {neh_randomize_sequence};
        neh_random_secret {neh_random_secret};
        neh_sequence_count {neh_sequence_count};
        neh_path_prefix {neh_path_prefix};

        location = / {{
            default_type text/plain;
            return 200 "Демо-шлюз NEH\n";
        }}

        location = {neh_protected_uri} {{
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_pass http://protected_backend;
        }}

        location = {neh_honeypot_uri} {{
            internal;
            proxy_set_header Host $host;
            proxy_set_header X-Original-URI $request_uri;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_pass http://honeypot_backend;
        }}

        location / {{
            proxy_set_header Host $host;
            proxy_set_header X-Original-URI $request_uri;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_pass http://honeypot_backend;
        }}
    }}
}}
