services:
  nginx:
    profiles: ["nginx-module"]
    build:
      context: .
      dockerfile: nginx-module/Dockerfile
    ports:
      - "{nginx_http_port}:80"
{nginx_port_bindings}    depends_on:
      - honeypot
      - protected-app
    volumes:
      - neh-logs:/var/log/neh

  gateway:
    build:
      context: ./gateway
    ports:
      - "{gateway_http_port}:80"
    depends_on:
      - honeypot
      - protected-app
    environment:
      - PORT=80
      - LOG_FILE=/var/log/neh/nginx-events.jsonl
      - PROTECTED_BASE=http://protected-app:{protected_app_port}
      - HONEYPOT_BASE=http://honeypot:{honeypot_port}
    volumes:
      - neh-logs:/var/log/neh

  honeypot:
    build:
      context: ./honeypot
    environment:
      - PORT={honeypot_port}
      - LOG_FILE=/var/log/neh/honeypot.jsonl
    volumes:
      - neh-logs:/var/log/neh

  protected-app:
    build:
      context: ./protected-app
    environment:
      - PORT={protected_app_port}

  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:{elastic_version}
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
      - ES_JAVA_OPTS=-Xms512m -Xmx512m
    ports:
      - "{elasticsearch_port}:9200"

  kibana:
    image: docker.elastic.co/kibana/kibana:{elastic_version}
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
      - XPACK_SECURITY_ENABLED=false
      - XPACK_ENCRYPTEDSAVEDOBJECTS_ENCRYPTIONKEY={kibana_encryption_key}
    ports:
      - "{kibana_port}:5601"
    depends_on:
      - elasticsearch

  kibana-bootstrap:
    image: curlimages/curl:{curl_image_version}
    depends_on:
      - kibana
    volumes:
      - ./lab/kibana/neh-dashboard.ndjson:/assets/neh-dashboard.ndjson:ro
    entrypoint:
      - sh
      - -ceu
      - |
        until curl -fsS http://kibana:5601/api/status >/dev/null; do
          sleep 5
        done
        curl -fsS -X POST "http://kibana:5601/api/saved_objects/_import?overwrite=true" \
          -H "kbn-xsrf: true" \
          -F file=@/assets/neh-dashboard.ndjson >/dev/null

  telegram-bot:
    build:
      context: ./telegram-bot
    env_file:
      - ./.env
    environment:
      - ELASTICSEARCH_URL=http://elasticsearch:9200
    depends_on:
      - elasticsearch
      - kibana

  filebeat:
    image: docker.elastic.co/beats/filebeat:{elastic_version}
    user: root
    command: ["filebeat", "-e", "--strict.perms=false"]
    volumes:
      - ./filebeat/filebeat.yml:/usr/share/filebeat/filebeat.yml:ro
      - neh-logs:/var/log/neh:ro
    depends_on:
      - elasticsearch
      - gateway
      - honeypot

volumes:
  neh-logs:
