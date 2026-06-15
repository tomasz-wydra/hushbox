# Relay Deployment

## Docker Compose

Start the relay with:

```bash
cd relay_server
docker compose up -d
```

This is the simplest way to run the Flask relay with MongoDB persistence.

## Reverse Proxy

For production use, put the relay behind a reverse proxy such as nginx or Traefik and enable HTTPS.

## Example nginx Configuration

```nginx
server {
    listen 443 ssl;
    server_name relay.example.com;

    ssl_certificate     /etc/letsencrypt/live/relay.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/relay.example.com/privkey.pem;

    location / {
        proxy_pass         http://localhost:5000;
        proxy_read_timeout 60s;
        proxy_buffering    off;
    }
}
```

## Deployment Notes

- Keep `proxy_read_timeout` higher than the relay long-poll timeout.
- Disable unnecessary buffering for long-poll responses.
- Restrict administrative access to the host.
- Monitor disk usage and queue growth.
- Review retention settings before exposing the relay publicly.