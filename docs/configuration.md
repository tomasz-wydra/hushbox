# Configuration

## Relay Environment Variables

These variables can be set in `docker-compose.yml` or through your deployment environment.

| Variable | Default | Description |
|----------|---------|-------------|
| `MESSAGE_TTL` | `86400` | Message retention in seconds |
| `MAX_QUEUE` | `500` | Maximum messages per recipient queue |
| `LONG_POLL_TIMEOUT` | `30` | Maximum long polling wait in seconds |
| `MAX_PAYLOAD` | `65536` | Maximum payload size in bytes |
| `PORT` | `5000` | Relay server port |

## Client Settings

Client settings are stored locally, for example in `settings.json`, depending on the current implementation.

Typical settings include:

- relay URL,
- local UI preferences,
- local application state.

## Recommended Defaults

For small self-hosted deployments:

- keep message retention low,
- use HTTPS,
- do not expose debug mode,
- monitor queue growth and payload sizes.