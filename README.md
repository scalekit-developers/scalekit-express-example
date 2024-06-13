<p align="center">
  <a href="https://scalekit.com" target="_blank" rel="noopener noreferrer">
    <picture>
      <img src="https://cdn.scalekit.cloud/v1/scalekit-logo-dark.svg" height="64">
    </picture>
  </a>
  <br/>
</p>
<h1 align="center">
  Scalekit Express Example App
</h1>
<h4 align="center">
Scalekit helps you ship Enterprise Auth in days.

This is an example Express.js app that demonstrates how to use the Scalekit Node SDK to integrate Scalekit with your Node.js applications.
</h4>

## Getting Started

1. [Sign up](https://scalekit.com) for a Scalekit account.
2. Get your `env_url`, `client_id` and `client_secret` from the Scalekit dashboard.

## How to Run

```sh
# Clone the repository
git clone --recursive https://github.com/scalekit-inc/scalekit-express-example.git
```

```sh
# Install scalekit-express-example dependencies
npm install
```

```sh

# Update .env file with env_url, client_id and client_secret fetched from the Scalekit dashboard as below
SCALEKIT_ENV_URL = env_url
SCALEKIT_CLIENT_ID = client_id
SCALEKIT_CLIENT_SECRET = client_secret
```

```sh
# Run the server:
npm start
```

```sh
Open http://localhost:8080 with your preferred browser

```

## API Reference

See the [Scalekit API docs](https://docs.scalekit.com/apis) for more information about the API and authentication.