`health.json` is reconstructed from the Docker `/health` handler with an arbitrary
non-sensitive timestamp. The handler imports the installed `crawl4ai.__version__`;
the configurable OpenAPI version is not used. `logo.png` is the unchanged
1622-byte public `/static/assets/crawl4ai-logo.png` asset, SHA-256
`50dafdc7defc6da27ae873dca7d48aef7187888506f4748c8e0022f9886b4c42`.
Neither fixture is a live capture.

Source pins (same health schema and logo at all three):

- [v0.8.5](https://github.com/unclecode/crawl4ai/tree/4bf17796d422fb1876918c169ebe909552b0fb21)
- [v0.8.6](https://github.com/unclecode/crawl4ai/tree/4e4a996878cfa577d24b3a45c91b0e51429b3671)
- [v0.8.7](https://github.com/unclecode/crawl4ai/tree/7b280d36b150b544bf0994285b4755dca18c2149)

Paths: `deploy/docker/server.py`, `deploy/docker/config.yml`,
`deploy/docker/static/assets/crawl4ai-logo.png`, `crawl4ai/__version__.py`.
The reader supports stable package metadata from 0.8.5 onward only. Older servers
may report stale `0.5.1-d1`; malformed, fork-marked or prerelease metadata stays
inconclusive. Unmarked forks/backports cannot be distinguished by metadata alone.
