# Web Log Parser

A `nanoagent.plugin/v0001` plugin.

## Tools

| Tool | Does | Code |
|---|---|---|
| `analyze_log` | Parses one Web log line and classifies it as an access or error record | `src/plugin/log.py` |

### Tasks

| Task | Does | Runner |
|---|---|---|
| `analyze-log` | Parses and classifies one Web server log line | `tool`, with `analyze_log` |

## Layout

```text
.
├── nanoagent.yaml
├── contract.py
├── README.md
├── LICENSE
├── pyproject.toml
├── uv.lock
├── .gitignore
├── .env
├── src/plugin/
├── tests/
├── ui/
├── product/
└── verifier/
```

`contract.py` is the one place a value's shape is declared. Its Output classes are the JSON Schemas the server offers and the agent sees, and every input and output is built into its class on the way in and out. A tool that fails raises; NanoAgent sees an MCP error.

## Develop and run

```bash
uv sync --extra dev
uv run pytest
```

Publishing checks every plugin rule: push the plugin to a public GitHub repository and run:

```bash
rush publish <server> <github-url>
```