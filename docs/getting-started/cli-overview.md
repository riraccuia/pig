# CLI overview

Tips for poking around the pig CLI.

## Help

Start here.

```bash
pig -h
```

## Version

Get the version of the binary.

```bash
pig -version
```

## Pig knows the docs

```bash
pig -docs
```

Some sections support the `-md` flag to output the content as markdown.

```bash
pig -docs config -md > fields.md
```

## Freeze a good command

```bash
pig -l -id lab -P . -k -sk secret -to-cfg json > lab.json
pig -config lab.json
```

`-to-cfg` prints and exits. Handy once a flag line is worth keeping, or as a starting point for a more complex setup.

## Convert config formats

Json and toml are both fine and it's all down to personal preference.
Flip between them in a second.

```bash
pig -config lab.json -to-cfg toml > lab.toml
pig -config lab.toml -to-cfg json > lab.json
```

Same settings, other format.

## Settings, secrets, and scripts

Some options can live in the environment instead of on the command line: tokens, WireGuard keys, and other bootstrap values.

Tunnel scripts also get their own read-only variables on each event (event type, adapter name, remote address, and so on).

```bash
pig -docs env
```

## Good to know

- `-P .` in NAT-T mode means “try everything”. Then check `pig -docs protos` when you want to pick one on purpose.
- Connect and listen look similar in help. A missing flag often means you’re on the wrong side, for instance `-R` is connect-only, and `-jwk` is listen-only.

## Next steps

- [CLI reference](../reference/cli/pig.md)
- [Quick start](quick-start.md)
- [Connect](../reference/cli/connect.md) / [Listen](../reference/cli/listen.md)