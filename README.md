# CTF Docs

[![pipeline status](https://gitlab.com/xanhacks/ctf-docs/badges/master/pipeline.svg)](https://gitlab.com/xanhacks/ctf-docs/-/commits/master)
[![github star](https://img.shields.io/github/stars/xanhacks/ctf-docs.svg?style=social&label=Star)](https://github.com/xanhacks/ctf-docs)

Documentation and cheatsheets about CTF and pentest.

**Warning :** This documentation is under construction, the architecture of the site will evolve regularly and some articles are not finished.

**Live demo** at [https://docs.xanhacks.xyz/](https://docs.xanhacks.xyz/).

## Installation

```bash
$ python3 -m pip install mkdocs mkdocs-material mkdocs-macros-plugin
$ mkdocs serve
INFO     -  Building documentation...
INFO     -  [macros] - Macros arguments: {'module_name': 'main', 'modules': [], 'include_dir': '', 'include_yaml': [], 'j2_block_start_string': '',
            'j2_block_end_string': '', 'j2_variable_start_string': '', 'j2_variable_end_string': '', 'on_undefined': 'keep', 'verbose': False}
INFO     -  [macros] - Extra variables (config file): ['homepage', 'base_url', 'social']
INFO     -  [macros] - Extra filters (module): ['pretty']
INFO     -  Cleaning site directory
INFO     -  Documentation built in 0.99 seconds
INFO     -  [14:46:35] Serving on http://127.0.0.1:8000/
```

## Made with

Made with [mkdocs](https://github.com/mkdocs/mkdocs) and the [material theme](https://squidfunk.github.io/mkdocs-material/).

Deployed with Gitlab pages.

## Inspired by

Inspired by and complementary to [hacktricks](https://github.com/carlospolop/hacktricks) and [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings).
