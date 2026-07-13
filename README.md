# proxytool

`proxytool` is a proxy chaining tool specifically created to resolve an issue with connecting `proxychains` with HTTP(S) proxies.

## Configuration

The configuration file format and parsing logic are adapted from the popular `proxychains` tool, which is licensed under the **GPL 2.0** license. Ensure you have a valid `proxychains4.conf` in the directory where you run the tool.

## Features

- **Proxy Chaining Modes**: The 3 basic chaining rules are now fully implemented and supported:
  - **Dynamic Chain**: Proxies are chained in the order they appear, skipping any unresponsive proxies.
  - **Strict Chain**: Proxies are chained in the exact order they appear. If one proxy fails, the connection fails.
  - **Random Chain**: Proxies are chosen randomly from the list to form the chain.

## Compilation

To compile the project, navigate to the `src` directory and execute the following two commands:

1. **Compile the shared library (hooking mechanism):**
   ```bash
   cd src
   gcc -shared -fPIC -o proxytool_hook.so hook.c proxy_chain.c config.c socks.c http_connect.c base64.c -ldl
   ```

2. **Compile the main executable:**
   ```bash
   gcc main.c config.c proxy_chain.c socks.c http_connect.c base64.c -o proxytool
   ```

## Usage

You can route any command's network traffic through the proxy chain by prefixing it with the compiled `proxytool` executable.

```bash
./src/proxytool <command> [arguments...]
```

**Example:**
```bash
./src/proxytool curl http://example.com
```

## License

This project is licensed under the [GNU General Public License v2.0 (GPL-2.0)](LICENSE).

## Author

- **Name**: Babajide Olowoyo
- **Email**: olowoyobabajide@gmail.com
