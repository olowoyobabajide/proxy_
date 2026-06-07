# proxytool

`proxytool` is a proxy chaining tool specifically created to resolve an issue with connecting `proxychains` with HTTP(S) proxies.

## Configuration

The configuration file is adapted from the well-known `proxychains` project. Ensure you have a valid `proxychains4.conf` in the directory where you run the tool.

## Features

- **Dynamic Chain Method**: Currently, this is the default and only supported proxy chaining method.
- *Other chaining methods (like strict or random chains) will be implemented in future updates.*

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

This project is licensed under the [MIT License](LICENSE).

## Author

- **Name**: Babajide Olowoyo
- **Email**: olowoyobabajide@gmail.com
