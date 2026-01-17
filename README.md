# CheckOCPP

CheckOCPP is a Wireshark dissector for the Open Charge Point Protocol (OCPP). It provides an efficient and scalable solution for passive compliance audits by automatically detecting OCPP versions, validating message structures, and flagging non-compliant packets.

## Features
- **Automatic OCPP version detection**: Identifies whether captured traffic corresponds to OCPP 1.6J, 2.0J, or 2.0.1J.
- **Protocol compliance validation**: Checks message structure and schema conformity.
- **Non-compliant packet highlighting**: Flags invalid packets to aid debugging and compliance verification.
- **IPv4/IPv6 traffic distinction**: Provides a visual indicator for OCPP packets transmitted over IPv4.
- **Selectable procotol version**:
    - option **All versions**: Processes OCPP packets without distinguishing between versions.
    - option **specific version**: Dissects only one specific protocol version and adds expert information for more precise analysis.

## Installation
1. Ensure you have Wireshark installed on your system.
1. Ensure the `wireshark` command is available from your system's PATH variable.
1. Ensure you have `luarocks`, a C compiler (needed by luarocks) and the correct version of the Lua interpreter installed on your system.
1. Ensure the `luarocks` command is available from your system's PATH variable.
1. The correct version of the Lua interpreter depends on the version of Wireshark you have installed. That is: For Wireshark 4.2.x and below Lua 5.2 is necessary. For Wireshark 4.3.0 and later Lua 5.4 is necessary. (see https://www.wireshark.org/docs/wsdg_html_chunked/wsluarm.html)
1. Along with the Lua interpreter, ensure that the Lua development files are installed. They are available in the `libluaX.Y-dev` on Linux systems and usually shipped by default on Windows installations.
1. Ensure that the Lua interpreter is either available from your system's PATH variable, or it is added to the luarocks configuration by calling `luarocks --lua-version X.Y variables.LUA <path/to/lua-executable>`
1. Optionally, a `Python` installation can be used to retrieve the jsonschemas necessary by the plugin. The schemas might also be downloaded elsewhere.
1. Depending on your system either the `installWin.cmd` or `installLinux.sh` script should be used to download the necessary lua libraries, add the paths to the `LUA_PATH` and `LUA_CPATH` environment variables and store the dissector to Wireshark's plugin folder. The script must be called the following way:
    ```
    install(Win.cmd|Linux.sh) (local|global) [verbose]
    ```
    - `local` as first argument will install the dissector to Wireshark's local lua plugin path
    - `global` as first argument will install the dissector to Wireshark's global lua plugin path. Note that for a global installation the script must be run with elevated privileges.
    - `verbose` as second argument will enable verbose output
1. and go back here
1. Restart Wireshark to load the dissector.
1. You might get an error message from Wireshark, especially on Windows systems, that some lua libraries were not found. If that happens, please restart Wireshark again.
1. Open the dissector preferences, navigate to the OCPP protocol and specify the path to the OCPP schemas. If you have no OCPP schemas installed yet, you can do that by calling `pip install ocpp`.

## Usage

1. Open Wireshark
2. Navigate to `Edit > Preferences > Protocols > OCPP` and ...
    - ... modify the path to the schemas, and
    - ... choose the protocol version to be dissected
3. Start capturing network traffic.
2. Apply the filter `ocpp` to isolate OCPP traffic.
3. Add the coloring rules.
4. Expand the OCPP protocol details to inspect message type, message ID, and payload validation results.
5. Look for highlighted packets to identify non-compliant or misconfigured OCPP messages.

## Limitations
- CheckOCPP only works with unencrypted traffic. If TLS is enabled, decryption keys are required.
- It only validates OCPP JSON version, not SOAP version.

## Known issues
- The `installWin.cmd` and `installLinux.sh` script replaces the libraries `lua-cjson`,and `net-url` with the version necessary for this plugin if they were already installed before the script started. This might break some other programs if one makes heavy use of lua.
    - Possible Workaround: Install the plugin manually and also install the necessary lua libraries manually with luarocks by creating a new rock. Afterwards, add the newly created rock to the LUA_PATH and LUA_CPATH variables.

## Information and Links for developers
- An introduction to Batch programming (Windows): https://tutorialreference.com/batch-scripting/batch-script-introduction
- Information on Batch command expansion (Windows): https://stackoverflow.com/questions/4094699/how-does-the-windows-command-interpreter-cmd-exe-parse-scripts/4095133#4095133
