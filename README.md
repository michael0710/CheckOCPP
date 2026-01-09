# CheckOCPP

CheckOCPP is a Wireshark dissector for the Open Charge Point Protocol (OCPP). It provides an efficient and scalable solution for passive compliance audits by automatically detecting OCPP versions, validating message structures, and flagging non-compliant packets.

## Features
- **Automatic OCPP version detection**: Identifies whether captured traffic corresponds to OCPP 1.6, 2.0, or 2.0.1.
- **Protocol compliance validation**: Checks message structure and schema conformity.
- **Non-compliant packet highlighting**: Flags invalid packets to aid debugging and compliance verification.
- **IPv4/IPv6 traffic distinction**: Provides a visual indicator for OCPP packets transmitted over IPv4.
- **Two dissector implementations**:
  - **Single dissector**: Processes OCPP packets without distinguishing between versions.
  - **Separate dissectors**: Assigns a distinct dissector to each OCPP version for more precise analysis.

## Installation

1. Ensure you have Wireshark installed on your system.
2. Then refer to the subsection regarding your system

### Installation on Windows
On Windows systems the batch script `installWin.cmd` can be used to install the dissector and the necessary lua libraries to a Wireshark installation.
Before running that script make sure that ...
- ... Wireshark is added to the PATH variable (the script determines the location to place the lua dissector from that variable)
- ... `luarocks` is installed and added to the PATH variable
- ... you have a C compiler installed, which is used by `luarocks` to build some lua library modules (especially `lua-cjson` for this dissector)
- ... you have the correct version of `Lua` installed on your system AND ...
  - ... either have the path to the Lua interpreter `luaXY.exe` added to the PATH variable
  - ... or have called `luarocks --lua-version X.Y variables.LUA <path/to/luaXY.exe>` before running that script
  - ... NOTE: that `XY` stands for the major and minor Lua version. For Wireshark 4.2.X and below Lua 5.2 is necessary. For Wireshark 4.3.0 and later Lua 5.4 is necessary.
- ... OPTIONAL but highly recommended is to have `Python` installed.

The dissector can now be installed and used after the following steps:
- Install the dissector by executing the `installWin.cmd` with either `single` or `multiple` given as the first argument and either `local` or `global` given as the second argument. If the script finishes without an error message, the dissector has been installed successfully.
  - `single` as the first argument will install the **Single dissector**
  - `multiple` as the first argument will install **Separate dissectors** for each version of OCPP
  - `local` as second argument will install the dissector to Wireshark's local lua plugin path
  - `global` as second argument will install the dissector to Wireshark's global lua plugin path
- Restart Wireshark to load the dissector.
- You might get an error message from Wireshark that some lua libraries were not found. If that happens, please restart Wireshark again.
- Open the dissector preferences, navigate to the OCPP protocol and specify the path to the OCPP schemas. If you have no OCPP schemas installed yet, you can do that by calling `pip install ocpp`.

### Installation on Linux
**NOTE**: this section is deprecated and will soon be replaced with a similar installation script as the `installWin.cmd` for Windows.
2. Use 'make install-single' or 'make install-multiple' to install the dissector.
3. Restart Wireshark to load the dissector.

## Usage

1. Open Wireshark
2. Navigate to `Edit > Preferences > Protocols > OCPP` and modify the path to the schemas.
3. Start capturing network traffic.
2. Apply the filter `ocpp` to isolate OCPP traffic if single dissector is installed. If not, search by `ocpp1.6`, `ocpp2.0`, or `ocpp2.0.1`.
3. Add the coloring rules.
4. Expand the OCPP protocol details to inspect message type, message ID, and payload validation results.
5. Look for highlighted packets to identify non-compliant or misconfigured OCPP messages.

## Limitations
- CheckOCPP only works with unencrypted traffic. If TLS is enabled, decryption keys are required.
- It only validates OCPP JSON version, not SOAP version.

## Known issues
- The `install.cmd` script replaces the libraries `lua-cjson`,and `net-url` with the version necessary for this plugin if they were already installed before the script started. This might break some other programs if one makes heavy use of lua.
  - Possible Workaround: Install the plugin manually and also install the necessary lua libraries manually with luarocks and create a new rock. Afterwards, add the newly created rock to the LUA_PATH and LUA_CPATH variables.
