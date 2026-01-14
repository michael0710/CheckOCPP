#!/bin/bash
# Bash script to add the plugin to a given wireshark installation
#
# Prerequisites:
#     Wireshark installation (added to PATH)
#     LuaRocks (added to PATH) (to install required lua packages)
#     Lua (added to PATH, or registered with luarocks by calling
#             'luarocks --lua-version X.Y variables.LUA <path/to/luaXY.exe>' )
#             note that Wireshark version below 4.3.0 requires Lua5.2 while
#             later versions require Lua5.4
# Optional:
#     Python (to install the ocpp json schemas)
#
# SYNOPSIS
#     ./installLinux.sh (single|multiple) (global|local) [verbose]
#            single: adds the ocppDissector.lua file to the existing Wireshark
#                    installation
#            multiple: adds the separate files ocpp16Dissector.lua,
#                      ocpp20Dissector.lua, ocpp201Dissector.lua to the
#                      existing Wireshark installation
#            global: adds the plugin to the global plugin folder
#            local: adds the plugin to the user specific plugin folder

# some useful local functions -------------------------------------------------
#isVersionLT ver1 ver2, returns true or false
isVersionLT() {
    oldIFS=$IFS;
    IFS='.';
    read -r ver1major ver1minor ver1patch <<< "$1";
    read -r ver2major ver2minor ver2patch <<< "$2";
    rv="false"
    if [ $ver1major -lt $ver2major ]; then
        rv="true";
    elif [ $ver1major -eq $ver2major ]; then
        if [ $ver1minor -lt $ver2minor ]; then
            rv="true";
        elif [ $ver1minor -eq $ver2minor ]; then
            if [ $ver1patch -lt $ver2patch ]; then
                rv="true";
            fi
        fi
    fi
    echo $rv
    IFS=$oldIFS
}

# start of the actual script --------------------------------------------------
echo "Installing the CheckOCPP dissector to wireshark ...";

if [ $# -lt 2 ]; then
    echo "ERROR: expected at least two arguments, got $#";
    exit 1;
fi

if [ $1 != "single" ] && [ $1 != "multiple" ]; then
    echo "ERROR: invalid first argument '$1'. Expected 'single' or 'multiple'";
    exit 1;
fi
pluginType=$1

if [ $2 != "global" ] && [ $2 != "local" ]; then
    echo "ERROR: invalid second argument '$2'. Expected 'global' or 'local'";
    exit 1;
fi
installDirType=$2

if [ $2 = "global" ] && [ "$(id -u)" -ne 0 ]; then
	echo "ERROR: With the 'global' option, the script must be run in privileged mode!"
	exit 1
fi

if [ $# -ge 3 ] && [ $3 = "verbose" ]; then
    echo "Activating verbose output ...";
    set -v;
fi

echo "";
echo "Checking Wireshark installation ...";
if ! command -v wireshark >/dev/null 2>&1; then
    echo "# ERROR: No existing wireshark installation found";
    exit;
fi

echo "# Found existing Wireshark installation";

echo "";
echo "Checking version of Wireshark ...";
wiresharkVersion="$(wireshark -v | grep 'Wireshark [0-9.]*' | awk '{print $2}')";
# set lua version as stated in https://www.wireshark.org/docs/wsdg_html_chunked/wsluarm.html
if [ "$(isVersionLT ${wiresharkVersion} 4.3.0)" = "true" ]; then
    wsLuaVersion="5.2";
else
    wsLuaVersion="5.4";
fi
echo "# Found Wireshark version $wiresharkVersion, which requires Lua $wsLuaVersion";

if [ "$installDirType" = "global" ]; then
    pluginPath=/usr/lib/x86_64-linux-gnu/wireshark/plugins
else
    pluginPath=$HOME/.local/lib/wireshark/plugins
fi

echo "";
echo "Checking for LuaRocks installation ...";
if ! command -v luarocks >/dev/null 2>&1; then
    echo "# ERROR: LuaRocks is not available. Please install the lua libraries 'cjson', 'jsonschema' and 'net.url' manually";
    exit;
fi
echo "# LuaRocks is available";

echo "";
if [ ! -e "$pluginPath" ] || [ ! -d "$pluginPath" ]; then
    echo "Creating directory '$pluginPath' ...";
    if ! mkdir -p $pluginPath; then
        echo "# ERROR: 'mkdir' command failed";
        exit;
    fi
fi

echo "Installing plugin to $pluginPath ...";
if [ "$pluginType" = "single" ]; then
    if ! cp -u ocppDissector.lua $pluginPath >/dev/null 2>&1; then
        echo "# ERROR: 'cp' command failed";
        exit;
    fi
else
    cd ./separate
    if ! cp -u ocpp16Dissector.lua $pluginPath  >/dev/null 2>&1; then
        echo "# ERROR: 'cp' command failed";
        cd ..;
        exit;
    fi
    if ! cp -u ocpp20Dissector.lua $pluginPath  >/dev/null 2>&1; then
        echo "# ERROR: 'cp' command failed";
        cd ..;
        exit;
    fi
    if ! cp -u ocpp201Dissector.lua $pluginPath >/dev/null 2>&1; then
        echo "# ERROR: 'cp' command failed";
        cd ..;
        exit;
    fi
    cd ..
fi

echo "";
echo "Finding the path to the lua libraries ...";
luaPath="$(luarocks --lua-version $wsLuaVersion --$installDirType config deploy_lua_dir)";
luaCPath="$(luarocks --lua-version $wsLuaVersion --$installDirType config deploy_lib_dir)";
echo "# Found lua modules path '$luaPath'"
echo "# Found library modules path '$luaCPath'"

echo "";
echo "Installing the necessary lua libraries with luarocks ...";
echo "# Installing 'net-url' by executing 'luarocks --lua-version $wsLuaVersion --$installDirType install net-url 1.1-1' ..."
if ! luarocks --lua-version $wsLuaVersion --$installDirType install net-url 1.1-1 >/dev/null 2>&1; then
    echo "# ERROR: luarocks command to install 'net-url' version 1.1-1 failed";
    echo "# Please try to rerun the prompted command to get more detailed information about the error";
    exit;
fi

echo "# Installing 'lua-cjson' by executing 'luarocks --lua-version $wsLuaVersion --$installDirType install lua-cjson 2.1.0.10-1' ..."
if ! luarocks --lua-version $wsLuaVersion --$installDirType install lua-cjson 2.1.0.10-1 >/dev/null 2>&1; then
    echo "# ERROR: luarocks command to install 'lua-cjson' version 2.1.0.10-1 failed";
    echo "# Please try to rerun the prompted command to get more detailed information about the error";
    exit;
fi

# a little hacky workaround is necessary here... if one would install the jsonschema package
# by using luarocks with the command 'luarocks --lua-version %wsLuaVersion% install jsonschema'
# then the package 'lrexlib-pcre' will be installed as a dependency of 'jsonschema'. As 'lrexlib-pcre'
# brings another dependency to 'libpcre' with it, this command will fail if the library is not preinstalled.
# As Wireshark is shipped with its own lua interpreter, which also contains the libpcre library, it is
# therefore enough for us to just get the lua source code of the 'jsonschema' repository and store it
# in the lua library folder where we already stored our own 'ocpputil.lua' file.
echo "# Downloading the 'jsonschema' v.0.9.9 release ...";
if ! wget https://github.com/api7/jsonschema/archive/refs/tags/v0.9.9.tar.gz --output-document=jsonschema-0.9.9.tar.gz >/dev/null 2>&1; then
    echo "# ERROR: 'Download' command failed";
    exit;
fi

if [ -e jsonschema-0.9.9 ] && [ -d jsonschema-0.9.9 ]; then
    echo "# Clean up artifact from previous run ...";
    rm -rf jsonschema-0.9.9 >/dev/null 2>&1;
fi

echo "# Unzipping the 'jsonschema' source ...";
if ! tar -xf jsonschema-0.9.9.tar.gz >/dev/null 2>&1; then
    echo "# ERROR: 'tar' command failed";
    exit 1;
fi
echo "# Removing zip archive ...";
rm -f jsonschema-0.9.9.tar.gz >/dev/null 2>&1 || echo "# WARNING: 'rm' command failed";
echo "# Installing module 'jsonschema.lua' to local lua libraries ...";
if ! cp -u jsonschema-0.9.9/lib/jsonschema.lua $luaPath >/dev/null 2>&1; then
    echo "# ERROR: 'cp' command failed";
    exit;
fi

if [ ! -e $luaPath/jsonschema/ ] || [ ! -d $luaPath/jsonschema/ ]; then
    echo "# Creating directory '$luaPath/jsonschema/' ..."
    if ! mkdir $luaPath/jsonschema/; then
        echo "# ERROR: 'mkdir' command failed";
        exit;
    fi
fi

echo "# Installing module 'jsonschema/store.lua' to local lua libraries ...";
if ! cp -u jsonschema-0.9.9/lib/jsonschema/store.lua $luaPath/jsonschema/ >/dev/null 2>&1; then
    echo "# ERROR: 'cp' command failed";
    exit;
fi
echo "# Clean up unzipped folder structure ...";
rm -rf jsonschema-0.9.9 >/dev/null 2>&1 || echo "# WARNING: 'rm' command failed";

echo "";
echo "Installing utility module 'ocpputil.lua' to local lua libraries ...";
if ! cp -u ocpputil.lua $luaPath >/dev/null 2>&1; then
    echo "# ERROR: 'cp' command failed";
    exit;
fi

if [ $installDirType = "local" ]; then
    echo "Adding paths to the LUA_PATH variable ...";
    statusLrPath="$(luarocks --lua-version $wsLuaVersion --$installDirType path --lr-path)";
    if [ "$statusLrPath" = "$LUA_PATH" ]; then
        echo "# Variable LUA_PATH is already up to date";
    else
        echo "# Storing new value of LUA_PATH in ~/.profile ...";
        lrPathCurrent="$(grep LUA_PATH= ~/.profile)";
        if [ "$lrPathCurrent" = "" ]; then
            echo "" >> ~/.profile;
            echo "# LUA_PATH variable added by the 'installLinux.sh' script of the OCPP dissector for Wireshark" >> ~/.profile;
            echo "# DO NOT MODIFY THE LINE BELOW UNLESS YOU KNOW WHAT YOU'RE DOING " >> ~/.profile;
            echo "export LUA_PATH='${statusLrPath}'" >> ~/.profile
        else
            sed -i '/^${lrPathCurrent}$/c\${statusLrPath}' ~/.profile
        fi
    fi
    
    echo "Adding paths to the LUA_CPATH variable ...";
    statusLrCPath="$(luarocks --lua-version $wsLuaVersion --$installDirType path --lr-cpath)";
    if [ "$statusLrCPath" = "$LUA_CPATH" ]; then
        echo "# Variable LUA_CPATH is already up to date";
    else
        echo "# Storing new value of LUA_CPATH in ~/.profile ...";
        lrCPathCurrent="$(grep LUA_CPATH= ~/.profile)";
        if [ "$lrCPathCurrent" = "" ]; then
            echo "" >> ~/.profile;
            echo "# LUA_CPATH variable added by the 'installLinux.sh' script of the OCPP dissector for Wireshark" >> ~/.profile;
            echo "# DO NOT MODIFY THE LINE BELOW UNLESS YOU KNOW WHAT YOU'RE DOING " >> ~/.profile;
            echo "export LUA_CPATH='${statusLrCPath}'" >> ~/.profile
        else
            sed -i '/^${lrCPathCurrent}$/c\${statusLrCPath}' ~/.profile
        fi
    fi
fi

# TODO: if the plugin is installed with the 'global' argument: WHERE TO WRITE THE LUAROCKS PATH THEN?

echo "";
echo "Checking for Python installation ...";
if ! command -v pip >/dev/null 2>&1; then
    echo "# Python is available";
    echo "NOTE: to use the dissector, run 'pip install ocpp', note down the paths where the json schemas are installed, and set them in the dissector's preferences.";
else
    echo "# Python is not available";
    echo "WARNING: no Python installation found, make sure to get the OCPP json schemas elsewhere and set the path to them in the dissector's preferences!";
fi

echo "";
exit 0;

