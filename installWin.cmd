@echo off
REM Batch script to add the plugin to a given wireshark installation
REM
REM Prerequisites:
REM     Wireshark installation (added to PATH)
REM     LuaRocks (added to PATH) (to install required lua packages)
REM     Lua (added to PATH, or registered with luarocks by calling 'luarocks --lua-version X.Y variables.LUA <path/to/luaXY.exe>' )
REM             note that Wireshark version below 4.3.0 requires Lua5.2 while later versions require Lua5.4
REM Optional:
REM     Python (to install the ocpp json schemas)
REM
REM SYNOPSIS
REM     .\install.bat (single|multiple) (global|local) [verbose]
REM            single: adds the ocppDissector.lua file to the existing Wireshark installation
REM            multiple: adds the separate files ocpp16Dissector.lua, ocpp20Dissector.lua separate/ocpp201Dissector.lua to the existing Wireshark installation
REM            global: adds the plugin to the global plugin folder
REM            local: adds the plugin to the user specific plugin folder
REM note that this batch file expects two arguments: either "single" or "multiple" as first argument and either "global" or "local" as second argument
REM
REM for developers not familiar with batch programming:
REM     https://tutorialreference.com/batch-scripting/batch-script-introduction
REM for information on how the batch line parser works (oder of expansion):
REM     https://stackoverflow.com/questions/4094699/how-does-the-windows-command-interpreter-cmd-exe-parse-scripts/4095133#4095133

setlocal enabledelayedexpansion
echo Installing the CheckOCPP dissector to wireshark ...

if NOT "%1"=="single" (
    if NOT "%1"=="multiple" (
        echo ERROR: invalid first argument %1. Expected 'single' or 'multiple'
        exit /B 1
    )
)
set pluginType=%1

if NOT "%2"=="global" (
    if NOT "%2"=="local" (
        echo ERROR: invalid second argument %2. Expected 'global' or 'local'
        exit /B 1
    )
)
set installDirType=%2

if "%3"=="verbose" (
    echo Activating verbose output ...
    echo on
)

echo.
echo Checking Wireshark installation ...
call wireshark -v > nul 2>&1 || (echo # ERROR: No existing wireshark installation found & exit /B 1)
echo # Found existing Wireshark installation

echo.
echo Checking version of Wireshark ...
REM TODO why the hell is there an empty line printed between the above echo and the echo after the for loop??
FOR /F "tokens=* delims=" %%x in ('wireshark -v') DO call :extractWsVersion %%x
REM set lua version as stated in https://www.wireshark.org/docs/wsdg_html_chunked/wsluarm.html
call :isVersionLT %wiresharkVersion% 4.3.0 isLowerVersion
if %isLowerVersion%==true (
    set wsLuaVersion=5.2
) else (
    set wsLuaVersion=5.4
)
echo # Found Wireshark version %wiresharkVersion%, which requires Lua %wsLuaVersion%

echo Checking path to Wireshark ...
FOR /F "tokens=* delims=" %%x in ('where wireshark') DO set pathToWireshark=%%~dpx

if "!pathToWireshark:~0,26!"=="C:\Program Files\Wireshark" (
    set isGlobalInstallation=true
    echo # Found global installation at "!pathToWireshark!"
) else (
    set isGlobalInstallation=false
    echo # Found portable app at "!pathToWireshark!"
)

if isGlobalInstallation==true (
    if "%installDirType%"=="global" (
        set pluginPath=%pathToWireshark%plugins
    ) else (
        set pluginPath=%APPDATA%\Wireshark\plugins
    )
) else (
    if "%installDirType%"=="global" (
        set pluginPath=%pathToWireshark%plugins
    ) else (
        set pluginPath=%pathToWireshark%..\..\Data\plugins
    )
)

echo.
echo Checking for LuaRocks installation ...
call luarocks > nul 2>&1 || (echo # ERROR: LuaRocks is not available. Please install the lua libraries 'cjson', 'jsonschema' and 'net.url' manually & exit /B 1)
echo # LuaRocks is available

echo.
if NOT exist %pluginPath% (
    echo Creating directory '%pluginPath%' ...
    call mkdir %pluginPath%
    if NOT %ERRORLEVEL%==0 (
        echo # ERROR: 'mkdir' command failed with return code %ERRORLEVEL%
        exit /B 1
    )
)

echo Installing plugin to %pluginPath% ...
if "%pluginType%"=="single" (
    goto :installPlugin_single
) else (
    goto :installPlugin_multiple
)

:installPlugin_single
    call COPY /Y /V ocppDissector.lua %pluginPath% > nul 2>&1 || (echo # ERROR: 'COPY' command failed with return code %ERRORLEVEL% & exit /B 1)
    goto :installPlugin_finished
:installPlugin_multiple
    cd ./separate
    call COPY /Y /V ocpp16Dissector.lua %pluginPath%  > nul 2>&1 || (echo # ERROR: 'COPY' command failed with return code %ERRORLEVEL% & exit /B 1)
    call COPY /Y /V ocpp20Dissector.lua %pluginPath%  > nul 2>&1 || (echo # ERROR: 'COPY' command failed with return code %ERRORLEVEL% & exit /B 1)
    call COPY /Y /V ocpp201Dissector.lua %pluginPath% > nul 2>&1 || (echo # ERROR: 'COPY' command failed with return code %ERRORLEVEL% & exit /B 1)
    cd ..
:installPlugin_finished

echo.
echo Finding the path to the lua libraries ...
FOR /F "tokens=* delims=" %%x in ('luarocks --lua-version %wsLuaVersion% config home_tree') DO set luaPathPrefix=%%x
FOR /F "tokens=* delims=" %%x in ('luarocks --lua-version %wsLuaVersion% config lua_modules_path') DO set luaPathSuffix=%%x
FOR /F "tokens=* delims=" %%x in ('luarocks --lua-version %wsLuaVersion% config lib_modules_path') DO set luaCPathSuffix=%%x
set luaPath=%luaPathPrefix%\%luaPathSuffix%
set luaCPath=%luaPathPrefix%\%luaCPathSuffix%
echo # Found lua modules path '%luaPath%'
echo # Found library modules path '%luaCPath%'

echo.
echo Installing the necessary lua libraries with luarocks ...

echo # Installing 'net-url' by executing 'luarocks --lua-version %wsLuaVersion% install net-url 1.1-1' ...
call luarocks --lua-version %wsLuaVersion% install net-url 1.1-1 > nul 2>&1 || (  echo # ERROR: luarocks command to install 'net-url' version 1.1-1 failed with return code %ERRORLEVEL% ^
                                                                                & echo # Please try to rerun the prompted command to get more detailed information about the error ^
                                                                                & exit /B 1)

echo # Installing 'lua-cjson' by executing 'luarocks --lua-version %wsLuaVersion% install lua-cjson 2.1.0.10-1' ...
call luarocks --lua-version %wsLuaVersion% install lua-cjson 2.1.0.10-1 > nul 2>&1 || (  echo # ERROR: luarocks command to install 'lua-cjson' version 2.1.0.10-1 failed with return code %ERRORLEVEL% ^
                                                                                       & echo # Please try to rerun the prompted command to get more detailed information about the error ^
                                                                                       & exit /B 1)

REM a little hacky workaround is necessary here... if one would install the jsonschema package
REM by using luarocks with the command 'luarocks --lua-version %wsLuaVersion% install jsonschema'
REM then the package 'lrexlib-pcre' will be installed as a dependency of 'jsonschema'. As 'lrexlib-pcre'
REM brings another dependency to 'libpcre' with it, this command will fail if the library is not preinstalled.
REM As Wireshark is shipped with its own lua interpreter, which also contains the libpcre library, it is
REM therefore enough for us to just get the lua source code of the 'jsonschema' repository and store it
REM in the lua library folder where we already stored our own 'ocpputil.lua' file.
echo # Downloading the 'jsonschema' v.0.9.9 release ...
call powershell -Command "(New-Object System.Net.WebClient).DownloadFile('https://github.com/api7/jsonschema/archive/refs/tags/v0.9.9.zip', 'jsonschema-0.9.9.zip')" ^
             > nul 2>&1 || (echo # ERROR: 'Download' command failed with return code %ERRORLEVEL% & exit /B 1)

if exist jsonschema-0.9.9 (
    echo # Clean up artifact from previous run ...
    call rmdir /s /q jsonschema-0.9.9 > nul 2>&1
)
echo # Unzipping the 'jsonschema' source ...
call unzip jsonschema-0.9.9.zip > nul 2>&1 || (echo # ERROR: 'unzip' command failed with return code %ERRORLEVEL% & exit /B 1)
echo # Removing zip archive ...
call del /f /q jsonschema-0.9.9.zip > nul 2>&1 || (echo # WARNING: 'del' command failed)
echo # Installing module 'jsonschema.lua' to local lua libraries ...
call COPY /Y /V jsonschema-0.9.9\lib\jsonschema.lua %luaPath% > nul 2>&1 || (echo # ERROR: 'COPY' command failed with return code %ERRORLEVEL% & exit /B 1)
if NOT exist %luaPath%\jsonschema\ (
    echo # Creating directory '%luaPath%\jsonschema\' ...
    call mkdir %luaPath%\jsonschema\
    if NOT %ERRORLEVEL%==0 (
        echo # ERROR: 'mkdir' command failed with return code %ERRORLEVEL%
        exit /B 1
    )
)
echo # Installing module 'jsonschema\store.lua' to local lua libraries ...
call COPY /Y /V jsonschema-0.9.9\lib\jsonschema\store.lua %luaPath%\jsonschema\ > nul 2>&1 || (echo # ERROR: 'COPY' command failed with return code %ERRORLEVEL% & exit /B 1)
echo # Clean up unzipped folder structure ...
call rmdir /s /q jsonschema-0.9.9 > nul 2>&1 || (echo # WARNING: 'rmdir' command failed)

REM if the Wireshark installation is in C:\Program Files and the user wishes to install the plugin globally, it might not be possible due to missing permissions

echo.
echo Installing utility module 'ocpputil.lua' to local lua libraries ...
call COPY /Y /V ocpputil.lua %luaPath% > nul 2>&1 || (echo # ERROR: 'COPY' command failed with return code %ERRORLEVEL% & exit /B 1)

echo.
if defined LUA_PATH_%wsLuaVersion:~0,1%_%wsLuaVersion:~2,1% (
    echo Reading content of the LUA_PATH_%wsLuaVersion:~0,1%_%wsLuaVersion:~2,1% environment variable ...
    set localEnvLuaPath=!LUA_PATH_%wsLuaVersion:~0,1%_%wsLuaVersion:~2,1%!
) else (
    echo Creating LUA_PATH_%wsLuaVersion:~0,1%_%wsLuaVersion:~2,1% environment variable ...
    set localEnvLuaPath=
)

echo Adding paths to the LUA_PATH_%wsLuaVersion:~0,1%_%wsLuaVersion:~2,1% variable ...
set luaBasicPath=%luaPath%\?.lua
call :checkContains %luaBasicPath% %localEnvLuaPath% rvCheckContains
if %rvCheckContains%==false (
    echo # Adding missing path '%luaBasicPath%' ...
    set localEnvLuaPath=%localEnvLuaPath%%luaBasicPath%;
) else (
    echo # Path '%luaBasicPath%' already exists
)

set luaCjsonPath=%luaPath%\cjson\?.lua
call :checkContains %luaCjsonPath% %localEnvLuaPath% rvCheckContains
if %rvCheckContains%==false (
    echo # Adding missing path '%luaCjsonPath%' ...
    set localEnvLuaPath=%localEnvLuaPath%%luaCjsonPath%;
) else (
    echo # Path '%luaCjsonPath%' already exists
)

set luaJsonschemaPath=%luaPath%\jsonschema\?.lua
call :checkContains %luaJsonschemaPath% %localEnvLuaPath% rvCheckContains
if %rvCheckContains%==false (
    echo # Adding missing path '%luaJsonschemaPath%' ...
    set localEnvLuaPath=%localEnvLuaPath%%luaJsonschemaPath%;
) else (
    echo # Path '%luaJsonschemaPath%' already exists
)

set luaNetPath=%luaPath%\net\?.lua
call :checkContains %luaNetPath% %localEnvLuaPath% rvCheckContains
if %rvCheckContains%==false (
    echo # Adding missing path '%luaNetPath%' ...
    set localEnvLuaPath=%localEnvLuaPath%%luaNetPath%;
) else (
    echo # Path '%luaNetPath%' already exists
)

if "%localEnvLuaPath%"=="!LUA_PATH_%wsLuaVersion:~0,1%_%wsLuaVersion:~2,1%!" (
    echo # Variable LUA_PATH_%wsLuaVersion:~0,1%_%wsLuaVersion:~2,1% is already up to date
) else (
    set envPathChanged=true
    echo # Storing new value of LUA_PATH_%wsLuaVersion:~0,1%_%wsLuaVersion:~2,1% in environment variables ...
    call REG ADD "HKCU\Environment" /v "LUA_PATH_%wsLuaVersion:~0,1%_%wsLuaVersion:~2,1%" /t REG_SZ /d "%localEnvLuaPath%" /f > nul 2>&1
    if NOT %ERRORLEVEL%==0 (
        echo # ERROR: Unable to set or change environment variable. Command failed with return code %ERRORLEVEL%
        exit /B 1
    )
)

echo.
if defined LUA_CPATH_%wsLuaVersion:~0,1%_%wsLuaVersion:~2,1% (
    echo Reading content of the LUA_CPATH_%wsLuaVersion:~0,1%_%wsLuaVersion:~2,1% environment variable ...
    set localEnvLuaCPath=!LUA_CPATH_%wsLuaVersion:~0,1%_%wsLuaVersion:~2,1%!
) else (
    echo Creating LUA_CPATH_%wsLuaVersion:~0,1%_%wsLuaVersion:~2,1% environment variable ...
    set localEnvLuaCPath=
)

echo Adding paths to the LUA_CPATH_%wsLuaVersion:~0,1%_%wsLuaVersion:~2,1% variable ...
set luaBasicCPath=%luaCPath%\?.dll
call :checkContains %luaBasicCPath% %localEnvLuaCPath% rvCheckContains
if %rvCheckContains%==false (
    echo # Adding missing path '%luaBasicCPath%' ...
    set localEnvLuaCPath=%localEnvLuaCPath%%luaBasicCPath%;
) else (
    echo # Path '%luaBasicCPath%' already exists
)

if "%localEnvLuaCPath%"=="!LUA_CPATH_%wsLuaVersion:~0,1%_%wsLuaVersion:~2,1%!" (
    echo # Variable LUA_CPATH_%wsLuaVersion:~0,1%_%wsLuaVersion:~2,1% is already up to date
) else (
    set envPathChanged=true
    echo # Storing new value of LUA_CPATH_%wsLuaVersion:~0,1%_%wsLuaVersion:~2,1% in environment variables.
    call REG ADD "HKCU\Environment" /v "LUA_CPATH_%wsLuaVersion:~0,1%_%wsLuaVersion:~2,1%" /t REG_SZ /d "%localEnvLuaCPath%" /f > nul 2>&1
    if NOT %ERRORLEVEL%==0 (
        echo # ERROR: Unable to set or change environment variable. Command failed with return code %ERRORLEVEL%
        exit /B 1
    )
)

echo.
echo Checking for Python installation ...
call pip > nul 2>&1 && (set hasPythonInstalled=true & echo # Python is available) || (echo # Python is not available)

echo.
if defined hasPythonInstalled (
    echo NOTE: to use the dissector, run 'pip install ocpp', note down the paths where the json schemas are installed, and set them in the dissector's preferences.
) else (
    echo WARNING: no Python installation found, make sure to get the OCPP json schemas elsewhere and set the path to them in the dissector's preferences!
)

if defined envPathChanged (
    echo NOTE: The environment variables have been changed. Please restart Wireshark to apply the changes.
)

echo.
endlocal
exit /B 0

REM --- local function definitions --------------------------------------------
REM isVersionLT ver1 ver2 rv
:isVersionLT
    setlocal
    REM find ver1 major
    set ver1=%1
    set ver2=%2
    set rv=false
    call :findSubStrNo ver1 . 0 ver1major
    call :findSubStrNo ver1 . 1 ver1minor
    call :findSubStrNo ver1 . 2 ver1patch
    call :findSubStrNo ver2 . 0 ver2major
    call :findSubStrNo ver2 . 1 ver2minor
    call :findSubStrNo ver2 . 2 ver2patch
    REM 'cast' the version strings to numbers
    set /A ver1major=%ver1major%
    set /A ver1minor=%ver1minor%
    set /A ver1patch=%ver1patch%
    set /A ver2major=%ver2major%
    set /A ver2minor=%ver2minor%
    set /A ver2patch=%ver2patch%
    if %ver1major% LSS %ver2major% (
        set rv=true
    )
    if %ver1major% EQU %ver2major% (
        if %ver1minor% LSS %ver2minor% (
            set rv=true
        )
        if %ver1minor% EQU %ver2minor% (
            if %ver1patch% LSS %ver2patch% (
                set rv=true
            )
        )
    )

    (endlocal & set %3=%rv%)
exit /B 0

REM extractWsVersion str
:extractWsVersion
    REM only to be called until wiresharkVersion is defined
    if defined wiresharkVersion (
        exit /B 0
    )
    setlocal
    set inputBeg=%1
    if "%inputBeg%"=="Wireshark" (
        set rv="%2"
    )
    if defined rv (
        REM a little hack to get the value of the local variable rv in the global variable wiresharkVersion
        for /F "delims=" %%V in (!rv!) DO (    
            endlocal
            set "wiresharkVersion=%%V"
        )
    ) else (
        endlocal
    )
exit /B 0

REM checkContains string1 stringList2check ... rv
:checkContains
    setlocal
    set str1=%1
    set rv=false
:checkContains_loop
    set str2=%2
    if "!str2:~1,1!"==":" (
        shift
        if %str1%==%str2% (
            set rv=true
        )
    ) else (
        goto :checkContains_exit
    )
    goto :checkContains_loop
:checkContains_exit
    (endlocal & set %2=%rv%)
exit /B 0

REM returns the n-th substring delimited by the delim character. Fails if the n-th substring does not exist
REM findSubStrNo string delim no rvSubstr
:findSubStrNo
    setlocal
    set /A startChar=0
    set /A endChar=0
    set /A currentChar=0
    set /A activeSubstring=0
    set str=%1
    set delim=%2
    set /A substringStopIndex=%3
    call :strLen str inputLen 
:findSubStrNo_findStartIndex
    if %activeSubstring% NEQ %substringStopIndex% (
        if %currentChar% GTR %inputLen% (
            goto :findSubStrNo_exit_not_found
        )
        if "!%1:~%currentChar%,1!"=="%delim%" (
            set /A activeSubstring+=1
        )
        set /A currentChar+=1
        goto :findSubStrNo_findStartIndex
    )
    set /A startChar=%currentChar%
    set /A substringStopIndex+=1
:findSubStrNo_findEndIndex
    if %activeSubstring% NEQ %substringStopIndex% (
        if %currentChar% GTR %inputLen% (
            REM in C I would have written a simple break; statement here. However, it also works that way
            set /A activeSubstring+=1
        )
        if "!%1:~%currentChar%,1!"=="%delim%" (
            set /A activeSubstring+=1
        )
        set /A currentChar+=1
        goto :findSubStrNo_findEndIndex
    )
    set /A subStrLen=%currentChar%
    set /A subStrLen-=%startChar%
    set /A subStrLen-=1
    (endlocal & set %4=!%1:~%startChar%,%subStrLen%!)
exit /B 0
:findSubStrNo_exit_not_found
    endlocal
exit /B 1

:strLen
    setlocal
:strLen_Loop
    if not "!%1:~%len%!"=="" (
        set /A len+=1 & goto :strLen_Loop
    )
    (endlocal & set %2=%len%)
exit /B 0
REM NOTE: 473
