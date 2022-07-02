@echo off

set "CURRENT_DIRECTORY=%~dp0"
if NOT "%CURRENT_DIRECTORY:~-33%" == "\ravencoin-stratum-proxy\windows\" (
    echo Error: Please run this batch file as-is from its original location in the ravencoin-stratum-proxy folder
    exit /B
)

echo checking for python...

if exist "%CURRENT_DIRECTORY%python_files\python.exe" (

    echo python.exe exists... assuming all dependancies are installed....
    goto SKIP_DOWNLOADS
)

echo downloading python...
powershell -Command "Invoke-WebRequest https://www.python.org/ftp/python/3.9.13/python-3.9.13-embed-win32.zip -OutFile %CURRENT_DIRECTORY%python.zip"

FOR /F "tokens=* USEBACKQ" %%F IN (`powershell -Command "Get-FileHash %CURRENT_DIRECTORY%python.zip -Algorithm SHA256 | Select-Object -ExpandProperty Hash"`) DO (
    set HASH=%%F
)
echo downloaded python hash: %HASH%
if NOT "%HASH%" == "F8ED5E019D7BC6DBA1D7DFA5D59052B5241C37E8EAA5293133C898AC7ACEDB98" (
    echo warning: hash mismatch! exiting and removing the file.
    del "%CURRENT_DIRECTORY%python.zip"
    pause
    exit /B
)
echo downloading pip installer
powershell -Command "Invoke-WebRequest https://bootstrap.pypa.io/get-pip.py -OutFile %CURRENT_DIRECTORY%get-pip.py"

echo extracting python...
powershell -Command "Expand-Archive %CURRENT_DIRECTORY%python.zip -DestinationPath %CURRENT_DIRECTORY%python_files"

echo installing pip...
%CURRENT_DIRECTORY%python_files\python.exe %CURRENT_DIRECTORY%get-pip.py

echo removing archives...
del "%CURRENT_DIRECTORY%python.zip"
del "%CURRENT_DIRECTORY%get-pip.py"

echo patching python...
echo Lib\site-packages>> "%CURRENT_DIRECTORY%python_files\python39._pth"

echo installing pre-built module...
%CURRENT_DIRECTORY%python_files\python.exe -m pip install %CURRENT_DIRECTORY%python_modules\pysha3-1.0.3.dev1-cp39-cp39-win32.whl

echo install pip modules...
%CURRENT_DIRECTORY%python_files\python.exe -m pip install -r %CURRENT_DIRECTORY%requirements.txt

:SKIP_DOWNLOADS

set "FILE_LOCATION=%CURRENT_DIRECTORY%..\run.bat"

if exist "%FILE_LOCATION%" (
    echo ==========================================================
    set /p "DO_RESET=run.bat already exists. Reset? y/n (Default n): "
    if "%DO_RESET%" == "" (
        set "DO_RESET=n"
    )
    echo %DO_RESET%
    if "%DO_RESET%" == "n" (
        exit /B
    )
    echo regenerating run.bat ...
)

echo ==========================================================
:CHECK_MAINNET
set "IS_MAINNET=y"
set /p "IS_MAINNET_INPUT=Is this for mainnet or testnet? (Default mainnet): "
if "%IS_MAINNET_INPUT%" == "" (
    set "IS_MAINNET_INPUT=mainnet"
)

if "%IS_MAINNET_INPUT%" == "mainnet" (
    set "IS_MAINNET=y"
    set "DEFAULT_PORT=8766"
    goto POST_CHECK_MAINNET
)

if "%IS_MAINNET_INPUT%" == "testnet" (
    set "IS_MAINNET="
    set "DEFAULT_PORT=18766"
    goto POST_CHECK_MAINNET
)

echo Unknown input: %IS_MAINNET_INPUT% options are: (mainnet/testnet)
goto CHECK_MAINNET

:POST_CHECK_MAINNET
echo ==========================================================

set /p "NODE_IP=What is the ip of your node? (Default localhost): "
if "%NODE_IP%" == "" (
    set "NODE_IP=localhost"
)

echo ==========================================================
:POST_CHECK_IP

set /p "NODE_PORT=What is the port of your node? (Default %DEFAULT_PORT%): "
if "%NODE_PORT%" == "" (
    set "NODE_PORT=%DEFAULT_PORT%"
)

set /a "TEST_PORT=%NODE_PORT%+0"
if %TEST_PORT% LEQ 1024 (
    echo Not a valid port: %NODE_PORT%
    goto POST_CHECK_IP
)

echo ==========================================================
:POST_CHECK_PORT

set /p "RPC_USERNAME=What is your RPC username?: "
if "%RPC_USERNAME%" == "" (
    echo You must input a username
    goto POST_CHECK_PORT
)

echo ==========================================================
:POST_CHECK_USERNAME

set /p "RPC_PASSWORD=What is your RPC password?: "
if "%RPC_PASSWORD%" == "" (
    echo You must input a password
    goto POST_CHECK_USERNAME
)

echo ==========================================================
:POST_CHECK_PASSWORD

set /p "ALLOW_EXTERNAL_CONNECTIONS_INPUT=Allow miners running externally from this computer to connect to this converter? y/n (Default n): "
if "%ALLOW_EXTERNAL_CONNECTIONS_INPUT%" == "" (
    set "ALLOW_EXTERNAL_CONNECTIONS_INPUT=n"
) 

if "%ALLOW_EXTERNAL_CONNECTIONS_INPUT%" == "y" (
    set "ALLOW_EXTERNAL_CONNECTIONS=y"
    goto POST_CHECK_EXTERNAL
)

if "%ALLOW_EXTERNAL_CONNECTIONS_INPUT%" == "n" (
    set "ALLOW_EXTERNAL_CONNECTIONS="
    goto POST_CHECK_EXTERNAL
)

echo Invalid option: %ALLOW_EXTERNAL_CONNECTIONS_INPUT%, please enter "y" or "n"
goto POST_CHECK_PASSWORD

:POST_CHECK_EXTERNAL
echo ==========================================================
:PRE_CHECK_PORT

set /p "CONVERTER_PORT=What port would you like to run the converter on?: "
if "%CONVERTER_PORT%" == "" (
    echo You must input a port.
    goto PRE_CHECK_PORT
)

set /a "TEST_PORT=%CONVERTER_PORT%+0"
if %TEST_PORT% LEQ 1024 (
    echo Not a valid port: %CONVERTER_PORT%
    goto PRE_CHECK_PORT
)

set "EXTERNAL_STRING_VALUE=true"
if NOT defined ALLOW_EXTERNAL_CONNECTIONS set "EXTERNAL_STRING_VALUE=false"

set "TESTNET_STRING_VALUE=false"
if NOT defined IS_MAINNET set "TESTNET_STRING_VALUE=true"

echo generating bat file...
echo echo Connect to your stratum converter at stratum+tcp://localhost:%CONVERTER_PORT%>%FILE_LOCATION%
echo %CURRENT_DIRECTORY%python_files\python.exe %CURRENT_DIRECTORY%..\stratum-converter.py %CONVERTER_PORT% %NODE_IP% %RPC_USERNAME% %RPC_PASSWORD% %NODE_PORT% %EXTERNAL_STRING_VALUE% %TESTNET_STRING_VALUE%>>%FILE_LOCATION%
echo done... runnable bat can be found at %FILE_LOCATION%
pause