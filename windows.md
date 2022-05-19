`
error: Microsoft Visual C++ 14.0 or greater is required. Get it with "Microsoft C++ Build Tools": https://visualstudio.microsoft.com/visual-cpp-build-tools/
`

Cant compile sha3 needs c++ build tools: https://visualstudio.microsoft.com/visual-cpp-build-tools/

download the file and manually addind the dependecies or using the following command did the trick:
```
vs_buildtools.exe --norestart --passive --downloadThenInstall --includeRecommended --add Microsoft.VisualStudio.Workload.NativeDesktop --add Microsoft.VisualStudio.Workload.VCTools --add Microsoft.VisualStudio.Workload.MSBuildTools
```

pip install -r requirements.txt
