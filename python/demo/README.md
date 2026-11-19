# Local Streamlit demo

This interface uses the C++ `RSetup` and `RKeygen` implementations with
`SystemRandomSource` to generate demo bidder keys. The parameters are deliberately
small and insecure. Ring formation and membership are public-key lookup only;
they are not cryptographic RSign/RVerify.

The signature, Dilithium, and WCM stages remain unavailable because the demo does
not configure the providers required for a real signing and verification flow.

## Run

### macOS

Install the C++ dependencies and Apple command-line tools:

```sh
brew install cmake gmp ntl
```

Then, from the repository root:

```sh
python3 -m pip install -r python/demo/requirements.txt
streamlit run python/demo/app.py
```

### Windows (PowerShell)

Install CMake, a C++17 compiler (for example, Visual Studio Build Tools with
the C++ workload), and NTL/GMP libraries built for that compiler. If the
libraries are under a nonstandard prefix, point CMake to it in the same
PowerShell session:

```powershell
$env:CMAKE_PREFIX_PATH = "C:\path\to\ntl-gmp-prefix"
py -m pip install -r python/demo/requirements.txt
py -m streamlit run python/demo/app.py
```

Replace the example prefix with the directory containing the dependency
`include` and `lib` directories.

The app builds its small C++ key-generation wrapper in `build/python_demo` when
the first key-generation request is made. CMake, a C++17 compiler, NTL, and GMP
must be installed and discoverable by CMake.
