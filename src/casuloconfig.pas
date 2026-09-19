unit CasuloConfig;

{$mode objfpc}{$H+}

interface

uses SysUtils;

function ProjectRoot: string;
function ProjectPath(const APath: string): string;

const


   GITHUB_URL = 'https://github.com/leonardomcl/Casulo';

  { Stub Linux }

  RustTemplatePath =
    'stub_linux/src/main.rs.in';

  RustGeneratedPath =
    'stub_linux/src/main.rs';

  
  RustLinuxVmTemplatePath =
    'stub_linux/src/exec_vm.rs.in';

  RustLinuxVmGeneratedPath =
    'stub_linux/src/exec_vm.rs';

  
  RustManifestTemplatePath =
    'stub_linux/Cargo.toml.in';

  RustManifestPath =
    'stub_linux/Cargo.toml';

  
  RUST_LINUX_TARGET_GNU =
    'x86_64-unknown-linux-gnu';

  RUST_LINUX_TARGET_MUSL =
    'x86_64-unknown-linux-musl';

  { A pipeline acrescenta o target Cargo selecionado a este caminho. }
  RustTargetRootPath =
    'stub_linux/target';

  RustBinaryName =
    'stub';


  { Stub Windows }

  { Target usado pelo cargo-xwin. }
  RUST_WIN_TARGET =
    'x86_64-pc-windows-msvc';

  
  RustWinTemplatePath =
    'stub_windows/src/main.rs.in';

  RustWinGeneratedPath =
    'stub_windows/src/main.rs';

  
  RustWinLoaderPath =
    'stub_windows/src/loader.rs';

  RustWinPagingPath =
    'stub_windows/src/paging.rs';

  RustWinExecSignalPath =
    'stub_windows/src/exec_signal.rs';

  
  RustWinExecVmTemplatePath =
    'stub_windows/src/exec_vm.rs.in';

  RustWinExecVmGeneratedPath =
    'stub_windows/src/exec_vm.rs';

  
  RustWinExecVmPath =
    'stub_windows/src/exec_vm.rs';

  
  RustWinManifestTemplatePath =
    'stub_windows/Cargo.toml.in';

  RustWinManifestPath =
    'stub_windows/Cargo.toml';

  
  RustWinBuildTemplatePath =
    'stub_windows/build.rs.in';

  RustWinBuildGeneratedPath =
    'stub_windows/build.rs';

  
  RustWinBinaryPath =
    'stub_windows/target/x86_64-pc-windows-msvc/release/stub.exe';


  { Recursos do Stub Windows }

  RustWinRcDataDir =
    'stub_windows/assets/rcdata';

  RustWinRcScriptPath =
    'stub_windows/assets/casulo_resources.rc';

  RCDATA_ID_MIN: Word = 16;
  RCDATA_ID_MAX: Word = 32768;


  { ImageBase }

  { Distância mínima entre bases: 512 MiB. }
  IMAGEBASE_MIN_GAP: QWord =
    $0000000020000000;


  { Execução Windows }

  WINDOWS_EXEC_IN_MEMORY = True;

  
  WINDOWS_DEMAND_PAGING = True;

  SELF_TEXT_HASH_BINDING = True;


  { Compressão }

  COMPACT_ZSTD = 0;
  COMPACT_BROTLI = 1;

  
  ZSTD_ARGS_LEVEL = '-22';

  MAX_INPUT_SIZE: Int64 =
    512 * 1024 * 1024;


var

  RUST_LINUX_TARGET: string =
    RUST_LINUX_TARGET_GNU;

  { Mantém compressor, decompressor e dependência Cargo sincronizados. }
  COMPACT_ALGORITHM: Integer =
    COMPACT_BROTLI;

  STRIP_STUB: Boolean =
    False;


  { ImageBase }

  RANDOM_IMAGEBASE: Boolean =
    False;

  DEFAULT_STUB_IMAGEBASE: QWord =
    $0000009332140000;

  RCDATA_FRAGMENT_SIZE: Integer =
    128 * 1024;


  { Opções do compilador Rust }

    LTO_CONFIG: Boolean = true;
    OPT_LEVEL_CONFIG: String = '"z"';


implementation

function ProjectRoot: string;
var
  ExeDir: string;
begin
  { O executável é gerado em <projeto>/bin. }
  ExeDir := ExtractFilePath(ParamStr(0));
  if ExeDir = '' then
    ExeDir := GetCurrentDir;

  Result := ExpandFileName(
    IncludeTrailingPathDelimiter(ExeDir) + '..'
  );
  Result := IncludeTrailingPathDelimiter(Result);
end;

function ProjectPath(const APath: string): string;
begin
  Result :=
    ExpandFileName(
      ProjectRoot +
      StringReplace(
        APath,
        '/',
        DirectorySeparator,
        [rfReplaceAll]
      )
    );
end;


end.

