unit CasuloCommon;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, BaseUnix, Process,
  Packer, CasuloConfig, CasuloLinuxVm;

function GetFileSizeByName(const FileName: string): Int64;

function ExecutarProcesso(const Cmd: string; const Args: array of string;
  out Saida: string): Boolean;

function GetLinuxRustDecompressorCode(CompressionAlgorithm: Integer): string;

function PatchLinuxCargoTemplate(const TemplatePath, OutputPath: string;
  CompressionAlgorithm: Integer): Boolean;

function PatchStubTemplate(const TemplatePath: string; const OutputPath: string;
  const Secret: TBytes; const Magics: TQWordArray;
  const FooterMagic: QWord; const FragLabel, MetaLabel: TBytes;
  CompressionAlgorithm: Integer; const VM: TLinuxVmBuild): Boolean;

function CompilarStub(const ManifestPath: string; out Saida: string): Boolean;
function RemoverMetadados(const Arquivo: string; out Erro: string): Boolean;
function CompactarComZstd(const Origem, Destino: string; out Saida: string): Boolean;
function CompactBrotli(const Origem, Destino: string; out Saida: string): Boolean;

function CriarCopiaTemporaria(const Origem: string;
  out ArquivoTemporario: string): Boolean;

procedure CriarArquivoFinal(const ArquivoSaida: string; const Stub: TBytes;
  const PackedRegion: TBytes);
procedure GravarBytesEmArquivo(const Arquivo: string; const Dados: TBytes);

implementation

function GetFileSizeByName(const FileName: string): Int64;
var
  Stream: TFileStream;
begin
  if not FileExists(FileName) then
    Exit(-1);

  Stream := TFileStream.Create(FileName, fmOpenRead or fmShareDenyNone);
  try
    Result := Stream.Size;
  finally
    Stream.Free;
  end;
end;

function ExecutarProcesso(const Cmd: string; const Args: array of string;
  out Saida: string): boolean;
var
  Proc: TProcess;
  Buffer: TStringList;
  I: integer;
begin
  Result := False;
  Saida := '';

  Proc := TProcess.Create(nil);
  Buffer := TStringList.Create;

  try
    Proc.Executable := Cmd;

    for I := Low(Args) to High(Args) do
      Proc.Parameters.Add(Args[I]);

    Proc.Options := [poWaitOnExit, poUsePipes, poStderrToOutPut];

    try
      Proc.Execute;

      Buffer.LoadFromStream(Proc.Output);
      Saida := Buffer.Text;

      Result := Proc.ExitStatus = 0;

    except
      on E: Exception do
      begin
        Saida := E.Message;
        Result := False;
      end;
    end;

  finally
    Buffer.Free;
    Proc.Free;
  end;
end;

{ Detecta TLS estático no PE64. O loader manual só consegue inicializar o
  template da thread atual; payloads com dados TLS ficam no modo convencional. }


{ Gera o descompressor Rust usado pela Stub Linux. }

function GetLinuxRustDecompressorCode(CompressionAlgorithm: Integer): string;
begin
  case CompressionAlgorithm of
    COMPACT_ZSTD:
    begin
      Result :=
        '#[inline]' + LineEnding +
        'fn decompress_payload(input: &[u8], final_size: usize) -> Option<Vec<u8>> {' + LineEnding +
        '    if final_size == 0 || final_size as u64 > MAX_PAYLOAD_SIZE {' + LineEnding +
        '        return None;' + LineEnding +
        '    }' + LineEnding +
        '' + LineEnding +
        '    let mut decoder = ruzstd::decoding::FrameDecoder::new();' + LineEnding +
        '    decoder.set_max_window_size(MAX_PAYLOAD_SIZE);' + LineEnding +
        '' + LineEnding +
        '    let mut out = vec![0u8; final_size];' + LineEnding +
        '    let written = match decoder.decode_all(input, &mut out) {' + LineEnding +
        '        Ok(n) => n,' + LineEnding +
        '        Err(_) => {' + LineEnding +
        '            secure_zero(&mut out);' + LineEnding +
        '            return None;' + LineEnding +
        '        }' + LineEnding +
        '    };' + LineEnding +
        '' + LineEnding +
        '    if written != final_size {' + LineEnding +
        '        secure_zero(&mut out);' + LineEnding +
        '        return None;' + LineEnding +
        '    }' + LineEnding +
        '' + LineEnding +
        '    Some(out)' + LineEnding +
        '}' + LineEnding;
    end;

    COMPACT_BROTLI:
    begin
      Result :=
        '#[inline]' + LineEnding +
        'fn decompress_payload(input: &[u8], final_size: usize) -> Option<Vec<u8>> {' + LineEnding +
        '    if final_size == 0 || final_size as u64 > MAX_PAYLOAD_SIZE {' + LineEnding +
        '        return None;' + LineEnding +
        '    }' + LineEnding +
        '' + LineEnding +
        '    let mut out = vec![0u8; final_size];' + LineEnding +
        '' + LineEnding +
        '    const SCRATCH_U8_SIZE: usize = 32 * 1024 * 1024;' + LineEnding +
        '    const SCRATCH_U32_COUNT: usize = 1024 * 1024;' + LineEnding +
        '    const SCRATCH_HC_COUNT: usize = 4 * 1024 * 1024;' + LineEnding +
        '' + LineEnding +
        '    let mut scratch_u8 = vec![0u8; SCRATCH_U8_SIZE];' + LineEnding +
        '    let mut scratch_u32 = vec![0u32; SCRATCH_U32_COUNT];' + LineEnding +
        '    let mut scratch_hc = vec![' + LineEnding +
        '        brotli_decompressor::HuffmanCode::default();' + LineEnding +
        '        SCRATCH_HC_COUNT' + LineEnding +
        '    ];' + LineEnding +
        '' + LineEnding +
        '    let info = brotli_decompressor::brotli_decode_prealloc(' + LineEnding +
        '        input,' + LineEnding +
        '        &mut out,' + LineEnding +
        '        &mut scratch_u8,' + LineEnding +
        '        &mut scratch_u32,' + LineEnding +
        '        &mut scratch_hc,' + LineEnding +
        '    );' + LineEnding +
        '' + LineEnding +
        '    secure_zero(&mut scratch_u8);' + LineEnding +
        '' + LineEnding +
        '    match info.result {' + LineEnding +
        '        brotli_decompressor::BrotliResult::ResultSuccess => {' + LineEnding +
        '            if info.decoded_size != final_size {' + LineEnding +
        '                secure_zero(&mut out);' + LineEnding +
        '                return None;' + LineEnding +
        '            }' + LineEnding +
        '            Some(out)' + LineEnding +
        '        }' + LineEnding +
        '        _ => {' + LineEnding +
        '            secure_zero(&mut out);' + LineEnding +
        '            None' + LineEnding +
        '        }' + LineEnding +
        '    }' + LineEnding +
        '}' + LineEnding;
    end;

  else
    raise Exception.CreateFmt('Algoritmo de compressão Linux inválido: %d',
      [CompressionAlgorithm]);
  end;
end;


{ Gera o Cargo.toml da Stub Linux. }

function PatchLinuxCargoTemplate(const TemplatePath, OutputPath: string;
  CompressionAlgorithm: Integer): Boolean;
const
  ALGORITHM_MARKER = '@@@ALGORITHM_MODE@@@';
  OPT_LEVEL_MARKER = '@@OPT_LEVEL@@';
  LTO_CFG_MARKER   = '@@LTO_CFG@@';
var
  FS: TStringList;
  Source: string;
  Dependency: string;
  LtoLiteral: string;
  OptLevelLiteral: string;

  function NormalizeOptLevel(const Value: string): string;
  var
    S: string;
  begin
    S := Trim(Value);

    if (Length(S) >= 2) and
       (((S[1] = '"') and (S[Length(S)] = '"')) or
        ((S[1] = '''') and (S[Length(S)] = ''''))) then
      S := Copy(S, 2, Length(S) - 2);

    S := LowerCase(Trim(S));

    if (S = '0') or (S = '1') or (S = '2') or (S = '3') then
      Exit(S);

    if (S = 's') or (S = 'z') then
      Exit('"' + S + '"');

    raise Exception.Create('OPT_LEVEL_CONFIG inválido: ' + Value +
      '. Use 0, 1, 2, 3, "s" ou "z".');
  end;

begin
  Result := False;

  if not FileExists(TemplatePath) then
    raise Exception.Create('Template Cargo.toml.in Linux não encontrado: ' +
      TemplatePath);

  case CompressionAlgorithm of
    COMPACT_ZSTD:
      Dependency :=
        'ruzstd = { version = "0.9.0", default-features = false }';

    COMPACT_BROTLI:
      Dependency :=
        'brotli-decompressor = { version = "6.0.0", default-features = false }';

  else
    raise Exception.CreateFmt('Algoritmo de compressão Linux inválido: %d',
      [CompressionAlgorithm]);
  end;

  if LTO_CONFIG then
    LtoLiteral := 'true'
  else
    LtoLiteral := 'false';

  OptLevelLiteral := NormalizeOptLevel(OPT_LEVEL_CONFIG);

  FS := TStringList.Create;
  try
    FS.LoadFromFile(TemplatePath);
    Source := FS.Text;

    if Pos(ALGORITHM_MARKER, Source) = 0 then
      raise Exception.Create('Marcador ' + ALGORITHM_MARKER +
        ' não encontrado no Cargo.toml.in Linux.');

    if Pos(OPT_LEVEL_MARKER, Source) = 0 then
      raise Exception.Create('Marcador ' + OPT_LEVEL_MARKER +
        ' não encontrado no Cargo.toml.in Linux.');

    if Pos(LTO_CFG_MARKER, Source) = 0 then
      raise Exception.Create('Marcador ' + LTO_CFG_MARKER +
        ' não encontrado no Cargo.toml.in Linux.');

    Source := StringReplace(Source, ALGORITHM_MARKER, Dependency,
      [rfReplaceAll]);
    Source := StringReplace(Source, OPT_LEVEL_MARKER, OptLevelLiteral,
      [rfReplaceAll]);
    Source := StringReplace(Source, LTO_CFG_MARKER, LtoLiteral,
      [rfReplaceAll]);

    FS.Text := Source;
    FS.SaveToFile(OutputPath);
    Result := True;
  finally
    FS.Free;
  end;
end;


function PatchStubTemplate(const TemplatePath: string; const OutputPath: string;
  const Secret: TBytes; const Magics: TQWordArray;
  const FooterMagic: QWord; const FragLabel, MetaLabel: TBytes;
  CompressionAlgorithm: Integer; const VM: TLinuxVmBuild): Boolean;
const
  SECRET_ENC_MARKER          = '@@SECRET_ENC@@';
  SECRET_MASK_MARKER         = '@@SECRET_MASK@@';
  MAGIC_COUNT_MARKER         = '@@MAGIC_COUNT@@';
  MAGIC_ARRAY_MARKER         = '@@MAGIC_ARRAY@@';
  FOOTER_MAGIC_MARKER        = '@@FOOTER_MAGIC@@';
  FRAG_LABEL_MARKER          = '@@FRAG_LABEL@@';
  META_LABEL_MARKER          = '@@META_LABEL@@';
  PROC_STATUS_ENC_MARKER     = '@@PROC_STATUS_ENC@@';
  PROC_STATUS_MASK_MARKER    = '@@PROC_STATUS_MASK@@';
  PROC_SELF_EXE_ENC_MARKER   = '@@PROC_SELF_EXE_ENC@@';
  PROC_SELF_EXE_MASK_MARKER  = '@@PROC_SELF_EXE_MASK@@';
  TRACER_PID_ENC_MARKER      = '@@TRACER_PID_ENC@@';
  TRACER_PID_MASK_MARKER     = '@@TRACER_PID_MASK@@';
  DECOMPRESSOR_MARKER        = '@@DECOMPRESSOR_IMPL@@';
  VM_SEED_MARKER              = '@@VM_SEED@@';

  
  function BytesToRustArray(const B: TBytes): string;
  var
    K: Integer;
  begin
    Result := '';
    for K := 0 to Length(B) - 1 do
    begin
      if K > 0 then
        Result := Result + ', ';
      Result := Result + Format('0x%.2x', [B[K]]);
    end;
  end;

  
  function AsciiBytes(const S: AnsiString; AddNull: Boolean): TBytes;
  var
    K, Extra: Integer;
  begin
    if AddNull then Extra := 1 else Extra := 0;
    SetLength(Result, Length(S) + Extra);

    for K := 1 to Length(S) do
      Result[K - 1] := Byte(Ord(S[K]));

    if AddNull then
      Result[High(Result)] := 0;
  end;

  
  procedure MaskBytes(const Plain: TBytes; out Encoded, Mask: TBytes);
  var
    K: Integer;
  begin
    Mask := RandomBytes(Length(Plain));
    if Length(Mask) <> Length(Plain) then
      raise Exception.Create('Falha ao gerar máscara aleatória do Stub.');

    SetLength(Encoded, Length(Plain));
    for K := 0 to Length(Plain) - 1 do
      Encoded[K] := Plain[K] xor Mask[K];
  end;

  procedure ClearBytes(var B: TBytes);
  begin
    if Length(B) > 0 then
      FillChar(B[0], Length(B), 0);
    SetLength(B, 0);
  end;

  procedure RequireMarker(const Marker, SourceText: string);
  begin
    if Pos(Marker, SourceText) = 0 then
      raise Exception.Create('Marcador ' + Marker +
        ' não encontrado no template Rust.');
  end;

var
  Source: string;
  SecretEncoded, SecretMask: TBytes;
  ProcStatusPlain, ProcStatusEncoded, ProcStatusMask: TBytes;
  ProcSelfExePlain, ProcSelfExeEncoded, ProcSelfExeMask: TBytes;
  TracerPidPlain, TracerPidEncoded, TracerPidMask: TBytes;

  SecretEncodedLiteral, SecretMaskLiteral: string;
  ProcStatusEncodedLiteral, ProcStatusMaskLiteral: string;
  ProcSelfExeEncodedLiteral, ProcSelfExeMaskLiteral: string;
  TracerPidEncodedLiteral, TracerPidMaskLiteral: string;

  MagicCountLiteral: string;
  MagicArrayLiteral: string;
  FooterMagicLiteral: string;
  FragLabelLiteral: string;
  MetaLabelLiteral: string;
  VmSeedLiteral: string;
  DecompressorCode: string;
  FS: TStringList;
  I: Integer;
begin
  Result := False;

  if Length(Secret) <> SECRET_SIZE then
    raise Exception.Create('Secret deve ter 32 bytes.');
  if Length(Magics) < 1 then
    raise Exception.Create('É necessário ao menos 1 magic.');
  if (Length(FragLabel) <> 16) or (Length(MetaLabel) <> 16) then
    raise Exception.Create('Labels de derivação devem ter 16 bytes.');

  { Strings embutidas usam uma máscara diferente em cada build. }
  { O Secret codificado inclui a saída da VM deste build. }
  PrepararLinuxVmSecret(Secret, VM, SecretEncoded, SecretMask);

  ProcStatusPlain := AsciiBytes('/proc/self/status', True);
  ProcSelfExePlain := AsciiBytes('/proc/self/exe', True);
  TracerPidPlain := AsciiBytes('TracerPid:', False);

  if Length(ProcStatusPlain) <> 18 then
    raise Exception.Create('Tamanho inesperado de /proc/self/status.');
  if Length(ProcSelfExePlain) <> 15 then
    raise Exception.Create('Tamanho inesperado de /proc/self/exe.');
  if Length(TracerPidPlain) <> 10 then
    raise Exception.Create('Tamanho inesperado de TracerPid:.');

  MaskBytes(ProcStatusPlain, ProcStatusEncoded, ProcStatusMask);
  MaskBytes(ProcSelfExePlain, ProcSelfExeEncoded, ProcSelfExeMask);
  MaskBytes(TracerPidPlain, TracerPidEncoded, TracerPidMask);

  FS := TStringList.Create;
  try
    FS.LoadFromFile(TemplatePath);
    Source := FS.Text;
    DecompressorCode := GetLinuxRustDecompressorCode(CompressionAlgorithm);

    SecretEncodedLiteral := BytesToRustArray(SecretEncoded);
    SecretMaskLiteral := BytesToRustArray(SecretMask);

    ProcStatusEncodedLiteral := BytesToRustArray(ProcStatusEncoded);
    ProcStatusMaskLiteral := BytesToRustArray(ProcStatusMask);
    ProcSelfExeEncodedLiteral := BytesToRustArray(ProcSelfExeEncoded);
    ProcSelfExeMaskLiteral := BytesToRustArray(ProcSelfExeMask);
    TracerPidEncodedLiteral := BytesToRustArray(TracerPidEncoded);
    TracerPidMaskLiteral := BytesToRustArray(TracerPidMask);

    FragLabelLiteral := BytesToRustArray(FragLabel);
    MetaLabelLiteral := BytesToRustArray(MetaLabel);
    VmSeedLiteral := BytesToRustArray(VM.Seed);

    MagicCountLiteral := IntToStr(Length(Magics));
    MagicArrayLiteral := '';
    for I := 0 to Length(Magics) - 1 do
    begin
      if I > 0 then
        MagicArrayLiteral := MagicArrayLiteral + ', ';
      MagicArrayLiteral :=
        MagicArrayLiteral + '0x' + IntToHex(Magics[I], 16);
    end;

    FooterMagicLiteral := IntToHex(FooterMagic, 16);

    RequireMarker(SECRET_ENC_MARKER, Source);
    RequireMarker(SECRET_MASK_MARKER, Source);
    RequireMarker(MAGIC_COUNT_MARKER, Source);
    RequireMarker(MAGIC_ARRAY_MARKER, Source);
    RequireMarker(FOOTER_MAGIC_MARKER, Source);
    RequireMarker(FRAG_LABEL_MARKER, Source);
    RequireMarker(META_LABEL_MARKER, Source);
    RequireMarker(PROC_STATUS_ENC_MARKER, Source);
    RequireMarker(PROC_STATUS_MASK_MARKER, Source);
    RequireMarker(PROC_SELF_EXE_ENC_MARKER, Source);
    RequireMarker(PROC_SELF_EXE_MASK_MARKER, Source);
    RequireMarker(TRACER_PID_ENC_MARKER, Source);
    RequireMarker(TRACER_PID_MASK_MARKER, Source);
    RequireMarker(DECOMPRESSOR_MARKER, Source);
    RequireMarker(VM_SEED_MARKER, Source);

    Source := StringReplace(Source, SECRET_ENC_MARKER,
      SecretEncodedLiteral, [rfReplaceAll]);
    Source := StringReplace(Source, SECRET_MASK_MARKER,
      SecretMaskLiteral, [rfReplaceAll]);
    Source := StringReplace(Source, MAGIC_ARRAY_MARKER,
      MagicArrayLiteral, [rfReplaceAll]);
    Source := StringReplace(Source, MAGIC_COUNT_MARKER,
      MagicCountLiteral, [rfReplaceAll]);
    Source := StringReplace(Source, FOOTER_MAGIC_MARKER,
      FooterMagicLiteral, [rfReplaceAll]);
    Source := StringReplace(Source, FRAG_LABEL_MARKER,
      FragLabelLiteral, [rfReplaceAll]);
    Source := StringReplace(Source, META_LABEL_MARKER,
      MetaLabelLiteral, [rfReplaceAll]);
    Source := StringReplace(Source, PROC_STATUS_ENC_MARKER,
      ProcStatusEncodedLiteral, [rfReplaceAll]);
    Source := StringReplace(Source, PROC_STATUS_MASK_MARKER,
      ProcStatusMaskLiteral, [rfReplaceAll]);
    Source := StringReplace(Source, PROC_SELF_EXE_ENC_MARKER,
      ProcSelfExeEncodedLiteral, [rfReplaceAll]);
    Source := StringReplace(Source, PROC_SELF_EXE_MASK_MARKER,
      ProcSelfExeMaskLiteral, [rfReplaceAll]);
    Source := StringReplace(Source, TRACER_PID_ENC_MARKER,
      TracerPidEncodedLiteral, [rfReplaceAll]);
    Source := StringReplace(Source, TRACER_PID_MASK_MARKER,
      TracerPidMaskLiteral, [rfReplaceAll]);
    Source := StringReplace(Source, DECOMPRESSOR_MARKER,
      DecompressorCode, [rfReplaceAll]);
    Source := StringReplace(Source, VM_SEED_MARKER,
      VmSeedLiteral, [rfReplaceAll]);

    FS.Text := Source;
    FS.SaveToFile(OutputPath);
    Result := True;
  finally
    FS.Free;

    ClearBytes(SecretEncoded);
    ClearBytes(SecretMask);
    ClearBytes(ProcStatusPlain);
    ClearBytes(ProcStatusEncoded);
    ClearBytes(ProcStatusMask);
    ClearBytes(ProcSelfExePlain);
    ClearBytes(ProcSelfExeEncoded);
    ClearBytes(ProcSelfExeMask);
    ClearBytes(TracerPidPlain);
    ClearBytes(TracerPidEncoded);
    ClearBytes(TracerPidMask);
  end;
end;


{ Compilação da Stub Linux }

function CompilarStub(const ManifestPath: string;
  out Saida: string): Boolean;
begin
  Saida := '';

  if SameText(RUST_LINUX_TARGET, RUST_LINUX_TARGET_MUSL) then
  begin
    Result := ExecutarProcesso(
      'cargo',
      [
        'rustc',
        '--release',
        '--target',
        RUST_LINUX_TARGET,
        '--manifest-path',
        ManifestPath,
        '--',
        '-C',
        'link-self-contained=no',
        '-C',
        'relocation-model=static'
      ],
      Saida
    );
    Exit;
  end;

  if SameText(RUST_LINUX_TARGET, RUST_LINUX_TARGET_GNU) then
  begin
    Result := ExecutarProcesso(
      'cargo',
      [
        'build',
        '--release',
        '--target',
        RUST_LINUX_TARGET,
        '--manifest-path',
        ManifestPath
      ],
      Saida
    );
    Exit;
  end;

  Saida := 'Target Rust Linux inválido: ' + RUST_LINUX_TARGET;
  Result := False;
end;

{ Pós-processamento do binário }

function RemoverMetadados(const Arquivo: string; out Erro: string): boolean;
begin
  Result := ExecutarProcesso('strip', ['--strip-all', '--remove-section=.comment',
    '--remove-section=.note', '--remove-section=.note.gnu.build-id',
    '--remove-section=.note.ABI-tag', '--remove-section=.note.gnu.property',
    Arquivo], Erro);
end;

{ Compressão do payload }

function CompactarComZstd(const Origem, Destino: string; out Saida: string): boolean;
begin
  
  Result := ExecutarProcesso('zstd',
    ['--ultra', ZSTD_ARGS_LEVEL, '-f', '-q', '-o', Destino, Origem], Saida);
end;

function CompactBrotli(const Origem, Destino: string; out Saida: string): boolean;
begin
  
  Result := ExecutarProcesso('brotli',
    ['-q', '11', '-w', '24', '-f', '-o', Destino, Origem], Saida);
end;

function CriarCopiaTemporaria(const Origem: string;
  out ArquivoTemporario: string): boolean;
var
  TempFD: cint;
  TempPath: string;
  NomeAleatorio: string;
  RandomData: TBytes;
  SourceStream: TFileStream;
  Buffer: array[0..65535] of byte;
  ReadCount: integer;
  WriteCount: integer;
  Offset: integer;
  I: integer;
begin
  Result := False;
  ArquivoTemporario := '';

  
  repeat
    RandomData := RandomBytes(16);

    NomeAleatorio := '';

    for I := 0 to Length(RandomData) - 1 do
      NomeAleatorio := NomeAleatorio + IntToHex(RandomData[I], 2);

    TempPath := '/tmp/packer-' + NomeAleatorio;

    TempFD := fpOpen(PChar(TempPath), O_WRONLY or O_CREAT or O_EXCL, &600);

  until TempFD >= 0;

  try
    ArquivoTemporario := TempPath;

    
    SourceStream := TFileStream.Create(Origem, fmOpenRead or fmShareDenyWrite);

    try
      while True do
      begin
        ReadCount := SourceStream.Read(Buffer, SizeOf(Buffer));

        if ReadCount = 0 then
          Break;

        Offset := 0;

        { fpWrite pode retornar escrita parcial. }
        while Offset < ReadCount do
        begin
          WriteCount := fpWrite(TempFD, Buffer[Offset], ReadCount - Offset);

          if WriteCount <= 0 then
            raise Exception.Create(
              'Erro ao escrever o arquivo temporário.');

          Inc(Offset, WriteCount);
        end;
      end;

    finally
      SourceStream.Free;
    end;

    
    if fpClose(TempFD) <> 0 then
      raise Exception.Create('Erro ao fechar o arquivo temporário.');

    TempFD := -1;

    { Arquivo temporário acessível apenas pelo usuário atual. }
    if fpChmod(PChar(ArquivoTemporario), &700) <> 0 then
      raise Exception.Create(
        'Não foi possível definir as permissões do arquivo temporário.');

    Result := True;

  except
    if TempFD >= 0 then
      fpClose(TempFD);

    if ArquivoTemporario <> '' then
      DeleteFile(ArquivoTemporario);

    ArquivoTemporario := '';

    raise;
  end;
end;


procedure CriarArquivoFinal(const ArquivoSaida: string; const Stub: TBytes;
  const PackedRegion: TBytes);
var
  FSOut: TFileStream;
begin
  FSOut := TFileStream.Create(ArquivoSaida, fmCreate);

  try
    
    if Length(Stub) > 0 then
      FSOut.WriteBuffer(Stub[0], Length(Stub));

    { Anexa a região produzida pelo packer. }
    if Length(PackedRegion) > 0 then
      FSOut.WriteBuffer(PackedRegion[0], Length(PackedRegion));

  finally
    FSOut.Free;
  end;

  
  if fpChmod(ArquivoSaida, &755) <> 0 then
    raise Exception.Create('Não foi possível tornar o arquivo final executável.'
      );
end;

procedure GravarBytesEmArquivo(const Arquivo: string; const Dados: TBytes);
var
  FS: TFileStream;
  Pasta: string;
begin
  Pasta := ExtractFileDir(Arquivo);
  if (Pasta <> '') and (not DirectoryExists(Pasta)) then
    if not ForceDirectories(Pasta) then
      raise Exception.Create('Não foi possível criar diretório: ' + Pasta);

  FS := TFileStream.Create(Arquivo, fmCreate);
  try
    if Length(Dados) > 0 then
      FS.WriteBuffer(Dados[0], Length(Dados));
  finally
    FS.Free;
  end;
end;

end.
