unit CasuloLinuxPipeline;

{$mode objfpc}{$H+}

interface

uses
  SysUtils, Packer;

function EmpacotarLinux(AlvoPath, SaidaPath: string;
  Log: TDebugProc; out Erro: string): Boolean;

implementation

uses
  CasuloConfig, CasuloCommon, CasuloLinuxVm;

procedure EmitLog(const Log: TDebugProc; const Msg: string); inline;
begin
  if Assigned(Log) then
    Log(Msg);
end;

function StripStubEnabled: Boolean;
begin
  Result := STRIP_STUB;
end;

function EmpacotarLinux(AlvoPath, SaidaPath: string;
  Log: TDebugProc; out Erro: string): Boolean;
var
  Stub: TBytes;
  CompressedPayload: TBytes;
  Secret: TBytes;
  Magics: TQWordArray;
  FooterMagic: QWord;
  FragLabel: TBytes;
  MetaLabel: TBytes;
  PackedRegion: TBytes;

  TempPayloadPath: string;
  CompressedPath: string;
  CompressionOutput: string;
  CompilerOutput: string;
  StripOutput: string;

  OriginalSize: Int64;
  CompressedSize: Int64;
  StartTime: TDateTime;
  EndTime: TDateTime;

  StubTemplatePath: string;
  GeneratedStubPath: string;
  ManifestTemplatePath: string;
  ManifestPath: string;
  RustBinary: string;

  VmTemplatePath: string;
  VmGeneratedPath: string;
  VmBuild: TLinuxVmBuild;

  CompressionName: string;
  CompressionDisplayName: string;
  LtoDisplay: string;
  OptLevelDisplay: string;

  Success: Boolean;
begin
  Erro := '';
  Result := False;
  Success := False;

  TempPayloadPath := '';
  CompressedPath := '';
  StubTemplatePath := '';
  GeneratedStubPath := '';
  ManifestTemplatePath := '';
  ManifestPath := '';
  RustBinary := '';
  VmTemplatePath := '';
  VmGeneratedPath := '';

  CompressionName := '';
  CompressionDisplayName := '';
  LtoDisplay := '';
  OptLevelDisplay := '';

  StartTime := Now;

  try
    EmitLog(Log, '========== INICIANDO EMPACOTAMENTO LINUX ==========');

    
    if LTO_CONFIG then
      LtoDisplay := 'true'
    else
      LtoDisplay := 'false';

    OptLevelDisplay := StringReplace(Trim(OPT_LEVEL_CONFIG), '"', '',
      [rfReplaceAll]);
    OptLevelDisplay := StringReplace(OptLevelDisplay, '''', '',
      [rfReplaceAll]);

    case COMPACT_ALGORITHM of
      COMPACT_ZSTD:
        CompressionDisplayName := 'ZSTD';
      COMPACT_BROTLI:
        CompressionDisplayName := 'BROTLI';
    else
      raise Exception.CreateFmt('COMPACT_ALGORITHM inválido: %d',
        [COMPACT_ALGORITHM]);
    end;

    EmitLog(Log, '--- CONFIGURAÇÃO DO BUILD ---');
    EmitLog(Log, 'Target Rust: ' + RUST_LINUX_TARGET);
    EmitLog(Log, 'Algoritmo de compressão: ' + CompressionDisplayName);
    EmitLog(Log, 'Cargo opt-level: ' + OptLevelDisplay);
    EmitLog(Log, 'Cargo LTO: ' + LtoDisplay);
    EmitLog(Log, 'Cargo codegen-units: 1');
    EmitLog(Log, 'Cargo panic: abort');
    EmitLog(Log, 'Cargo strip: true');
    EmitLog(Log, 'STRIP_STUB pós-build: ' + BoolToStr(StripStubEnabled, True));
    EmitLog(Log, '-----------------------------');

    
    if Trim(AlvoPath) = '' then
      raise Exception.Create('Selecione um executável para empacotar.');

    if Trim(SaidaPath) = '' then
      raise Exception.Create('Selecione o arquivo de saída.');

    AlvoPath := ExpandFileName(AlvoPath);
    SaidaPath := ExpandFileName(SaidaPath);

    if not FileExists(AlvoPath) then
      raise Exception.Create('Payload não encontrado: ' + AlvoPath);

    if SameFileName(AlvoPath, SaidaPath) then
      raise Exception.Create(
        'O arquivo de entrada e o arquivo de saída não podem ser iguais.');

    
    OriginalSize := GetFileSizeByName(AlvoPath);

    if OriginalSize <= 0 then
      raise Exception.Create('O payload está vazio.');

    if OriginalSize > MAX_INPUT_SIZE then
      raise Exception.Create(Format('O payload excede o limite de %d MB.',
        [MAX_INPUT_SIZE div (1024 * 1024)]));

    EmitLog(Log, Format('Payload de entrada: %d bytes', [OriginalSize]));

    
    StubTemplatePath := ProjectPath(RustTemplatePath);
    GeneratedStubPath := ProjectPath(RustGeneratedPath);
    ManifestTemplatePath := ProjectPath(RustManifestTemplatePath);
    ManifestPath := ProjectPath(RustManifestPath);
    VmTemplatePath := ProjectPath(RustLinuxVmTemplatePath);
    VmGeneratedPath := ProjectPath(RustLinuxVmGeneratedPath);

    if (not SameText(RUST_LINUX_TARGET, RUST_LINUX_TARGET_GNU)) and
       (not SameText(RUST_LINUX_TARGET, RUST_LINUX_TARGET_MUSL)) then
      raise Exception.Create('Target Rust Linux inválido: ' +
        RUST_LINUX_TARGET);

    RustBinary :=
      IncludeTrailingPathDelimiter(ProjectPath(RustTargetRootPath)) +
      RUST_LINUX_TARGET + DirectorySeparator +
      'release' + DirectorySeparator +
      RustBinaryName;

    if not FileExists(StubTemplatePath) then
      raise Exception.Create('Template main.rs.in Linux não encontrado: ' +
        StubTemplatePath);

    if not FileExists(ManifestTemplatePath) then
      raise Exception.Create('Cargo.toml.in Linux não encontrado: ' +
        ManifestTemplatePath);

    if not FileExists(VmTemplatePath) then
      raise Exception.Create('Template exec_vm.rs.in Linux não encontrado: ' +
        VmTemplatePath);

    EmitLog(Log, 'Templates Linux validados.');

    
    EmitLog(Log, 'Gerando material criptográfico...');
    Secret := RandomBytes(SECRET_SIZE);

    if Length(Secret) <> SECRET_SIZE then
      raise Exception.Create('Falha ao gerar Secret.');

    
    EmitLog(Log, 'Criando cópia temporária segura do payload...');

    if not CriarCopiaTemporaria(AlvoPath, TempPayloadPath) then
      raise Exception.Create('Falha ao criar cópia temporária do payload.');

    
    EmitLog(Log, 'Algoritmo selecionado para compressão: ' +
      CompressionDisplayName);

    case COMPACT_ALGORITHM of
      COMPACT_ZSTD:
      begin
        CompressionName := 'zstd';
        CompressedPath := TempPayloadPath + '.zst';

        EmitLog(Log, 'Comprimindo payload com zstd (--ultra ' +
          ZSTD_ARGS_LEVEL + ')...');

        if not CompactarComZstd(TempPayloadPath, CompressedPath,
          CompressionOutput) then
          raise Exception.Create('Falha ao comprimir com zstd:' +
            LineEnding + CompressionOutput);
      end;

      COMPACT_BROTLI:
      begin
        CompressionName := 'brotli';
        CompressedPath := TempPayloadPath + '.br';

        EmitLog(Log, 'Comprimindo payload com brotli -q 11 -w 24...');

        if not CompactBrotli(TempPayloadPath, CompressedPath,
          CompressionOutput) then
          raise Exception.Create('Falha ao comprimir com brotli:' +
            LineEnding + CompressionOutput);
      end;
    end;

    
    CompressedPayload := LerArquivo(CompressedPath);

    if Length(CompressedPayload) = 0 then
      raise Exception.Create('O stream ' + CompressionName + ' está vazio.');

    CompressedSize := Length(CompressedPayload);

    EmitLog(Log, Format('Payload %s: %d -> %d bytes (%.2fx)',
      [CompressionName, OriginalSize, CompressedSize,
       OriginalSize / CompressedSize]));

    
    EmitLog(Log, 'Construindo containers fragmentados...');

    if not EncryptFragmented(CompressedPayload, OriginalSize, Secret, Magics,
      FooterMagic, FragLabel, MetaLabel, PackedRegion) then
      raise Exception.Create('Falha ao construir os containers fragmentados.');

    if Length(PackedRegion) = 0 then
      raise Exception.Create('A região empacotada está vazia.');

    if Length(Magics) < 1 then
      raise Exception.Create('Nenhum magic foi gerado.');

    EmitLog(Log, Format('Containers: %d | região empacotada: %d bytes',
      [Length(Magics), Length(PackedRegion)]));

    { VM deste build. }
    GerarLinuxVmBuild(VmBuild);

    EmitLog(Log, Format(
      'VM Linux: ISA própria sorteada | mix=%d ops | bytecode=%d bytes',
      [Length(VmBuild.MixOps), Length(VmBuild.MixCode)]));

    if not PatchExecVmTemplateLinux(
      VmTemplatePath,
      VmGeneratedPath,
      VmBuild
    ) then
      raise Exception.Create('Falha ao gerar exec_vm.rs da Stub Linux.');

    { Gera o main.rs com o material específico deste build. }
    EmitLog(Log, 'Gerando src/main.rs para ' +
      CompressionDisplayName + ' + VM Linux...');

    if not PatchStubTemplate(StubTemplatePath, GeneratedStubPath,
      Secret, Magics, FooterMagic, FragLabel, MetaLabel,
      COMPACT_ALGORITHM, VmBuild) then
      raise Exception.Create('Falha ao gerar o Stub Linux.');

    { Gera o Cargo.toml com a dependência de compressão escolhida. }
    EmitLog(Log, 'Gerando Cargo.toml Linux...');

    if not PatchLinuxCargoTemplate(ManifestTemplatePath, ManifestPath,
      COMPACT_ALGORITHM) then
      raise Exception.Create('Falha ao gerar Cargo.toml Linux.');

    if not FileExists(ManifestPath) then
      raise Exception.Create('Cargo.toml Linux não foi gerado: ' +
        ManifestPath);

    EmitLog(Log, 'Cargo.toml | algoritmo=' + CompressionDisplayName +
      ' | opt-level=' + OptLevelDisplay +
      ' | lto=' + LtoDisplay);

    
    if SameText(RUST_LINUX_TARGET, RUST_LINUX_TARGET_MUSL) then
      EmitLog(Log, 'Compilando Stub Linux MUSL (cargo rustc --release)...')
    else
      EmitLog(Log, 'Compilando Stub Linux GNU (cargo build --release)...');

    if not CompilarStub(ManifestPath, CompilerOutput) then
      raise Exception.Create('Falha na compilação do Stub Linux:' +
        LineEnding + CompilerOutput);

    if not FileExists(RustBinary) then
      raise Exception.Create('Cargo não gerou o Stub Linux: ' + RustBinary);

    EmitLog(Log, 'Stub Linux compilado com sucesso.');

    
    if StripStubEnabled then
    begin
      EmitLog(Log, 'Executando strip pós-build no Stub...');

      if not RemoverMetadados(RustBinary, StripOutput) then
        EmitLog(Log, 'Aviso: strip falhou: ' + StripOutput);
    end
    else
      EmitLog(Log, 'Strip pós-build desativado.');

    
    Stub := LerArquivo(RustBinary);

    if Length(Stub) = 0 then
      raise Exception.Create('O Stub Linux final está vazio.');

    EmitLog(Log, Format('Stub final: %d bytes', [Length(Stub)]));

    
    EmitLog(Log, 'Montando arquivo final...');
    CriarArquivoFinal(SaidaPath, Stub, PackedRegion);

    if (not FileExists(SaidaPath)) or
       (GetFileSizeByName(SaidaPath) <= 0) then
      raise Exception.Create('O arquivo final não foi criado corretamente.');

    Success := True;
    Result := True;
    EndTime := Now;

    EmitLog(Log, '========================================');
    EmitLog(Log, 'EMPACOTAMENTO LINUX CONCLUÍDO');
    EmitLog(Log, '--- BUILD EFETIVO ---');
    EmitLog(Log, 'Target: ' + RUST_LINUX_TARGET);
    EmitLog(Log, 'Compressão: ' + CompressionDisplayName);
    EmitLog(Log, 'opt-level: ' + OptLevelDisplay);
    EmitLog(Log, 'LTO: ' + LtoDisplay);
    EmitLog(Log, 'Strip Cargo: true');
    EmitLog(Log, 'Strip pós-build: ' + BoolToStr(StripStubEnabled, True));
    EmitLog(Log, '---------------------');
    EmitLog(Log, Format('Payload original: %d bytes', [OriginalSize]));
    EmitLog(Log, Format('Payload %s: %d bytes',
      [CompressionName, CompressedSize]));
    EmitLog(Log, Format('Containers: %d', [Length(Magics)]));
    EmitLog(Log, Format('Região empacotada: %d bytes',
      [Length(PackedRegion)]));
    EmitLog(Log, Format('Stub: %d bytes', [Length(Stub)]));
    EmitLog(Log, Format('Saída: %s (%d bytes)',
      [SaidaPath, GetFileSizeByName(SaidaPath)]));
    EmitLog(Log, Format('Tempo: %s',
      [FormatDateTime('hh:nn:ss', EndTime - StartTime)]));
    EmitLog(Log,
      'Criptografia: AES-256-CBC + HMAC-SHA256 por fragmento');
    EmitLog(Log,
      'KDF: HKDF-SHA256 com chaves encadeadas');
    EmitLog(Log,
      'VM Linux: própria/independente | Secret via VM mix | gate final via HOST_EXECVEAT');
    EmitLog(Log, '========================================');

  except
    on E: Exception do
    begin
      Result := False;
      Success := False;
      Erro := E.Message;
      EmitLog(Log, 'ERRO LINUX: ' + E.Message);
    end;
  end;

  { Limpeza dos temporários do build. }
  try
    if (CompressedPath <> '') and FileExists(CompressedPath) then
      DeleteFile(CompressedPath);

    if (TempPayloadPath <> '') and FileExists(TempPayloadPath) then
      DeleteFile(TempPayloadPath);

    if (RustBinary <> '') and FileExists(RustBinary) then
      DeleteFile(RustBinary);

    if (GeneratedStubPath <> '') and FileExists(GeneratedStubPath) then
      DeleteFile(GeneratedStubPath);

    if (VmGeneratedPath <> '') and FileExists(VmGeneratedPath) then
      DeleteFile(VmGeneratedPath);

    if (ManifestPath <> '') and FileExists(ManifestPath) then
      DeleteFile(ManifestPath);

  except
    on E: Exception do
      EmitLog(Log, 'Aviso durante limpeza Linux: ' + E.Message);
  end;

  
  if Length(Secret) > 0 then
    FillChar(Secret[0], Length(Secret), 0);

  if Length(CompressedPayload) > 0 then
    FillChar(CompressedPayload[0], Length(CompressedPayload), 0);

  if Length(PackedRegion) > 0 then
    FillChar(PackedRegion[0], Length(PackedRegion), 0);

  if Length(Stub) > 0 then
    FillChar(Stub[0], Length(Stub), 0);

  if Length(Magics) > 0 then
    FillChar(Magics[0], Length(Magics) * SizeOf(QWord), 0);

  if Length(FragLabel) > 0 then
    FillChar(FragLabel[0], Length(FragLabel), 0);

  if Length(MetaLabel) > 0 then
    FillChar(MetaLabel[0], Length(MetaLabel), 0);

  LimparLinuxVmBuild(VmBuild);

  if Success then
    EmitLog(Log, '========== LINUX FINALIZADO COM SUCESSO ==========')
  else
    EmitLog(Log, '========== LINUX FINALIZADO COM ERRO ==========');
end;

end.

