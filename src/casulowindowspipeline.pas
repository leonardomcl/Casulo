unit CasuloWindowsPipeline;

{$mode objfpc}{$H+}

interface

uses
  SysUtils, Packer, Classes, reswindows, casuloConfig;

function EmpacotarWindows(AlvoPath, SaidaPath: string;
  Log: TDebugProc; out Erro: string): boolean;

implementation

uses
  PEUtils, CasuloCommon, CasuloWindows;

procedure EmitLog(const Log: TDebugProc; const Msg: string); inline;
begin
  if Assigned(Log) then
    Log(Msg);
end;

function StripStubEnabled: boolean;
begin
  
  Result := STRIP_STUB;
end;


function EmpacotarWindows(AlvoPath, SaidaPath: string;
  Log: TDebugProc; out Erro: string): boolean;
var
  Stub, CompressedPayload, Secret, FragLabel, MetaLabel, PackedRegion: TBytes;
  Magics: TQWordArray;
  FooterMagic: QWord;
  TempPayloadPath, CompressedPath, RcDataDir, RcScriptPath: string;
  StubTemplate, StubGenerated, ManifestTemplatePath, ManifestPath: string;
  RustBinary, LoaderPath: string;
  PagingPath, ExecSignalPath: string;
  ExecVmTemplate, ExecVmGenerated: string;
  BuildTemplate, BuildGenerated: string;
  VmBuild: TVmBuild;
  SecretEncPadrao, SecretMask, TextHash, VmSeed, VmMix, SecretEncFinal: TBytes;
  TextOffset, TextTamanho: longword;
  Idx: integer;
  ManifestRcDataId: word;
  RcDataFragmentIds: TRcDataIdArray;
  CompilerOutput, CompressionOutput: string;
  CompressionName: string;
  CompressionDisplayName: string;
  LtoDisplay: string;
  OptLevelDisplay: string;
  OriginalSize, CompressedSize: int64;
  PEInfo: TPE64Info;
  PayloadOldBase, PayloadNewBase, PayloadBaseEfetiva, StubImageBase: QWord;
  Rebased: boolean;
  ExecInMemory: boolean;
  MotivoModo: string;
  StartTime, EndTime: TDateTime;
  Success: boolean;
  StripOutput: string;
  ResInfo: TStringList;
begin
  Erro := '';
  Result := False;
  Success := False;
  TempPayloadPath := '';
  CompressedPath := '';
  RcDataDir := '';
  RcScriptPath := '';
  ManifestRcDataId := 0;
  SetLength(RcDataFragmentIds, 0);
  StubGenerated := '';
  ExecVmGenerated := '';
  ManifestTemplatePath := '';
  ManifestPath := '';
  BuildGenerated := '';
  RustBinary := '';
  Rebased := False;
  ExecInMemory := False;
  PayloadOldBase := 0;
  PayloadNewBase := 0;
  PayloadBaseEfetiva := 0;
  StubImageBase := 0;
  CompressionName := '';
  CompressionDisplayName := '';
  LtoDisplay := '';
  OptLevelDisplay := '';
  StartTime := Now;


  try
    EmitLog(Log, '========== INICIANDO EMPACOTAMENTO WINDOWS ==========');

    
    if LTO_CONFIG then
      LtoDisplay := 'true'
    else
      LtoDisplay := 'false';

    OptLevelDisplay := StringReplace(Trim(OPT_LEVEL_CONFIG), '"', '',
      [rfReplaceAll]);

    case COMPACT_ALGORITHM of
      COMPACT_ZSTD:
        CompressionDisplayName := 'ZSTD';
      COMPACT_BROTLI:
        CompressionDisplayName := 'BROTLI';
      else
        CompressionDisplayName := 'DESCONHECIDO (' +
          IntToStr(COMPACT_ALGORITHM) + ')';
    end;

    EmitLog(Log, '--- CONFIGURAÇÃO DO BUILD ---');
    EmitLog(Log, 'Target Rust: ' + RUST_WIN_TARGET);
    EmitLog(Log, 'Algoritmo de compressão: ' + CompressionDisplayName);
    EmitLog(Log, 'Cargo opt-level: ' + OptLevelDisplay);
    EmitLog(Log, 'Cargo LTO: ' + LtoDisplay);
    EmitLog(Log, 'Cargo codegen-units: 1');
    EmitLog(Log, 'Cargo panic: abort');
    EmitLog(Log, 'Cargo strip: true');
    EmitLog(Log, 'STRIP_STUB pós-build: ' + BoolToStr(StripStubEnabled, True));
    EmitLog(Log, 'RANDOM_IMAGEBASE: ' + BoolToStr(RANDOM_IMAGEBASE, True));
    EmitLog(Log, 'WINDOWS_EXEC_IN_MEMORY: ' +
      BoolToStr(WINDOWS_EXEC_IN_MEMORY, True));
    EmitLog(Log, 'WINDOWS_DEMAND_PAGING: ' +
      BoolToStr(WINDOWS_DEMAND_PAGING, True));
    EmitLog(Log, 'SELF_TEXT_HASH_BINDING: ' +
      BoolToStr(SELF_TEXT_HASH_BINDING, True));
    EmitLog(Log, 'RCDATA_FRAGMENT_SIZE: ' +
      IntToStr(RCDATA_FRAGMENT_SIZE) + ' bytes');
    EmitLog(Log, '-----------------------------');

    if Trim(AlvoPath) = '' then
      raise Exception.Create('Selecione um executável Windows para empacotar.');
    if Trim(SaidaPath) = '' then
      raise Exception.Create('Selecione o arquivo de saída.');

    AlvoPath := ExpandFileName(AlvoPath);
    SaidaPath := ExpandFileName(SaidaPath);
    if not FileExists(AlvoPath) then
      raise Exception.Create('Payload não encontrado: ' + AlvoPath);
    if SameFileName(AlvoPath, SaidaPath) then
      raise Exception.Create('Entrada e saída não podem ser o mesmo arquivo.');

    OriginalSize := GetFileSizeByName(AlvoPath);
    if (OriginalSize <= 0) or (OriginalSize > MAX_INPUT_SIZE) then
      raise Exception.Create('Tamanho do payload Windows inválido ou acima do limite.');

    if not ReadPE64Info(AlvoPath, PEInfo) then
      raise Exception.Create(
        'A v1 do Casulo Windows aceita somente executáveis PE32+ x86-64 ' +
        '(GUI ou Console), não DLLs.');

    EmitLog(Log, Format('PE64 validado | ImageBase: 0x%s | Subsystem: %d',
      [IntToHex(PEInfo.ImageBase, 16), PEInfo.Subsystem]));

    
    ExecInMemory := DecidirModoExecucaoWindows(AlvoPath, PEInfo, MotivoModo);
    EmitLog(Log, 'Modo de execução: ' + MotivoModo);

    StubTemplate := ProjectPath(RustWinTemplatePath);
    StubGenerated := ProjectPath(RustWinGeneratedPath);
    LoaderPath := ProjectPath(RustWinLoaderPath);
    PagingPath := ProjectPath(RustWinPagingPath);
    ExecSignalPath := ProjectPath(RustWinExecSignalPath);
    ExecVmTemplate := ProjectPath(RustWinExecVmTemplatePath);
    ExecVmGenerated := ProjectPath(RustWinExecVmGeneratedPath);
    ManifestTemplatePath := ProjectPath(RustWinManifestTemplatePath);
    ManifestPath := ProjectPath(RustWinManifestPath);
    RustBinary := ProjectPath(RustWinBinaryPath);
    BuildTemplate := ProjectPath(RustWinBuildTemplatePath);
    BuildGenerated := ProjectPath(RustWinBuildGeneratedPath);
    RcDataDir := ProjectPath(RustWinRcDataDir);
    RcScriptPath := ProjectPath(RustWinRcScriptPath);

    if not FileExists(StubTemplate) then
      raise Exception.Create('Template Windows não encontrado: ' + StubTemplate);
    if not FileExists(LoaderPath) then
      raise Exception.Create('src/loader.rs não encontrado: ' + LoaderPath);
    if not FileExists(PagingPath) then
      raise Exception.Create('src/paging.rs não encontrado: ' + PagingPath);
    if not FileExists(ExecSignalPath) then
      raise Exception.Create('src/exec_signal.rs não encontrado: ' + ExecSignalPath);
    if not FileExists(ExecVmTemplate) then
      raise Exception.Create('src/exec_vm.rs.in não encontrado: ' + ExecVmTemplate);
    if not FileExists(ManifestTemplatePath) then
      raise Exception.Create('Cargo.toml.in Windows não encontrado: ' +
        ManifestTemplatePath);
    if not FileExists(BuildTemplate) then
      raise Exception.Create('build.rs.in Windows não encontrado: ' + BuildTemplate);

    Secret := RandomBytes(SECRET_SIZE);
    if Length(Secret) <> SECRET_SIZE then
      raise Exception.Create('Falha ao gerar Secret Windows.');

    { O rebase é feito sobre uma cópia do PE original. }
    if not CriarCopiaTemporaria(AlvoPath, TempPayloadPath) then
      raise Exception.Create('Falha ao criar cópia temporária do PE.');

    
    if not RANDOM_IMAGEBASE then
      EmitLog(Log, 'RANDOM_IMAGEBASE=False: ImageBase original do payload mantida.')
    else if PEInfo.HasCertificateTable then
      EmitLog(Log,
        'Payload possui tabela Authenticode: rebase ignorado para preservar a assinatura.')
    else if PECountRelocations(TempPayloadPath) = 0 then
      EmitLog(Log, 'Payload sem relocations utilizáveis (nenhum fixup real): ' +
        'ImageBase original mantida.')
    else
    begin
      repeat
        PayloadNewBase := GenerateRandomPE64ImageBase;
      until PayloadNewBase <> PEInfo.ImageBase;

      Rebased := RebasePE64InPlace(TempPayloadPath, PayloadNewBase, PayloadOldBase);
      if Rebased then
        EmitLog(Log, Format('Payload rebaseado: 0x%s -> 0x%s',
          [IntToHex(PayloadOldBase, 16), IntToHex(PayloadNewBase, 16)]))
      else
        EmitLog(Log,
          'Aviso: rebase não aplicado; usando o PE original da cópia temporária.');
    end;

    if Rebased then
      PayloadBaseEfetiva := PayloadNewBase
    else
      PayloadBaseEfetiva := PEInfo.ImageBase;

    EmitLog(Log, 'Algoritmo selecionado para compressão: ' +
      CompressionDisplayName);

    case COMPACT_ALGORITHM of
      COMPACT_ZSTD:
      begin
        CompressionName := 'zstd';
        CompressedPath := TempPayloadPath + '.zst';
        EmitLog(Log, 'Comprimindo payload Windows com zstd (--ultra ' +
          ZSTD_ARGS_LEVEL + ')...');
        if not CompactarComZstd(TempPayloadPath, CompressedPath,
          CompressionOutput) then
          raise Exception.Create('Falha no zstd:' + LineEnding +
            CompressionOutput);
      end;

      COMPACT_BROTLI:
      begin
        CompressionName := 'brotli';
        CompressedPath := TempPayloadPath + '.br';
        EmitLog(Log, 'Comprimindo payload Windows com brotli -q 11 -w 24...');
        if not CompactBrotli(TempPayloadPath, CompressedPath,
          CompressionOutput) then
          raise Exception.Create('Falha no brotli:' + LineEnding +
            CompressionOutput);
      end;
      else
        raise Exception.CreateFmt('COMPACT_ALGORITHM inválido: %d',
          [COMPACT_ALGORITHM]);
    end;

    CompressedPayload := LerArquivo(CompressedPath);
    if Length(CompressedPayload) = 0 then
      raise Exception.Create('Stream ' + CompressionName + ' Windows vazio.');
    CompressedSize := Length(CompressedPayload);

    if not EncryptFragmented(CompressedPayload, OriginalSize, Secret,
      Magics, FooterMagic, FragLabel, MetaLabel, PackedRegion) then
      raise Exception.Create('Falha ao construir região fragmentada Windows.');

    { Divide o PackedRegion em RCDATA; o Stub remonta a região antes de validá-la. }
    if not PrepararRcDataFragmentadoWindows(PackedRegion, RcDataDir,
      RcScriptPath, ManifestRcDataId, RcDataFragmentIds) then
      raise Exception.Create('Falha ao preparar RCDATA fragmentado Windows.');

    EmitLog(Log, Format(
      'RCDATA fragmentado: %d fragmentos + manifest ID %d | PackedRegion %d bytes',
      [Length(RcDataFragmentIds), ManifestRcDataId, Length(PackedRegion)]));

    { Mantém a base do Stub afastada da base preferida do payload. }
    if RANDOM_IMAGEBASE then
    begin
      repeat
        StubImageBase := GenerateRandomPE64ImageBase;
      until (not ExecInMemory) or (StubImageBase >=
          PayloadBaseEfetiva + IMAGEBASE_MIN_GAP) or (PayloadBaseEfetiva >=
          StubImageBase + IMAGEBASE_MIN_GAP);

      EmitLog(Log, 'RANDOM_IMAGEBASE=True: ImageBase aleatório do Stub: 0x' +
        IntToHex(StubImageBase, 16));
    end
    else
    begin
      StubImageBase := DEFAULT_STUB_IMAGEBASE;
      EmitLog(Log, 'RANDOM_IMAGEBASE=False: ImageBase fixo do Stub: 0x' +
        IntToHex(StubImageBase, 16));

      if ExecInMemory and (StubImageBase < PayloadBaseEfetiva +
        IMAGEBASE_MIN_GAP) and (PayloadBaseEfetiva < StubImageBase +
        IMAGEBASE_MIN_GAP) then
        EmitLog(Log, 'Aviso: ImageBase do Stub próxima da base preferida do payload; ' +
          'o loader vai depender de relocation.');
    end;

    
    GerarVmBuild(VmBuild);
    EmitLog(Log, Format(
      'VM do build: ISA sorteada, programa de derivação com %d instruções ' +
      '(%d bytes de bytecode).', [Length(VmBuild.MixOps),
      Length(VmBuild.MixCode)]));

    if not PatchExecVmTemplateWindows(ExecVmTemplate, ExecVmGenerated, VmBuild) then
      raise Exception.Create('Falha ao gerar exec_vm.rs do Stub Windows.');

    if not PatchStubTemplateWindows(StubTemplate, StubGenerated,
      Magics, FooterMagic, FragLabel, MetaLabel, PEInfo.Subsystem,
      ExecInMemory, COMPACT_ALGORITHM, ManifestRcDataId, VmBuild,
      SecretEncPadrao, SecretMask) then
      raise Exception.Create('Falha ao gerar main.rs do Stub Windows.');

    { O Cargo.toml recebe apenas a dependência do compressor selecionado. }
    EmitLog(Log, 'Gerando Cargo.toml para ' + CompressionName + '...');

    if not PatchWindowsCargoTemplate(ManifestTemplatePath, ManifestPath,
      COMPACT_ALGORITHM) then
      raise Exception.Create('Falha ao gerar Cargo.toml do Stub Windows.');

    if not FileExists(ManifestPath) then
      raise Exception.Create('Cargo.toml não foi gerado: ' + ManifestPath);

    EmitLog(Log, 'Cargo.toml gerado: ' + ManifestPath);
    EmitLog(Log, 'Cargo.toml | algoritmo=' + CompressionDisplayName +
      ' | opt-level=' + OptLevelDisplay +
      ' | lto=' + LtoDisplay);

    ResInfo := FResWindows.GetResInputs();

    if not PatchWindowsBuildTemplate(BuildTemplate, BuildGenerated,
      StubImageBase, ResInfo) then
      raise Exception.Create('Falha ao gerar build.rs do Stub Windows.');

    EmitLog(Log, 'Compilando Stub Windows (' + RUST_WIN_TARGET +
      ' via cargo-xwin)...');
    if not CompilarStubWindows(ManifestPath, CompilerOutput) then
      raise Exception.Create('Falha ao compilar Stub Windows.' +
        LineEnding + CompilerOutput + LineEnding +
        'Verifique: rustup target add x86_64-pc-windows-msvc --toolchain stable e cargo-xwin.');

    if not FileExists(RustBinary) then
      raise Exception.Create('Cargo não gerou o Stub Windows: ' + RustBinary);

    if StripStubEnabled then
    begin
      EmitLog(Log, 'Removendo metadados do Stub...');
      if not RemoverMetadados(RustBinary, StripOutput) then
        EmitLog(Log, 'Aviso: strip falhou: ' + StripOutput);
    end
    else
      EmitLog(Log, 'Strip do Stub desativado.');

    Stub := LerArquivo(RustBinary);
    if Length(Stub) = 0 then
      raise Exception.Create('Stub Windows vazio.');

    { O SECRET_ENC é fechado depois da compilação, quando o hash de .text já é
      conhecido. O Stub refaz a mesma derivação em runtime. }
    if not PEFindTextSection(Stub, TextOffset, TextTamanho) then
      raise Exception.Create('Seção .text não localizada no Stub compilado.');

    SetLength(TextHash, SECRET_SIZE);
    FillChar(TextHash[0], SECRET_SIZE, 0);

    if SELF_TEXT_HASH_BINDING then
    begin
      TextHash := SHA256Range(Stub, TextOffset, TextTamanho);
      EmitLog(Log, Format('Chave amarrada a .text: offset 0x%s, %d bytes.',
        [IntToHex(TextOffset, 8), TextTamanho]));
    end
    else
      EmitLog(Log, 'SELF_TEXT_HASH_BINDING=False: chave não amarrada ao código.');

    
    SetLength(VmSeed, SECRET_SIZE);
    for Idx := 0 to SECRET_SIZE - 1 do
      VmSeed[Idx] := byte((VmBuild.SeedSalt[Idx div 8] shr ((Idx mod 8) * 8)) and
        $FF) xor TextHash[Idx];

    VmMix := ExecutarProgramaMix(VmBuild, VmSeed);
    if Length(VmMix) <> SECRET_SIZE then
      raise Exception.Create('Programa de derivação da VM não produziu 32 bytes.');

    SetLength(SecretEncFinal, SECRET_SIZE);
    for Idx := 0 to SECRET_SIZE - 1 do
      SecretEncFinal[Idx] := Secret[Idx] xor SecretMask[Idx] xor VmMix[Idx];

    PatchSecretEncNoStub(Stub, SecretEncPadrao, SecretEncFinal,
      TextOffset, TextTamanho);
    EmitLog(Log, 'SECRET_ENC definitivo gravado no Stub compilado.');

    EmitLog(Log, 'Montando PE Casulo final...');
    CriarArquivoFinalWindows(SaidaPath, Stub, nil);

    if (not FileExists(SaidaPath)) or (GetFileSizeByName(SaidaPath) <= 0) then
      raise Exception.Create('Arquivo Windows final não foi criado corretamente.');

    Success := True;
    Result := True;
    EndTime := Now;
    EmitLog(Log, '========================================');
    EmitLog(Log, 'EMPACOTAMENTO WINDOWS CONCLUÍDO');
    EmitLog(Log, '--- BUILD EFETIVO ---');
    EmitLog(Log, 'Target: ' + RUST_WIN_TARGET);
    EmitLog(Log, 'Compressão: ' + CompressionDisplayName);
    EmitLog(Log, 'opt-level: ' + OptLevelDisplay);
    EmitLog(Log, 'LTO: ' + LtoDisplay);
    EmitLog(Log, 'Strip Cargo: true');
    EmitLog(Log, 'Strip pós-build: ' + BoolToStr(StripStubEnabled, True));
    EmitLog(Log, 'Execução em memória: ' + BoolToStr(ExecInMemory, True));
    EmitLog(Log, 'Demand paging efetivo: ' +
      BoolToStr(WINDOWS_DEMAND_PAGING and ExecInMemory, True));
    EmitLog(Log, 'Self .text hash binding: ' +
      BoolToStr(SELF_TEXT_HASH_BINDING, True));
    EmitLog(Log, '---------------------');
    EmitLog(Log, Format('Payload original: %d bytes', [OriginalSize]));
    EmitLog(Log, Format('Payload %s: %d bytes',
      [CompressionName, CompressedSize]));
    EmitLog(Log, Format('Chunks criptográficos: %d', [Length(Magics)]));
    EmitLog(Log, Format('Fragmentos RCDATA físicos: %d + 1 manifest (ID %d)',
      [Length(RcDataFragmentIds), ManifestRcDataId]));
    EmitLog(Log, Format('Stub Windows com RCDATA: %d bytes', [Length(Stub)]));
    EmitLog(Log, 'Stub ImageBase: 0x' + IntToHex(StubImageBase, 16));
    if Rebased then
      EmitLog(Log, 'Payload ImageBase: 0x' + IntToHex(PayloadNewBase, 16));
    EmitLog(Log, Format('Saída: %s (%d bytes)',
      [SaidaPath, GetFileSizeByName(SaidaPath)]));
    EmitLog(Log, Format('Tempo: %s',
      [FormatDateTime('hh:nn:ss', EndTime - StartTime)]));
    if SELF_TEXT_HASH_BINDING then
      EmitLog(Log,
        'VM: derivação de chave amarrada ao hash de .text + gate de execução, sem JIT.')
    else
      EmitLog(Log, 'VM: derivação de chave por salt do build + gate de execução, sem JIT.');
    if ExecInMemory then
    begin
      EmitLog(Log, 'Host da VM: mapeamento manual em memória (loader.rs).');
      if WINDOWS_DEMAND_PAGING then
        EmitLog(Log, 'Paginação sob demanda: ATIVA — .text da payload cifrado ' +
          'com chave efêmera, decifrado página a página por VEH.')
      else
        EmitLog(Log, 'Paginação sob demanda: desativada.');
    end
    else
      EmitLog(Log, 'Host da VM: extração temporária + CreateProcess ' +
        '(arquivo com DACL restrita, sem compartilhamento de escrita e ' +
        'exclusão automática no fechamento).');
    EmitLog(Log, '========================================');
  except
    on E: Exception do
    begin
      Result := False;
      Success := False;
      EmitLog(Log, 'ERRO WINDOWS: ' + E.Message);
      Erro := E.Message;
    end;
  end;

  try
    if (CompressedPath <> '') and FileExists(CompressedPath) then
      DeleteFile(CompressedPath);
    if (TempPayloadPath <> '') and FileExists(TempPayloadPath) then
      DeleteFile(TempPayloadPath);
    if (RustBinary <> '') and FileExists(RustBinary) then
      DeleteFile(RustBinary);
    { main.rs e exec_vm.rs são artefatos do build; loader.rs permanece estático. }
    if (StubGenerated <> '') and FileExists(StubGenerated) then
      DeleteFile(StubGenerated);
    if (ExecVmGenerated <> '') and FileExists(ExecVmGenerated) then
      DeleteFile(ExecVmGenerated);
    if (ManifestPath <> '') and FileExists(ManifestPath) then
      DeleteFile(ManifestPath);
    if (BuildGenerated <> '') and FileExists(BuildGenerated) then
      DeleteFile(BuildGenerated);
    if (RcDataDir <> '') or (RcScriptPath <> '') then
      LimparRcDataWindows(RcDataDir, RcScriptPath);
  except
    on E: Exception do
      EmitLog(Log, 'Aviso na limpeza Windows: ' + E.Message);
  end;

  if Length(Secret) > 0 then FillChar(Secret[0], Length(Secret), 0);
  if Length(CompressedPayload) > 0 then
    FillChar(CompressedPayload[0], Length(CompressedPayload), 0);
  if Length(PackedRegion) > 0 then
    FillChar(PackedRegion[0], Length(PackedRegion), 0);
  if Length(Stub) > 0 then FillChar(Stub[0], Length(Stub), 0);
  if Length(Magics) > 0 then
    FillChar(Magics[0], Length(Magics) * SizeOf(QWord), 0);
  if Length(RcDataFragmentIds) > 0 then
    FillChar(RcDataFragmentIds[0], Length(RcDataFragmentIds) * SizeOf(word), 0);
  if Length(FragLabel) > 0 then FillChar(FragLabel[0], Length(FragLabel), 0);
  if Length(MetaLabel) > 0 then FillChar(MetaLabel[0], Length(MetaLabel), 0);
  if Length(SecretMask) > 0 then FillChar(SecretMask[0], Length(SecretMask), 0);
  if Length(SecretEncFinal) > 0 then
    FillChar(SecretEncFinal[0], Length(SecretEncFinal), 0);
  if Length(VmMix) > 0 then FillChar(VmMix[0], Length(VmMix), 0);
  if Length(VmSeed) > 0 then FillChar(VmSeed[0], Length(VmSeed), 0);
  if Length(TextHash) > 0 then FillChar(TextHash[0], Length(TextHash), 0);
  if Length(VmBuild.MixCode) > 0 then
    FillChar(VmBuild.MixCode[0], Length(VmBuild.MixCode), 0);
  if Length(VmBuild.MixOps) > 0 then
    FillChar(VmBuild.MixOps[0], Length(VmBuild.MixOps) * SizeOf(TMixOp), 0);

  if Success then
    EmitLog(Log, '========== WINDOWS FINALIZADO COM SUCESSO ==========')
  else
    EmitLog(Log, '========== WINDOWS FINALIZADO COM ERRO ==========');
end;

end.
