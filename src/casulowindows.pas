unit CasuloWindows;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, Process, FileUtil, DCPsha256,
  Packer, PEUtils, CasuloConfig, CasuloCommon, Dialogs;

type
  TRcDataIdArray = array of word;

  TVmOpcodes = record
    MovImm, XorImm, AddImm, MulImm, RolImm, MixReg: byte;
    CmpImm, Jnz, HostCall, Emit, Halt: byte;
    LoadEnc, LoadMask, LoadMix, XorReg, StoreOut: byte;
    IncIndex, CmpIndex, SecretJnz, SecretHalt: byte;
    VerifyGate, ExecPayload: byte;
  end;

  TMixOpKind = (mokXor, mokAdd, mokMul, mokRol, mokMixReg);

  TMixOp = record
    Kind: TMixOpKind;
    Rd, Rs, Bits: byte;
    Imm: QWord;
  end;

  TMixOpArray = array of TMixOp;

  TVmBuild = record
    Ops: TVmOpcodes;
    ProgKey, ProgStride, ProgMul: QWord;
    GateK1, GateK2, GateK3, GateInitDelta: QWord;
    GateR1, GateR2: byte;
    SeedSalt: array[0..3] of QWord;
    MixOps: TMixOpArray;
    MixCode, GateCode, SecretCode: TBytes;
  end;

function PEHasStaticTLS(const FileName: string): boolean;
function PECountRelocations(const FileName: string): integer;
function DecidirModoExecucaoWindows(const PayloadPath: string;
  const PEInfo: TPE64Info; out Motivo: string): boolean;

procedure GerarVmBuild(out VM: TVmBuild);
function ExecutarProgramaMix(const VM: TVmBuild; const Seed: TBytes): TBytes;

function SHA256Range(const Dados: TBytes; Offset, Tamanho: longword): TBytes;
function PEFindTextSection(const Img: TBytes; out Offset, Tamanho: longword): boolean;
procedure PatchSecretEncNoStub(var Stub: TBytes; const Padrao, ValorFinal: TBytes;
  TextOffset, TextTamanho: longword);

function PatchExecVmTemplateWindows(const TemplatePath, OutputPath: string;
  const VM: TVmBuild): boolean;
function PatchStubTemplateWindows(const TemplatePath, OutputPath: string;
  const Magics: TQWordArray; FooterMagic: QWord; const FragLabel, MetaLabel: TBytes;
  Subsystem: word; ExecInMemory: boolean; CompressionAlgorithm: integer;
  ManifestRcDataId: word; const VM: TVmBuild;
  out SecretEncPadrao, SecretMask: TBytes): boolean;


function PatchWindowsBuildTemplate(const TemplatePath: string;
  const OutputPath: string; ImageBase: QWord; const ResInfo: TStringList): boolean;


function CompilarStubWindows(const ManifestPath: string; out Saida: string): boolean;

procedure LimparRcDataWindows(const RcDataDir, RcScriptPath: string);
function PrepararRcDataFragmentadoWindows(const PackedRegion: TBytes;
  const RcDataDir, RcScriptPath: string; out ManifestId: word;
  out FragmentIds: TRcDataIdArray): boolean;

procedure CriarArquivoFinalWindows(const ArquivoSaida: string;
  const Stub, PackedRegion: TBytes);

function PatchWindowsCargoTemplate(const TemplatePath: string;
  const OutputPath: string; CompressionAlgorithm: integer): boolean;

function GetRustDecompressorCode(CompressionAlgorithm: integer): string;

implementation

const
  VM_REG_COUNT = 4;
  VM_SECRET_SIZE = 32;
  VM_MIX_MIN_OPS = 24;
  VM_MIX_MAX_OPS = 40;

function GetRustDecompressorCode(CompressionAlgorithm: integer): string;
begin
  case CompressionAlgorithm of

    COMPACT_ZSTD:
    begin
      Result :=
        '#[inline]' + LineEnding +
        'fn decompress_payload(input: &[u8], final_size: usize) -> Option<Vec<u8>> {' +
        LineEnding + '    let mut out = vec![0u8; final_size];' +
        LineEnding + '    let mut fd = ruzstd::decoding::FrameDecoder::new();' +
        LineEnding + '' + LineEnding +
        '    let n = fd.decode_all(input, &mut out).ok()?;' +
        LineEnding + '' + LineEnding + '    if n != final_size {' +
        LineEnding + '        return None;' + LineEnding + '    }' +
        LineEnding + '' + LineEnding + '    Some(out)' + LineEnding + '}' + LineEnding;
    end;

    COMPACT_BROTLI:
    begin
      Result :=
        '#[inline]' + LineEnding +
        'fn decompress_payload(input: &[u8], final_size: usize) -> Option<Vec<u8>> {' +
        LineEnding + '    let cursor = std::io::Cursor::new(input);' +
        LineEnding + '' + LineEnding +
        '    let mut dec = brotli_decompressor::Decompressor::new(' +
        LineEnding + '        cursor,' + LineEnding + '        4096' +
        LineEnding + '    );' + LineEnding + '' + LineEnding +
        '    let mut out = vec![0u8; final_size];' + LineEnding +
        '' + LineEnding + '    dec.read_exact(&mut out).ok()?;' +
        LineEnding + '' + LineEnding + '    let mut extra = [0u8; 1];' +
        LineEnding + '' + LineEnding + '    match dec.read(&mut extra) {' +
        LineEnding + '        Ok(0) => Some(out),' + LineEnding +
        '' + LineEnding + '        _ => {' + LineEnding +
        '            secure_zero(&mut out);' + LineEnding +
        '            None' + LineEnding + '        }' + LineEnding +
        '    }' + LineEnding + '}' + LineEnding;
    end;

    else
      raise Exception.CreateFmt('Algoritmo de compressão inválido: %d',
        [CompressionAlgorithm]);
  end;
end;

function PatchWindowsCargoTemplate(const TemplatePath: string;
  const OutputPath: string; CompressionAlgorithm: integer): boolean;
const
  ALGORITHM_MARKER = '@@@ALGORITHM_MODE@@@';
  OPT_LEVEL_MARKER = '@@OPT_LEVEL@@';
  LTO_CFG_MARKER = '@@LTO_CFG@@';
var
  FS: TStringList;
  Source: string;
  Dependency: string;
  LtoLiteral: string;
begin
  Result := False;

  if not FileExists(TemplatePath) then
    raise Exception.Create('Template Cargo.toml.in não encontrado: ' +
      TemplatePath);

  case CompressionAlgorithm of

    COMPACT_ZSTD:
      Dependency :=
        'ruzstd = { version = "0.9.0", default-features = false }';

    COMPACT_BROTLI:
      Dependency :=
        'brotli-decompressor = { version = "6.0.0" }';

    else
      raise Exception.CreateFmt('Algoritmo de compressão inválido: %d',
        [CompressionAlgorithm]);
  end;


  { TOML usa booleanos em minúsculas. }

  if LTO_CONFIG then
    LtoLiteral := 'true'
  else
    LtoLiteral := 'false';

  FS := TStringList.Create;

  try
    FS.LoadFromFile(TemplatePath);

    Source := FS.Text;

    if Pos(ALGORITHM_MARKER, Source) = 0 then
      raise Exception.Create('Marcador ' + ALGORITHM_MARKER +
        ' não encontrado no Cargo.toml.in.');

    if Pos(OPT_LEVEL_MARKER, Source) = 0 then
      raise Exception.Create('Marcador ' + OPT_LEVEL_MARKER +
        ' não encontrado no Cargo.toml.in.');

    if Pos(LTO_CFG_MARKER, Source) = 0 then
      raise Exception.Create('Marcador ' + LTO_CFG_MARKER +
        ' não encontrado no Cargo.toml.in.');

    Source := StringReplace(Source, ALGORITHM_MARKER, Dependency, [rfReplaceAll]);

    Source := StringReplace(Source, OPT_LEVEL_MARKER, OPT_LEVEL_CONFIG,
      [rfReplaceAll]);

    Source := StringReplace(Source, LTO_CFG_MARKER, LtoLiteral, [rfReplaceAll]);

    FS.Text := Source;
    FS.SaveToFile(OutputPath);

    Result := True;

  finally
    FS.Free;
  end;
end;

function PEHasStaticTLS(const FileName: string): boolean;
var
  FS: TFileStream;
  PEOff, OptOff, SecTable, TLSOff: int64;
  NumSec, SizeOpt: word;
  TLSRva, TLSSize, ZeroFill: longword;
  StartVA, EndVA: QWord;

  function RdU16(Off: int64): word;
  begin
    Result := 0;
    if (Off < 0) or (Off + 2 > FS.Size) then Exit;
    FS.Position := Off;
    FS.ReadBuffer(Result, 2);
  end;

  function RdU32(Off: int64): longword;
  begin
    Result := 0;
    if (Off < 0) or (Off + 4 > FS.Size) then Exit;
    FS.Position := Off;
    FS.ReadBuffer(Result, 4);
  end;

  function RdU64(Off: int64): QWord;
  begin
    Result := 0;
    if (Off < 0) or (Off + 8 > FS.Size) then Exit;
    FS.Position := Off;
    FS.ReadBuffer(Result, 8);
  end;

  
  function RvaToOffset(ATable: int64; ACount: integer; Rva: longword): int64;
  var
    I: integer;
    SOff: int64;
    VA, VSize, RawSize, RawPtr, Span: longword;
  begin
    Result := -1;
    for I := 0 to ACount - 1 do
    begin
      SOff := ATable + int64(I) * 40;
      VSize := RdU32(SOff + 8);
      VA := RdU32(SOff + 12);
      RawSize := RdU32(SOff + 16);
      RawPtr := RdU32(SOff + 20);

      if VSize > RawSize then Span := VSize
      else
        Span := RawSize;
      if Span = 0 then Continue;

      if (Rva >= VA) and (Rva < VA + Span) then
      begin
        
        if (Rva - VA) >= RawSize then Exit;
        Result := int64(RawPtr) + int64(Rva - VA);
        Exit;
      end;
    end;
  end;

begin
  Result := False;
  if not FileExists(FileName) then Exit;

  FS := TFileStream.Create(FileName, fmOpenRead or fmShareDenyWrite);
  try
    if FS.Size < $200 then Exit;
    if RdU16(0) <> $5A4D then Exit;

    PEOff := RdU32($3C);
    if RdU32(PEOff) <> $00004550 then Exit;
    if RdU16(PEOff + 4) <> $8664 then Exit;

    NumSec := RdU16(PEOff + 6);
    SizeOpt := RdU16(PEOff + 20);
    OptOff := PEOff + 24;

    if RdU16(OptOff) <> $020B then Exit;
    if NumSec = 0 then Exit;

    
    if RdU32(OptOff + 108) < 10 then Exit;

    TLSRva := RdU32(OptOff + 112 + 9 * 8);
    TLSSize := RdU32(OptOff + 112 + 9 * 8 + 4);
    if (TLSRva = 0) or (TLSSize < 40) then Exit;

    SecTable := OptOff + SizeOpt;
    TLSOff := RvaToOffset(SecTable, NumSec, TLSRva);
    if TLSOff < 0 then Exit;

    
    StartVA := RdU64(TLSOff);
    EndVA := RdU64(TLSOff + 8);
    ZeroFill := RdU32(TLSOff + 32);

    Result := (EndVA > StartVA) or (ZeroFill > 0);
  finally
    FS.Free;
  end;
end;

{ Conta fixups reais da tabela de relocations. Entradas ABSOLUTE são apenas
  padding e não tornam a imagem relocável. }

function PECountRelocations(const FileName: string): integer;
var
  FS: TFileStream;
  PEOff, OptOff, SecTable, RelOff, Cursor: int64;
  NumSec, SizeOpt: word;
  RelRva, RelSize, BlocoSize: longword;
  Entradas, I: integer;
  Entrada: word;

  function RdU16(Off: int64): word;
  begin
    Result := 0;
    if (Off < 0) or (Off + 2 > FS.Size) then Exit;
    FS.Position := Off;
    FS.ReadBuffer(Result, 2);
  end;

  function RdU32(Off: int64): longword;
  begin
    Result := 0;
    if (Off < 0) or (Off + 4 > FS.Size) then Exit;
    FS.Position := Off;
    FS.ReadBuffer(Result, 4);
  end;

  function RvaToOffset(ATable: int64; ACount: integer; Rva: longword): int64;
  var
    J: integer;
    SOff: int64;
    VA, VSize, RawSize, RawPtr, Span: longword;
  begin
    Result := -1;
    for J := 0 to ACount - 1 do
    begin
      SOff := ATable + int64(J) * 40;
      VSize := RdU32(SOff + 8);
      VA := RdU32(SOff + 12);
      RawSize := RdU32(SOff + 16);
      RawPtr := RdU32(SOff + 20);

      if VSize > RawSize then Span := VSize
      else
        Span := RawSize;
      if Span = 0 then Continue;

      if (Rva >= VA) and (Rva < VA + Span) then
      begin
        if (Rva - VA) >= RawSize then Exit;
        Result := int64(RawPtr) + int64(Rva - VA);
        Exit;
      end;
    end;
  end;

begin
  Result := 0;
  if not FileExists(FileName) then Exit;

  FS := TFileStream.Create(FileName, fmOpenRead or fmShareDenyWrite);
  try
    if FS.Size < $200 then Exit;
    if RdU16(0) <> $5A4D then Exit;

    PEOff := RdU32($3C);
    if RdU32(PEOff) <> $00004550 then Exit;
    if RdU16(PEOff + 4) <> $8664 then Exit;

    NumSec := RdU16(PEOff + 6);
    SizeOpt := RdU16(PEOff + 20);
    OptOff := PEOff + 24;

    if RdU16(OptOff) <> $020B then Exit;
    if NumSec = 0 then Exit;

    
    if RdU32(OptOff + 108) < 6 then Exit;

    RelRva := RdU32(OptOff + 112 + 5 * 8);
    RelSize := RdU32(OptOff + 112 + 5 * 8 + 4);
    if (RelRva = 0) or (RelSize < 8) then Exit;

    SecTable := OptOff + SizeOpt;
    RelOff := RvaToOffset(SecTable, NumSec, RelRva);
    if RelOff < 0 then Exit;

    Cursor := 0;
    while Cursor + 8 <= int64(RelSize) do
    begin
      BlocoSize := RdU32(RelOff + Cursor + 4);
      
      if (BlocoSize < 8) or (Cursor + int64(BlocoSize) > int64(RelSize)) then Break;

      Entradas := (integer(BlocoSize) - 8) div 2;
      for I := 0 to Entradas - 1 do
      begin
        Entrada := RdU16(RelOff + Cursor + 8 + int64(I) * 2);
        if (Entrada shr 12) <> 0 then
          Inc(Result);
      end;

      Cursor := Cursor + int64(BlocoSize);
    end;
  finally
    FS.Free;
  end;
end;

function DecidirModoExecucaoWindows(const PayloadPath: string;
  const PEInfo: TPE64Info; out Motivo: string): boolean;
begin
  if not WINDOWS_EXEC_IN_MEMORY then
  begin
    Motivo := 'WINDOWS_EXEC_IN_MEMORY=False: modo disco forçado por configuração.';
    Exit(False);
  end;

  if PEHasStaticTLS(PayloadPath) then
  begin
    Motivo := 'Payload usa TLS estático (thread_local): modo disco obrigatório, ' +
      'threads criadas pela payload quebrariam no mapeamento manual.';
    Exit(False);
  end;

  
  if PECountRelocations(PayloadPath) = 0 then
  begin
    if PEInfo.HasRelocations then
      Motivo := 'Payload tem diretório de relocations VAZIO (nenhum fixup real): ' +
        'só carrega na ImageBase preferida. Modo disco.'
    else
      Motivo := 'Payload sem relocations: só carrega na ImageBase preferida, ' +
        'o que não é garantido em runtime. Modo disco.';
    Exit(False);
  end;


  Motivo := 'Payload compatível: mapeamento manual em memória.';
  Result := True;
end;

{ A VM é gerada por build; opcodes, constantes e bytecode mudam juntos. }

{$PUSH}{$Q-}{$R-}

function RolQ(V: QWord; Bits: byte): QWord;
begin
  Bits := Bits and 63;
  if Bits = 0 then
    Exit(V);
  Result := (V shl Bits) or (V shr (64 - Bits));
end;

{ Deve permanecer idêntico ao keystream_byte() de exec_vm.rs. }

function VmKeystreamByte(const VM: TVmBuild; Index: integer): byte;
var
  X: QWord;
begin
  X := VM.ProgKey xor (QWord(Index) * VM.ProgStride);
  X := X xor (X shr 33);
  X := X * VM.ProgMul;
  X := X xor (X shr 29);
  Result := byte(X and $FF);
end;

function ExecutarProgramaMix(const VM: TVmBuild; const Seed: TBytes): TBytes;
var
  R: array[0..VM_REG_COUNT - 1] of QWord;
  I, J: integer;
  Op: TMixOp;
begin
  if Length(Seed) <> VM_SECRET_SIZE then
    raise Exception.Create('Semente da VM deve ter 32 bytes.');

  for I := 0 to VM_REG_COUNT - 1 do
  begin
    R[I] := 0;
    for J := 7 downto 0 do
      R[I] := (R[I] shl 8) or QWord(Seed[I * 8 + J]);
  end;

  for I := 0 to Length(VM.MixOps) - 1 do
  begin
    Op := VM.MixOps[I];
    case Op.Kind of
      mokXor: R[Op.Rd] := R[Op.Rd] xor Op.Imm;
      mokAdd: R[Op.Rd] := R[Op.Rd] + Op.Imm;
      mokMul: R[Op.Rd] := R[Op.Rd] * Op.Imm;
      mokRol: R[Op.Rd] := RolQ(R[Op.Rd], Op.Bits);
      mokMixReg: R[Op.Rd] := R[Op.Rd] xor RolQ(R[Op.Rs], Op.Bits);
    end;
  end;

  SetLength(Result, VM_SECRET_SIZE);
  for I := 0 to VM_REG_COUNT - 1 do
    for J := 0 to 7 do
      Result[I * 8 + J] := byte((R[I] shr (J * 8)) and $FF);

  FillChar(R[0], SizeOf(R), 0);
end;

{$POP}

function RandQWord: QWord;
var
  B: TBytes;
  I: integer;
begin
  B := RandomBytes(8);
  if Length(B) <> 8 then
    raise Exception.Create('Falha ao gerar valor aleatório de 64 bits.');
  Result := 0;
  for I := 7 downto 0 do
    Result := (Result shl 8) or QWord(B[I]);
  FillChar(B[0], Length(B), 0);
end;

function RandByteValue: byte;
var
  B: TBytes;
begin
  B := RandomBytes(1);
  if Length(B) <> 1 then
    raise Exception.Create('Falha ao gerar byte aleatório.');
  Result := B[0];
  B[0] := 0;
end;

function RandRotBits: byte;
begin
  Result := 1 + (RandByteValue mod 63);
end;

{ Reserva $F1..$FF para valores especiais usados pela VM e pelos testes. }

procedure SortearBytesDistintos(Count: integer; out Valores: TBytes);
const
  POOL_SIZE = $F0;
var
  Pool, Entropia: TBytes;
  I, J: integer;
  T: byte;
begin
  if (Count < 1) or (Count > POOL_SIZE) then
    raise Exception.Create('Quantidade inválida de opcodes a sortear.');

  SetLength(Pool, POOL_SIZE);
  for I := 0 to POOL_SIZE - 1 do
    Pool[I] := byte(I + 1);

  Entropia := RandomBytes(POOL_SIZE * 2);

  for I := POOL_SIZE - 1 downto 1 do
  begin
    J := ((integer(Entropia[I * 2]) shl 8) or integer(Entropia[I * 2 + 1])) mod (I + 1);
    T := Pool[I];
    Pool[I] := Pool[J];
    Pool[J] := T;
  end;

  SetLength(Valores, Count);
  for I := 0 to Count - 1 do
    Valores[I] := Pool[I];

  FillChar(Pool[0], Length(Pool), 0);
  FillChar(Entropia[0], Length(Entropia), 0);
end;

procedure AppendByte(var B: TBytes; V: byte);
begin
  SetLength(B, Length(B) + 1);
  B[High(B)] := V;
end;

procedure AppendWordLE(var B: TBytes; V: word);
begin
  AppendByte(B, byte(V and $FF));
  AppendByte(B, byte((V shr 8) and $FF));
end;

procedure AppendQWordLE(var B: TBytes; V: QWord);
var
  I: integer;
begin
  for I := 0 to 7 do
    AppendByte(B, byte((V shr (I * 8)) and $FF));
end;

{ Fecha o programa com uma passada de difusão entre registradores. }

procedure GerarProgramaMix(var VM: TVmBuild);
var
  Total, I: integer;
  Op: TMixOp;
begin
  Total := VM_MIX_MIN_OPS + (integer(RandByteValue) mod
    (VM_MIX_MAX_OPS - VM_MIX_MIN_OPS + 1));

  SetLength(VM.MixOps, Total + VM_REG_COUNT);

  for I := 0 to Total - 1 do
  begin
    Op.Kind := TMixOpKind(RandByteValue mod 5);
    Op.Rd := byte(RandByteValue mod VM_REG_COUNT);
    Op.Rs := 0;
    Op.Bits := 0;
    Op.Imm := 0;

    case Op.Kind of
      mokXor, mokAdd:
        Op.Imm := RandQWord;
      mokMul:
        { Multiplicadores são sempre ímpares. }
        Op.Imm := RandQWord or 1;
      mokRol:
        Op.Bits := RandRotBits;
      mokMixReg:
      begin
        Op.Rs := byte((Op.Rd + 1 + (RandByteValue mod (VM_REG_COUNT - 1))) mod
          VM_REG_COUNT);
        Op.Bits := RandRotBits;
      end;
    end;

    VM.MixOps[I] := Op;
  end;

  
  for I := 0 to VM_REG_COUNT - 1 do
  begin
    Op.Kind := mokMixReg;
    Op.Rd := byte(I);
    Op.Rs := byte((I + 1) mod VM_REG_COUNT);
    Op.Bits := RandRotBits;
    Op.Imm := 0;
    VM.MixOps[Total + I] := Op;
  end;

  SetLength(VM.MixCode, 0);
  for I := 0 to Length(VM.MixOps) - 1 do
  begin
    Op := VM.MixOps[I];
    case Op.Kind of
      mokXor:
      begin
        AppendByte(VM.MixCode, VM.Ops.XorImm);
        AppendByte(VM.MixCode, Op.Rd);
        AppendQWordLE(VM.MixCode, Op.Imm);
      end;
      mokAdd:
      begin
        AppendByte(VM.MixCode, VM.Ops.AddImm);
        AppendByte(VM.MixCode, Op.Rd);
        AppendQWordLE(VM.MixCode, Op.Imm);
      end;
      mokMul:
      begin
        AppendByte(VM.MixCode, VM.Ops.MulImm);
        AppendByte(VM.MixCode, Op.Rd);
        AppendQWordLE(VM.MixCode, Op.Imm);
      end;
      mokRol:
      begin
        AppendByte(VM.MixCode, VM.Ops.RolImm);
        AppendByte(VM.MixCode, Op.Rd);
        AppendByte(VM.MixCode, Op.Bits);
      end;
      mokMixReg:
      begin
        AppendByte(VM.MixCode, VM.Ops.MixReg);
        AppendByte(VM.MixCode, Op.Rd);
        AppendByte(VM.MixCode, Op.Rs);
        AppendByte(VM.MixCode, Op.Bits);
      end;
    end;
  end;

  AppendByte(VM.MixCode, VM.Ops.Emit);
  AppendByte(VM.MixCode, VM.Ops.Halt);
end;

{ O gate usa as mesmas constantes compiladas no host Rust. }

procedure GerarProgramaGate(var VM: TVmBuild);
var
  PatchPos, FailPos: integer;
begin
  SetLength(VM.GateCode, 0);

  AppendByte(VM.GateCode, VM.Ops.XorImm);
  AppendByte(VM.GateCode, 0);
  AppendQWordLE(VM.GateCode, VM.GateK1);

  AppendByte(VM.GateCode, VM.Ops.RolImm);
  AppendByte(VM.GateCode, 0);
  AppendByte(VM.GateCode, VM.GateR1);

  AppendByte(VM.GateCode, VM.Ops.AddImm);
  AppendByte(VM.GateCode, 0);
  AppendQWordLE(VM.GateCode, VM.GateK2);

  AppendByte(VM.GateCode, VM.Ops.XorImm);
  AppendByte(VM.GateCode, 0);
  AppendQWordLE(VM.GateCode, VM.GateK3);

  AppendByte(VM.GateCode, VM.Ops.RolImm);
  AppendByte(VM.GateCode, 0);
  AppendByte(VM.GateCode, VM.GateR2);

  AppendByte(VM.GateCode, VM.Ops.HostCall);
  AppendByte(VM.GateCode, VM.Ops.VerifyGate);

  AppendByte(VM.GateCode, VM.Ops.CmpImm);
  AppendByte(VM.GateCode, 0);
  AppendQWordLE(VM.GateCode, 1);

  AppendByte(VM.GateCode, VM.Ops.Jnz);
  PatchPos := Length(VM.GateCode);
  AppendWordLE(VM.GateCode, 0);

  AppendByte(VM.GateCode, VM.Ops.HostCall);
  AppendByte(VM.GateCode, VM.Ops.ExecPayload);
  AppendByte(VM.GateCode, VM.Ops.Halt);

  FailPos := Length(VM.GateCode);
  AppendByte(VM.GateCode, VM.Ops.MovImm);
  AppendByte(VM.GateCode, 0);
  AppendQWordLE(VM.GateCode, 1);
  AppendByte(VM.GateCode, VM.Ops.Halt);

  if FailPos > High(word) then
    raise Exception.Create('Programa do gate grande demais para alvo de 16 bits.');

  VM.GateCode[PatchPos] := byte(FailPos and $FF);
  VM.GateCode[PatchPos + 1] := byte((FailPos shr 8) and $FF);
end;

procedure GerarProgramaSecret(var VM: TVmBuild);
begin
  SetLength(VM.SecretCode, 0);

  AppendByte(VM.SecretCode, VM.Ops.LoadEnc);
  AppendByte(VM.SecretCode, 0);

  AppendByte(VM.SecretCode, VM.Ops.LoadMask);
  AppendByte(VM.SecretCode, 1);

  AppendByte(VM.SecretCode, VM.Ops.XorReg);
  AppendByte(VM.SecretCode, 0);
  AppendByte(VM.SecretCode, 1);

  AppendByte(VM.SecretCode, VM.Ops.LoadMix);
  AppendByte(VM.SecretCode, 1);

  AppendByte(VM.SecretCode, VM.Ops.XorReg);
  AppendByte(VM.SecretCode, 0);
  AppendByte(VM.SecretCode, 1);

  AppendByte(VM.SecretCode, VM.Ops.StoreOut);
  AppendByte(VM.SecretCode, 0);

  AppendByte(VM.SecretCode, VM.Ops.IncIndex);

  AppendByte(VM.SecretCode, VM.Ops.CmpIndex);
  AppendByte(VM.SecretCode, VM_SECRET_SIZE);

  AppendByte(VM.SecretCode, VM.Ops.SecretJnz);
  AppendWordLE(VM.SecretCode, 0);   

  AppendByte(VM.SecretCode, VM.Ops.SecretHalt);
end;

procedure GerarVmBuild(out VM: TVmBuild);
var
  Codigos: TBytes;
  I: integer;
begin
  SortearBytesDistintos(22, Codigos);

  VM.Ops.MovImm := Codigos[0];
  VM.Ops.XorImm := Codigos[1];
  VM.Ops.AddImm := Codigos[2];
  VM.Ops.MulImm := Codigos[3];
  VM.Ops.RolImm := Codigos[4];
  VM.Ops.MixReg := Codigos[5];
  VM.Ops.CmpImm := Codigos[6];
  VM.Ops.Jnz := Codigos[7];
  VM.Ops.HostCall := Codigos[8];
  VM.Ops.Emit := Codigos[9];
  VM.Ops.Halt := Codigos[10];
  VM.Ops.LoadEnc := Codigos[11];
  VM.Ops.LoadMask := Codigos[12];
  VM.Ops.LoadMix := Codigos[13];
  VM.Ops.XorReg := Codigos[14];
  VM.Ops.StoreOut := Codigos[15];
  VM.Ops.IncIndex := Codigos[16];
  VM.Ops.CmpIndex := Codigos[17];
  VM.Ops.SecretJnz := Codigos[18];
  VM.Ops.SecretHalt := Codigos[19];
  VM.Ops.VerifyGate := Codigos[20];
  VM.Ops.ExecPayload := Codigos[21];

  VM.ProgKey := RandQWord;
  VM.ProgStride := RandQWord or 1;
  VM.ProgMul := RandQWord or 1;

  VM.GateK1 := RandQWord;
  VM.GateK2 := RandQWord;
  VM.GateK3 := RandQWord;
  VM.GateR1 := RandRotBits;
  VM.GateR2 := RandRotBits;

  
  repeat
    VM.GateInitDelta := RandQWord;
  until VM.GateInitDelta <> 0;

  for I := 0 to 3 do
    VM.SeedSalt[I] := RandQWord;

  GerarProgramaMix(VM);
  GerarProgramaGate(VM);
  GerarProgramaSecret(VM);

  FillChar(Codigos[0], Length(Codigos), 0);
end;

function SHA256Range(const Dados: TBytes; Offset, Tamanho: longword): TBytes;
var
  Hash: TDCP_sha256;
begin
  if (QWord(Offset) + QWord(Tamanho)) > QWord(Length(Dados)) then
    raise Exception.Create('Faixa fora do arquivo ao calcular SHA-256.');
  if Tamanho = 0 then
    raise Exception.Create('Faixa vazia ao calcular SHA-256.');

  SetLength(Result, 32);
  Hash := TDCP_sha256.Create(nil);
  try
    Hash.Init;
    Hash.Update(Dados[Offset], Tamanho);
    Hash.Final(Result[0]);
  finally
    Hash.Free;
  end;
end;

function LerU16(const B: TBytes; Offset: integer): word;
begin
  if (Offset < 0) or (Offset + 2 > Length(B)) then
    raise Exception.Create('Leitura de 16 bits fora do PE.');
  Result := word(B[Offset]) or (word(B[Offset + 1]) shl 8);
end;

function LerU32(const B: TBytes; Offset: integer): longword;
begin
  if (Offset < 0) or (Offset + 4 > Length(B)) then
    raise Exception.Create('Leitura de 32 bits fora do PE.');
  Result := longword(B[Offset]) or (longword(B[Offset + 1]) shl 8) or
    (longword(B[Offset + 2]) shl 16) or (longword(B[Offset + 3]) shl 24);
end;

{ Usa os mesmos campos do PE que o Stub consulta em runtime. }

function PEFindTextSection(const Img: TBytes; out Offset, Tamanho: longword): boolean;
var
  PeOff, Tabela, Entrada, I, Secoes, OptSize: integer;
  Nome: string;
  J: integer;
begin
  Result := False;
  Offset := 0;
  Tamanho := 0;

  if Length(Img) < $40 then
    Exit;
  if LerU16(Img, 0) <> $5A4D then
    Exit;

  PeOff := integer(LerU32(Img, $3C));
  if (PeOff <= 0) or (PeOff + 24 > Length(Img)) then
    Exit;
  if LerU32(Img, PeOff) <> $00004550 then
    Exit;

  Secoes := LerU16(Img, PeOff + 6);
  OptSize := LerU16(Img, PeOff + 20);
  Tabela := PeOff + 24 + OptSize;

  for I := 0 to Secoes - 1 do
  begin
    Entrada := Tabela + I * 40;
    if Entrada + 40 > Length(Img) then
      Exit;

    Nome := '';
    for J := 0 to 7 do
      if Img[Entrada + J] = 0 then
        Break
      else
        Nome := Nome + Chr(Img[Entrada + J]);

    if Nome = '.text' then
    begin
      Tamanho := LerU32(Img, Entrada + 16);   
      Offset := LerU32(Img, Entrada + 20);    
      Result := (Tamanho > 0) and (Offset > 0) and
        ((QWord(Offset) + QWord(Tamanho)) <= QWord(Length(Img)));
      Exit;
    end;
  end;
end;

{ O marcador deve ocorrer uma única vez e fora de .text. }

procedure PatchSecretEncNoStub(var Stub: TBytes; const Padrao, ValorFinal: TBytes;
  TextOffset, TextTamanho: longword);
var
  I, J, Encontrado, Ocorrencias: integer;
  Igual: boolean;
begin
  if (Length(Padrao) <> VM_SECRET_SIZE) or (Length(ValorFinal) <> VM_SECRET_SIZE) then
    raise Exception.Create('Tamanho inválido no patch do SECRET_ENC.');

  Encontrado := -1;
  Ocorrencias := 0;

  for I := 0 to Length(Stub) - VM_SECRET_SIZE do
  begin
    Igual := True;
    for J := 0 to VM_SECRET_SIZE - 1 do
      if Stub[I + J] <> Padrao[J] then
      begin
        Igual := False;
        Break;
      end;

    if Igual then
    begin
      Inc(Ocorrencias);
      if Encontrado < 0 then
        Encontrado := I;
    end;
  end;

  if Ocorrencias = 0 then
    raise Exception.Create(
      'SECRET_ENC não localizado no Stub compilado. O cargo pode ter ' +
      'reorganizado o literal: verifique se o build é release e sem LTO ' +
      'agressivo o bastante para fatiar o array.');
  if Ocorrencias > 1 then
    raise Exception.Create('SECRET_ENC ambíguo no Stub compilado.');

  if (QWord(Encontrado) + VM_SECRET_SIZE > QWord(TextOffset)) and
    (QWord(Encontrado) < QWord(TextOffset) + QWord(TextTamanho)) then
    raise Exception.Create(
      'SECRET_ENC caiu dentro de .text: o patch invalidaria o próprio hash.');

  for J := 0 to VM_SECRET_SIZE - 1 do
    Stub[Encontrado + J] := ValorFinal[J];
end;

function PatchExecVmTemplateWindows(const TemplatePath, OutputPath: string;
  const VM: TVmBuild): boolean;
var
  FS: TStringList;
  Source: string;


  function ProgramaParaRust(const B: TBytes): string;
  var
    K: integer;
  begin
    Result := '';
    for K := 0 to Length(B) - 1 do
    begin
      if K > 0 then
        Result := Result + ', ';
      if (K mod 12) = 0 then
        Result := Result + LineEnding + '    ';
      Result := Result + Format('0x%.2x', [B[K] xor VmKeystreamByte(VM, K)]);
    end;
  end;

  procedure Troca(const Marcador, Valor: string);
  begin
    if Pos(Marcador, Source) = 0 then
      raise Exception.Create('Marcador ' + Marcador +
        ' não encontrado no exec_vm.rs.in.');
    Source := StringReplace(Source, Marcador, Valor, [rfReplaceAll]);
  end;

  function Hex2(V: byte): string;
  begin
    Result := IntToHex(V, 2);
  end;

begin
  Result := False;

  if (Length(VM.MixCode) = 0) or (Length(VM.GateCode) = 0) or
    (Length(VM.SecretCode) = 0) then
    raise Exception.Create('Programas da VM não foram gerados.');

  FS := TStringList.Create;
  try
    FS.LoadFromFile(TemplatePath);
    Source := FS.Text;

    Troca('@@OP_MOV_IMM@@', Hex2(VM.Ops.MovImm));
    Troca('@@OP_XOR_IMM@@', Hex2(VM.Ops.XorImm));
    Troca('@@OP_ADD_IMM@@', Hex2(VM.Ops.AddImm));
    Troca('@@OP_MUL_IMM@@', Hex2(VM.Ops.MulImm));
    Troca('@@OP_ROL_IMM@@', Hex2(VM.Ops.RolImm));
    Troca('@@OP_MIX_REG@@', Hex2(VM.Ops.MixReg));
    Troca('@@OP_CMP_IMM@@', Hex2(VM.Ops.CmpImm));
    Troca('@@OP_JNZ@@', Hex2(VM.Ops.Jnz));
    Troca('@@OP_HOST_CALL@@', Hex2(VM.Ops.HostCall));
    Troca('@@OP_EMIT@@', Hex2(VM.Ops.Emit));
    Troca('@@OP_HALT@@', Hex2(VM.Ops.Halt));

    Troca('@@SOP_LOAD_ENC@@', Hex2(VM.Ops.LoadEnc));
    Troca('@@SOP_LOAD_MASK@@', Hex2(VM.Ops.LoadMask));
    Troca('@@SOP_LOAD_MIX@@', Hex2(VM.Ops.LoadMix));
    Troca('@@SOP_XOR_REG@@', Hex2(VM.Ops.XorReg));
    Troca('@@SOP_STORE_OUT@@', Hex2(VM.Ops.StoreOut));
    Troca('@@SOP_INC_INDEX@@', Hex2(VM.Ops.IncIndex));
    Troca('@@SOP_CMP_INDEX@@', Hex2(VM.Ops.CmpIndex));
    Troca('@@SOP_JNZ@@', Hex2(VM.Ops.SecretJnz));
    Troca('@@SOP_HALT@@', Hex2(VM.Ops.SecretHalt));

    Troca('@@HOST_VERIFY_GATE@@', Hex2(VM.Ops.VerifyGate));
    Troca('@@HOST_EXEC_PAYLOAD@@', Hex2(VM.Ops.ExecPayload));

    Troca('@@PROG_KEY@@', IntToHex(VM.ProgKey, 16));
    Troca('@@PROG_STRIDE@@', IntToHex(VM.ProgStride, 16));
    Troca('@@PROG_MUL@@', IntToHex(VM.ProgMul, 16));

    Troca('@@GATE_K1@@', IntToHex(VM.GateK1, 16));
    Troca('@@GATE_K2@@', IntToHex(VM.GateK2, 16));
    Troca('@@GATE_K3@@', IntToHex(VM.GateK3, 16));
    Troca('@@GATE_INIT_DELTA@@', IntToHex(VM.GateInitDelta, 16));
    Troca('@@GATE_R1@@', IntToStr(VM.GateR1));
    Troca('@@GATE_R2@@', IntToStr(VM.GateR2));

    Troca('@@MIX_PROGRAM_LEN@@', IntToStr(Length(VM.MixCode)));
    Troca('@@MIX_PROGRAM@@', ProgramaParaRust(VM.MixCode));
    Troca('@@GATE_PROGRAM_LEN@@', IntToStr(Length(VM.GateCode)));
    Troca('@@GATE_PROGRAM@@', ProgramaParaRust(VM.GateCode));
    Troca('@@SECRET_PROGRAM_LEN@@', IntToStr(Length(VM.SecretCode)));
    Troca('@@SECRET_PROGRAM@@', ProgramaParaRust(VM.SecretCode));

    FS.Text := Source;
    FS.SaveToFile(OutputPath);
    Result := True;
  finally
    FS.Free;
    Source := '';
  end;
end;

{ Gera main.rs com um marcador temporário para SECRET_ENC, corrigido após o build. }

function PatchStubTemplateWindows(const TemplatePath, OutputPath: string;
  const Magics: TQWordArray; FooterMagic: QWord; const FragLabel, MetaLabel: TBytes;
  Subsystem: word; ExecInMemory: boolean; CompressionAlgorithm: integer;
  ManifestRcDataId: word; const VM: TVmBuild;
  out SecretEncPadrao, SecretMask: TBytes): boolean;
const
  SECRET_ENC_MARKER = '@@SECRET_ENC@@';
  SECRET_MASK_MARKER = '@@SECRET_MASK@@';
  SEED_SALT_MARKER = '@@SEED_SALT@@';
  MASK_FROM_TEXT_MARKER = '@@MASK_FROM_TEXT@@';
  MAGIC_COUNT_MARKER = '@@MAGIC_COUNT@@';
  MAGIC_ARRAY_MARKER = '@@MAGIC_ARRAY@@';
  FOOTER_MAGIC_MARKER = '@@FOOTER_MAGIC@@';
  FRAG_LABEL_MARKER = '@@FRAG_LABEL@@';
  META_LABEL_MARKER = '@@META_LABEL@@';
  SUBSYSTEM_MARKER = '@@WINDOWS_SUBSYSTEM@@';
  EXEC_IN_MEMORY_MARKER = '@@EXEC_IN_MEMORY@@';
  DEMAND_PAGING_MARKER = '@@DEMAND_PAGING@@';
  MANIFEST_RCDATA_MARKER = '@@MANIFEST_RCDATA_ID@@';
  DECOMPRESSOR_MARKER = '@@DECOMPRESSOR_IMPL@@';
  EXEC_VM_DOMAIN_MARKER = '@@EXEC_VM_DOMAIN@@';

  function BytesToRustArray(const B: TBytes): string;
  var
    K: integer;
  begin
    Result := '';
    for K := 0 to Length(B) - 1 do
    begin
      if K > 0 then Result := Result + ', ';
      Result := Result + Format('0x%.2x', [B[K]]);
    end;
  end;

  procedure RequireMarker(const M, S: string);
  begin
    if Pos(M, S) = 0 then
      raise Exception.Create('Marcador ' + M + ' não encontrado no Stub Windows.');
  end;

var
  FS: TStringList;
  Source, MagicArray, SubsystemName, ExecModeLiteral: string;
  SeedSaltLiteral, MaskFromTextLiteral, DemandPagingLiteral: string;
  I: integer;
  DecompressorCode: string;
  ExecVmDomain: TBytes;
begin
  Result := False;
  if Length(Magics) < 1 then
    raise Exception.Create('Stub Windows requer ao menos um magic.');
  if (Length(FragLabel) <> FRAG_LABEL_SIZE) or
    (Length(MetaLabel) <> FRAG_LABEL_SIZE) then
    raise Exception.Create('Labels Windows devem ter 16 bytes.');

  if (CompressionAlgorithm <> COMPACT_ZSTD) and
    (CompressionAlgorithm <> COMPACT_BROTLI) then
    raise Exception.CreateFmt('Algoritmo de compressão Windows inválido: %d',
      [CompressionAlgorithm]);


  if ManifestRcDataId = 0 then
    raise Exception.Create('ID do manifest RCDATA Windows inválido.');

  case Subsystem of
    2: SubsystemName := 'windows';
    3: SubsystemName := 'console';
    else
      raise Exception.CreateFmt('Subsystem PE não suportado: %d', [Subsystem]);
  end;

  { True usa o caminho em memória; False usa o fallback em disco. }
  if ExecInMemory then
    ExecModeLiteral := 'true'
  else
    ExecModeLiteral := 'false';

  if SELF_TEXT_HASH_BINDING then
    MaskFromTextLiteral := 'true'
  else
    MaskFromTextLiteral := 'false';

  
  if WINDOWS_DEMAND_PAGING and ExecInMemory then
    DemandPagingLiteral := 'true'
  else
    DemandPagingLiteral := 'false';

  { Marcador aleatório usado para localizar SECRET_ENC após a compilação. }
  SecretEncPadrao := RandomBytes(SECRET_SIZE);
  SecretMask := RandomBytes(SECRET_SIZE);
  if (Length(SecretEncPadrao) <> SECRET_SIZE) or (Length(SecretMask) <> SECRET_SIZE) then
    raise Exception.Create('Falha ao gerar material aleatório do Stub Windows.');

  { Domain separator da Exec VM, gerado por build. }
  ExecVmDomain := RandomBytes(16);
  if Length(ExecVmDomain) <> 16 then
    raise Exception.Create('Falha ao gerar EXEC_VM_DOMAIN aleatório do Stub Windows.');


  SeedSaltLiteral := '';
  for I := 0 to 3 do
  begin
    if I > 0 then
      SeedSaltLiteral := SeedSaltLiteral + ', ';
    SeedSaltLiteral := SeedSaltLiteral + '0x' + IntToHex(VM.SeedSalt[I], 16);
  end;

  FS := TStringList.Create;
  try
    FS.LoadFromFile(TemplatePath);
    Source := FS.Text;

    RequireMarker(SECRET_ENC_MARKER, Source);
    RequireMarker(SECRET_MASK_MARKER, Source);
    RequireMarker(SEED_SALT_MARKER, Source);
    RequireMarker(MASK_FROM_TEXT_MARKER, Source);
    RequireMarker(MAGIC_COUNT_MARKER, Source);
    RequireMarker(MAGIC_ARRAY_MARKER, Source);
    RequireMarker(FOOTER_MAGIC_MARKER, Source);
    RequireMarker(FRAG_LABEL_MARKER, Source);
    RequireMarker(META_LABEL_MARKER, Source);
    RequireMarker(SUBSYSTEM_MARKER, Source);
    RequireMarker(EXEC_IN_MEMORY_MARKER, Source);
    RequireMarker(DEMAND_PAGING_MARKER, Source);
    RequireMarker(MANIFEST_RCDATA_MARKER, Source);
    RequireMarker(DECOMPRESSOR_MARKER, Source);
    RequireMarker(EXEC_VM_DOMAIN_MARKER, Source);


    MagicArray := '';
    for I := 0 to Length(Magics) - 1 do
    begin
      if I > 0 then MagicArray := MagicArray + ', ';
      MagicArray := MagicArray + '0x' + IntToHex(Magics[I], 16);
    end;

    DecompressorCode :=
      GetRustDecompressorCode(CompressionAlgorithm);

    Source := StringReplace(Source, DECOMPRESSOR_MARKER, DecompressorCode,
      [rfReplaceAll]);

    Source := StringReplace(Source, EXEC_VM_DOMAIN_MARKER,
      BytesToRustArray(ExecVmDomain), [rfReplaceAll]);

    Source := StringReplace(Source, SECRET_ENC_MARKER,
      BytesToRustArray(SecretEncPadrao), [rfReplaceAll]);
    Source := StringReplace(Source, SECRET_MASK_MARKER,
      BytesToRustArray(SecretMask), [rfReplaceAll]);
    Source := StringReplace(Source, SEED_SALT_MARKER, SeedSaltLiteral,
      [rfReplaceAll]);
    Source := StringReplace(Source, MASK_FROM_TEXT_MARKER,
      MaskFromTextLiteral, [rfReplaceAll]);
    Source := StringReplace(Source, MAGIC_COUNT_MARKER,
      IntToStr(Length(Magics)), [rfReplaceAll]);
    Source := StringReplace(Source, MAGIC_ARRAY_MARKER, MagicArray, [rfReplaceAll]);
    Source := StringReplace(Source, FOOTER_MAGIC_MARKER,
      IntToHex(FooterMagic, 16), [rfReplaceAll]);
    Source := StringReplace(Source, FRAG_LABEL_MARKER,
      BytesToRustArray(FragLabel), [rfReplaceAll]);
    Source := StringReplace(Source, META_LABEL_MARKER,
      BytesToRustArray(MetaLabel), [rfReplaceAll]);
    Source := StringReplace(Source, SUBSYSTEM_MARKER, SubsystemName,
      [rfReplaceAll]);
    Source := StringReplace(Source, EXEC_IN_MEMORY_MARKER, ExecModeLiteral,
      [rfReplaceAll]);
    Source := StringReplace(Source, DEMAND_PAGING_MARKER, DemandPagingLiteral,
      [rfReplaceAll]);
    Source := StringReplace(Source, MANIFEST_RCDATA_MARKER,
      IntToStr(ManifestRcDataId), [rfReplaceAll]);

    FS.Text := Source;
    FS.SaveToFile(OutputPath);
    Result := True;
  finally
    if Length(ExecVmDomain) > 0 then
      FillChar(ExecVmDomain[0], Length(ExecVmDomain), 0);
    SetLength(ExecVmDomain, 0);

    FS.Free;
    Source := '';
  end;
end;


function PatchWindowsBuildTemplate(const TemplatePath: string;
  const OutputPath: string; ImageBase: QWord; const ResInfo: TStringList): boolean;
const
  IMAGE_BASE_MARKER = '@@IMAGE_BASE@@';

  COMPANY_NAME_MARKER = '@@COMPANY_NAME@@';
  FILE_DESCRIPTION_MARKER = '@@FILE_DESCRIPTION@@';
  PRODUCT_NAME_MARKER = '@@PRODUCT_NAME@@';
  LEGAL_COPYRIGHT_MARKER = '@@LEGAL_COPYRIGHT@@';
  ORIGINAL_FILENAME_MARKER = '@@ORIGINAL_FILENAME@@';
  INTERNAL_NAME_MARKER = '@@INTERNAL_NAME@@';
  PRODUCT_VERSION_MARKER = '@@PRODUCT_VERSION@@';
  FILE_VERSION_MARKER = '@@FILE_VERSION@@';
var
  FS: TStringList;
  Source: string;

  function EscapeRustString(const Value: string): string;
  begin
    Result := Value;

    // Escapa valores inseridos em strings Rust.
    Result := StringReplace(Result, '\', '\\', [rfReplaceAll]);

    Result := StringReplace(Result, '"', '\"', [rfReplaceAll]);

    Result := StringReplace(Result, #13#10, '\n', [rfReplaceAll]);

    Result := StringReplace(Result, #10, '\n', [rfReplaceAll]);

    Result := StringReplace(Result, #13, '\n', [rfReplaceAll]);
  end;


  procedure ReplaceMarker(const Marker: string; const Value: string);
  begin
    if Pos(Marker, Source) = 0 then
      raise Exception.Create('Marcador não encontrado em build.rs.in: ' +
        Marker);

    Source := StringReplace(Source, Marker, EscapeRustString(Value),
      [rfReplaceAll]);
  end;

begin
  Result := False;

  if not FileExists(TemplatePath) then
    raise Exception.Create('Template build.rs.in não encontrado: ' + TemplatePath);

  if ImageBase = 0 then
    raise Exception.Create('ImageBase do Stub Windows inválida.');

  if (ImageBase and $FFFF) <> 0 then
    raise Exception.Create('ImageBase deve estar alinhada em 64 KiB.');

  FS := TStringList.Create;

  try
    FS.LoadFromFile(TemplatePath);

    Source := FS.Text;

    if Pos(IMAGE_BASE_MARKER, Source) = 0 then
      raise Exception.Create(
        'Marcador de ImageBase não encontrado no build.rs.in.');

    Source := StringReplace(Source, IMAGE_BASE_MARKER, IntToHex(ImageBase, 16),
      [rfReplaceAll]);

    ReplaceMarker(
      COMPANY_NAME_MARKER,
      ResInfo.Values['CompanyName']
      );

    ReplaceMarker(
      FILE_DESCRIPTION_MARKER,
      ResInfo.Values['FileDescription']
      );

    ReplaceMarker(
      PRODUCT_NAME_MARKER,
      ResInfo.Values['ProductName']
      );

    ReplaceMarker(
      LEGAL_COPYRIGHT_MARKER,
      ResInfo.Values['LegalCopyright']
      );

    ReplaceMarker(
      ORIGINAL_FILENAME_MARKER,
      ResInfo.Values['OriginalFilename']
      );

    ReplaceMarker(
      INTERNAL_NAME_MARKER,
      ResInfo.Values['InternalName']
      );

    ReplaceMarker(
      PRODUCT_VERSION_MARKER,
      ResInfo.Values['ProductVersion']
      );

    ReplaceMarker(
      FILE_VERSION_MARKER,
      ResInfo.Values['FileVersion']
      );

    FS.Text := Source;
    FS.SaveToFile(OutputPath);

    Result := True;

  finally
    FS.Free;
    ResInfo.Free;
  end;
end;

function CompilarStubWindows(const ManifestPath: string; out Saida: string): boolean;
var
  Proc: TProcess;
  Buffer: TStringList;
  RustupPath: string;
  CargoXwinPath: string;
  HomePath: string;
  EnvValue: string;
  EnvName: string;
  I, P: integer;

  function DeveIgnorarVariavel(const Nome: string): boolean;
  begin
    Result :=
      SameText(Nome, 'RUSTC') or SameText(Nome, 'RUSTC_WRAPPER') or
      SameText(Nome, 'RUSTC_WORKSPACE_WRAPPER') or SameText(Nome, 'RUSTFLAGS') or
      SameText(Nome, 'CARGO_ENCODED_RUSTFLAGS') or
      SameText(Nome, 'CARGO_BUILD_RUSTC') or SameText(Nome, 'RUSTUP_TOOLCHAIN') or
      SameText(Nome, 'CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER') or
      SameText(Nome, 'CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER') or
      SameText(Nome, 'CC_X86_64_PC_WINDOWS_MSVC') or
      SameText(Nome, 'CXX_X86_64_PC_WINDOWS_MSVC') or
      SameText(Nome, 'AR_X86_64_PC_WINDOWS_MSVC');
  end;

begin
  Result := False;
  Saida := '';

  HomePath := GetEnvironmentVariable('HOME');
  if HomePath = '' then
    raise Exception.Create('Não foi possível localizar o diretório HOME.');

  RustupPath := IncludeTrailingPathDelimiter(HomePath) + '.cargo/bin/rustup';
  CargoXwinPath := IncludeTrailingPathDelimiter(HomePath) + '.cargo/bin/cargo-xwin';

  if not FileExists(RustupPath) then
    raise Exception.Create('rustup não encontrado em: ' + RustupPath);

  if not FileExists(CargoXwinPath) then
    raise Exception.Create('cargo-xwin não encontrado.' + LineEnding +
      'Instale com: cargo install --locked cargo-xwin');

  Proc := TProcess.Create(nil);
  Buffer := TStringList.Create;
  try
    Proc.Executable := RustupPath;

    Proc.Parameters.Add('run');
    Proc.Parameters.Add('stable');
    Proc.Parameters.Add('cargo');
    Proc.Parameters.Add('xwin');
    Proc.Parameters.Add('build');
    Proc.Parameters.Add('--release');
    Proc.Parameters.Add('--target');
    Proc.Parameters.Add('x86_64-pc-windows-msvc');
    Proc.Parameters.Add('--manifest-path');
    Proc.Parameters.Add(ManifestPath);

    Proc.Environment.Clear;

    for I := 1 to GetEnvironmentVariableCount do
    begin
      EnvValue := GetEnvironmentString(I);
      P := Pos('=', EnvValue);
      if P <= 1 then
        Continue;

      EnvName := Copy(EnvValue, 1, P - 1);
      if not DeveIgnorarVariavel(EnvName) then
        Proc.Environment.Add(EnvValue);
    end;

    Proc.Environment.Add(
      'PATH=' + IncludeTrailingPathDelimiter(HomePath) + '.cargo/bin:' +
      GetEnvironmentVariable('PATH')
      );

    Proc.Environment.Add('RUSTUP_TOOLCHAIN=stable');

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

procedure EscreverU16LE(var B: TBytes; Offset: integer; Valor: word);
begin
  if (Offset < 0) or (Offset + 2 > Length(B)) then
    raise Exception.Create('Escrita U16 fora do manifest RCDATA.');
  B[Offset] := byte(Valor and $FF);
  B[Offset + 1] := byte((Valor shr 8) and $FF);
end;

procedure EscreverU32LE(var B: TBytes; Offset: integer; Valor: longword);
begin
  if (Offset < 0) or (Offset + 4 > Length(B)) then
    raise Exception.Create('Escrita U32 fora do manifest RCDATA.');
  B[Offset] := byte(Valor and $FF);
  B[Offset + 1] := byte((Valor shr 8) and $FF);
  B[Offset + 2] := byte((Valor shr 16) and $FF);
  B[Offset + 3] := byte((Valor shr 24) and $FF);
end;

procedure EscreverU64LE(var B: TBytes; Offset: integer; Valor: QWord);
var
  I: integer;
begin
  if (Offset < 0) or (Offset + 8 > Length(B)) then
    raise Exception.Create('Escrita U64 fora do manifest RCDATA.');
  for I := 0 to 7 do
    B[Offset + I] := byte((Valor shr (I * 8)) and $FF);
end;

procedure LimparRcDataWindows(const RcDataDir, RcScriptPath: string);
var
  SR: TSearchRec;
  Nome: string;
begin
  if DirectoryExists(RcDataDir) then
  begin
    if FindFirst(IncludeTrailingPathDelimiter(RcDataDir) + '*', faAnyFile, SR) = 0 then
    try
      repeat
        if (SR.Name <> '.') and (SR.Name <> '..') and
          ((SR.Attr and faDirectory) = 0) then
        begin
          Nome := IncludeTrailingPathDelimiter(RcDataDir) + SR.Name;
          if FileExists(Nome) then
            DeleteFile(Nome);
        end;
      until FindNext(SR) <> 0;
    finally
      FindClose(SR);
    end;
  end;

  if (RcScriptPath <> '') and FileExists(RcScriptPath) then
    DeleteFile(RcScriptPath);
end;

function RcDataIdUsado(Id: word; const Usados: TRcDataIdArray): boolean;
var
  I: integer;
begin
  Result := False;
  for I := 0 to Length(Usados) - 1 do
    if Usados[I] = Id then
      Exit(True);
end;

function GerarRcDataIdUnico(var Usados: TRcDataIdArray): word;
var
  B: TBytes;
  Candidato: word;
  Faixa: longword;
begin
  if RCDATA_ID_MAX < RCDATA_ID_MIN then
    raise Exception.Create('Faixa de IDs RCDATA inválida.');

  Faixa := longword(RCDATA_ID_MAX - RCDATA_ID_MIN + 1);
  repeat
    B := RandomBytes(2);
    if Length(B) <> 2 then
      raise Exception.Create('Falha ao gerar ID aleatório de RCDATA.');

    Candidato := word(RCDATA_ID_MIN +
      ((longword(B[0]) or (longword(B[1]) shl 8)) mod Faixa));

    FillChar(B[0], Length(B), 0);
  until not RcDataIdUsado(Candidato, Usados);

  SetLength(Usados, Length(Usados) + 1);
  Usados[High(Usados)] := Candidato;
  Result := Candidato;
end;

{ Manifest RCDATA v1: magic(8), versão(4), count(4), tamanho(8), SHA-256(32)
  e uma entrada de 16 bytes para cada fragmento. }

function PrepararRcDataFragmentadoWindows(const PackedRegion: TBytes;
  const RcDataDir, RcScriptPath: string; out ManifestId: word;
  out FragmentIds: TRcDataIdArray): boolean;
const
  MANIFEST_HEADER_SIZE = 56;
  MANIFEST_ENTRY_SIZE = 16;
  MANIFEST_VERSION = 1;
  PACKED_FOOTER_SIZE = 40;
  PACKED_TRAILER_SIZE = 32;
var
  Usados: TRcDataIdArray;
  Manifest, Hash, Fragmento, ManifestMagic: TBytes;
  Rc: TStringList;
  Total, Count, I, Off, Tam, Ent, FooterPos: integer;
  NomeArquivo: string;
begin
  Result := False;
  ManifestId := 0;
  SetLength(FragmentIds, 0);
  SetLength(Usados, 0);

  if Length(PackedRegion) = 0 then
    raise Exception.Create('PackedRegion vazio ao preparar RCDATA fragmentado.');
  if RCDATA_FRAGMENT_SIZE <= 0 then
    raise Exception.Create('RCDATA_FRAGMENT_SIZE inválido.');

  LimparRcDataWindows(RcDataDir, RcScriptPath);
  if not DirectoryExists(RcDataDir) then
    if not ForceDirectories(RcDataDir) then
      raise Exception.Create('Não foi possível criar diretório RCDATA: ' + RcDataDir);

  Total := Length(PackedRegion);

  { O magic do manifest reutiliza os 8 bytes LE do FooterMagic. }
  if Total < (PACKED_FOOTER_SIZE + PACKED_TRAILER_SIZE) then
    raise Exception.Create('PackedRegion pequeno demais para conter footer/trailer v4.');

  FooterPos := Total - PACKED_TRAILER_SIZE - PACKED_FOOTER_SIZE;
  SetLength(ManifestMagic, 8);
  Move(PackedRegion[FooterPos], ManifestMagic[0], 8);

  Count := (Total + RCDATA_FRAGMENT_SIZE - 1) div RCDATA_FRAGMENT_SIZE;
  if (Count <= 0) or (Count > 4096) then
    raise Exception.CreateFmt('Quantidade de fragmentos RCDATA inválida: %d', [Count]);

  ManifestId := GerarRcDataIdUnico(Usados);
  SetLength(FragmentIds, Count);
  for I := 0 to Count - 1 do
    FragmentIds[I] := GerarRcDataIdUnico(Usados);

  Hash := SHA256Range(PackedRegion, 0, longword(Total));
  if Length(Hash) <> 32 then
    raise Exception.Create('SHA-256 do PackedRegion inválido.');

  SetLength(Manifest, MANIFEST_HEADER_SIZE + Count * MANIFEST_ENTRY_SIZE);
  FillChar(Manifest[0], Length(Manifest), 0);
  Move(ManifestMagic[0], Manifest[0], 8);
  EscreverU32LE(Manifest, 8, MANIFEST_VERSION);
  EscreverU32LE(Manifest, 12, longword(Count));
  EscreverU64LE(Manifest, 16, QWord(Total));
  Move(Hash[0], Manifest[24], 32);

  Rc := TStringList.Create;
  try
    Rc.Add(Format('%d RCDATA "assets/rcdata/manifest.bin"', [ManifestId]));

    Off := 0;
    for I := 0 to Count - 1 do
    begin
      Tam := RCDATA_FRAGMENT_SIZE;
      if Tam > Total - Off then
        Tam := Total - Off;

      SetLength(Fragmento, Tam);
      if Tam > 0 then
        Move(PackedRegion[Off], Fragmento[0], Tam);

      NomeArquivo := IncludeTrailingPathDelimiter(RcDataDir) +
        Format('chunk_%.4d.bin', [I]);
      GravarBytesEmArquivo(NomeArquivo, Fragmento);

      Ent := MANIFEST_HEADER_SIZE + I * MANIFEST_ENTRY_SIZE;
      EscreverU32LE(Manifest, Ent, longword(I));
      EscreverU16LE(Manifest, Ent + 4, FragmentIds[I]);
      EscreverU16LE(Manifest, Ent + 6, 0);
      EscreverU64LE(Manifest, Ent + 8, QWord(Tam));

      Rc.Add(Format('%d RCDATA "assets/rcdata/chunk_%.4d.bin"',
        [FragmentIds[I], I]));

      if Length(Fragmento) > 0 then
        FillChar(Fragmento[0], Length(Fragmento), 0);
      SetLength(Fragmento, 0);
      Inc(Off, Tam);
    end;

    if Off <> Total then
      raise Exception.Create('Falha interna ao dividir PackedRegion em RCDATA.');

    GravarBytesEmArquivo(IncludeTrailingPathDelimiter(RcDataDir) +
      'manifest.bin', Manifest);
    Rc.SaveToFile(RcScriptPath);

    Result := True;
  finally
    Rc.Free;
    if Length(Hash) > 0 then FillChar(Hash[0], Length(Hash), 0);
    if Length(Manifest) > 0 then FillChar(Manifest[0], Length(Manifest), 0);
    if Length(Fragmento) > 0 then FillChar(Fragmento[0], Length(Fragmento), 0);
    if Length(ManifestMagic) > 0 then FillChar(ManifestMagic[0], Length(ManifestMagic), 0);
    if Length(Usados) > 0 then FillChar(Usados[0], Length(Usados) * SizeOf(word), 0);
  end;
end;

procedure CriarArquivoFinalWindows(const ArquivoSaida: string;
  const Stub, PackedRegion: TBytes);
var
  FSOut: TFileStream;
begin
  FSOut := TFileStream.Create(ArquivoSaida, fmCreate);
  try
    if Length(Stub) > 0 then
      FSOut.WriteBuffer(Stub[0], Length(Stub));
    if Length(PackedRegion) > 0 then
      FSOut.WriteBuffer(PackedRegion[0], Length(PackedRegion));
  finally
    FSOut.Free;
  end;
end;

end.
