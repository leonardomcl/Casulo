unit CasuloLinuxVm;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils;

const
  LINUX_VM_REG_COUNT   = 4;
  LINUX_VM_SECRET_SIZE = 32;
  LINUX_VM_MIX_MIN_OPS = 24;
  LINUX_VM_MIX_MAX_OPS = 40;

type
  TLinuxVmOpcodes = record
    MovImm, XorImm, AddImm, MulImm, RolImm, MixReg: Byte;
    CmpImm, Jnz, HostCall, Emit, Halt: Byte;

    LoadEnc, LoadMask, LoadMix, XorReg, StoreOut: Byte;
    IncIndex, CmpIndex, SecretJnz, SecretHalt: Byte;

    VerifyGate, ExecveatPayload: Byte;
  end;

  TLinuxMixOpKind = (
    lmokXor,
    lmokAdd,
    lmokMul,
    lmokRol,
    lmokMixReg
  );

  TLinuxMixOp = record
    Kind: TLinuxMixOpKind;
    Rd, Rs, Bits: Byte;
    Imm: QWord;
  end;

  TLinuxMixOpArray = array of TLinuxMixOp;

  TLinuxVmBuild = record
    Ops: TLinuxVmOpcodes;

    ProgKey: QWord;
    ProgStride: QWord;
    ProgMul: QWord;

    GateK1: QWord;
    GateK2: QWord;
    GateK3: QWord;
    GateInitDelta: QWord;
    GateR1: Byte;
    GateR2: Byte;

    { Seed exclusiva da VM Linux. }
    Seed: TBytes;

    MixOps: TLinuxMixOpArray;
    MixCode: TBytes;
    GateCode: TBytes;
    SecretCode: TBytes;
  end;

procedure GerarLinuxVmBuild(out VM: TLinuxVmBuild);

function ExecutarLinuxProgramaMix(const VM: TLinuxVmBuild;
  const Seed: TBytes): TBytes;

procedure PrepararLinuxVmSecret(const Secret: TBytes;
  const VM: TLinuxVmBuild; out Encoded, Mask: TBytes);

function PatchExecVmTemplateLinux(const TemplatePath, OutputPath: string;
  const VM: TLinuxVmBuild): Boolean;

procedure LimparLinuxVmBuild(var VM: TLinuxVmBuild);

implementation

uses
  Packer;

{$PUSH}{$Q-}{$R-}

function RolQ(V: QWord; Bits: Byte): QWord;
begin
  Bits := Bits and 63;
  if Bits = 0 then
    Exit(V);

  Result := (V shl Bits) or (V shr (64 - Bits));
end;

function LinuxVmKeystreamByte(const VM: TLinuxVmBuild;
  Index: Integer): Byte;
var
  X: QWord;
begin
  X := VM.ProgKey xor (QWord(Index) * VM.ProgStride);
  X := X xor (X shr 33);
  X := X * VM.ProgMul;
  X := X xor (X shr 29);
  Result := Byte(X and $FF);
end;

function ExecutarLinuxProgramaMix(const VM: TLinuxVmBuild;
  const Seed: TBytes): TBytes;
var
  R: array[0..LINUX_VM_REG_COUNT - 1] of QWord;
  I, J: Integer;
  Op: TLinuxMixOp;
begin
  if Length(Seed) <> LINUX_VM_SECRET_SIZE then
    raise Exception.Create('Seed da VM Linux deve ter 32 bytes.');

  FillChar(R[0], SizeOf(R), 0);

  for I := 0 to LINUX_VM_REG_COUNT - 1 do
  begin
    R[I] := 0;
    for J := 7 downto 0 do
      R[I] := (R[I] shl 8) or QWord(Seed[I * 8 + J]);
  end;

  for I := 0 to Length(VM.MixOps) - 1 do
  begin
    Op := VM.MixOps[I];

    case Op.Kind of
      lmokXor:
        R[Op.Rd] := R[Op.Rd] xor Op.Imm;

      lmokAdd:
        R[Op.Rd] := R[Op.Rd] + Op.Imm;

      lmokMul:
        R[Op.Rd] := R[Op.Rd] * Op.Imm;

      lmokRol:
        R[Op.Rd] := RolQ(R[Op.Rd], Op.Bits);

      lmokMixReg:
        R[Op.Rd] := R[Op.Rd] xor RolQ(R[Op.Rs], Op.Bits);
    end;
  end;

  SetLength(Result, LINUX_VM_SECRET_SIZE);

  for I := 0 to LINUX_VM_REG_COUNT - 1 do
    for J := 0 to 7 do
      Result[I * 8 + J] := Byte((R[I] shr (J * 8)) and $FF);

  FillChar(R[0], SizeOf(R), 0);
end;

{$POP}

function RandQWord: QWord;
var
  B: TBytes;
  I: Integer;
begin
  B := RandomBytes(8);

  if Length(B) <> 8 then
    raise Exception.Create('Falha ao gerar QWord aleatório para VM Linux.');

  Result := 0;
  for I := 7 downto 0 do
    Result := (Result shl 8) or QWord(B[I]);

  FillChar(B[0], Length(B), 0);
end;

function RandByteValue: Byte;
var
  B: TBytes;
begin
  B := RandomBytes(1);

  if Length(B) <> 1 then
    raise Exception.Create('Falha ao gerar byte aleatório para VM Linux.');

  Result := B[0];
  B[0] := 0;
end;

function RandRotBits: Byte;
begin
  Result := 1 + (RandByteValue mod 63);
end;

procedure SortearBytesDistintos(Count: Integer; out Valores: TBytes);
const
  POOL_SIZE = $F0;
var
  Pool, Entropia: TBytes;
  I, J: Integer;
  T: Byte;
begin
  if (Count < 1) or (Count > POOL_SIZE) then
    raise Exception.Create('Quantidade inválida de opcodes da VM Linux.');

  SetLength(Pool, POOL_SIZE);

  for I := 0 to POOL_SIZE - 1 do
    Pool[I] := Byte(I + 1);

  Entropia := RandomBytes(POOL_SIZE * 2);

  if Length(Entropia) <> POOL_SIZE * 2 then
    raise Exception.Create('Falha ao gerar entropia para ISA da VM Linux.');

  for I := POOL_SIZE - 1 downto 1 do
  begin
    J := ((Integer(Entropia[I * 2]) shl 8) or
      Integer(Entropia[I * 2 + 1])) mod (I + 1);

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

procedure AppendByte(var B: TBytes; V: Byte);
begin
  SetLength(B, Length(B) + 1);
  B[High(B)] := V;
end;

procedure AppendWordLE(var B: TBytes; V: Word);
begin
  AppendByte(B, Byte(V and $FF));
  AppendByte(B, Byte((V shr 8) and $FF));
end;

procedure AppendQWordLE(var B: TBytes; V: QWord);
var
  I: Integer;
begin
  for I := 0 to 7 do
    AppendByte(B, Byte((V shr (I * 8)) and $FF));
end;

procedure GerarProgramaMix(var VM: TLinuxVmBuild);
var
  Total, I: Integer;
  Op: TLinuxMixOp;
begin
  Total := LINUX_VM_MIX_MIN_OPS +
    (Integer(RandByteValue) mod
      (LINUX_VM_MIX_MAX_OPS - LINUX_VM_MIX_MIN_OPS + 1));

  SetLength(VM.MixOps, Total + LINUX_VM_REG_COUNT);

  for I := 0 to Total - 1 do
  begin
    Op.Kind := TLinuxMixOpKind(RandByteValue mod 5);
    Op.Rd := Byte(RandByteValue mod LINUX_VM_REG_COUNT);
    Op.Rs := 0;
    Op.Bits := 0;
    Op.Imm := 0;

    case Op.Kind of
      lmokXor, lmokAdd:
        Op.Imm := RandQWord;

      lmokMul:
        Op.Imm := RandQWord or 1;

      lmokRol:
        Op.Bits := RandRotBits;

      lmokMixReg:
      begin
        Op.Rs := Byte(
          (Op.Rd + 1 +
            (RandByteValue mod (LINUX_VM_REG_COUNT - 1))) mod
          LINUX_VM_REG_COUNT
        );
        Op.Bits := RandRotBits;
      end;
    end;

    VM.MixOps[I] := Op;
  end;

  { Fecha a mistura entre os registradores. }
  for I := 0 to LINUX_VM_REG_COUNT - 1 do
  begin
    Op.Kind := lmokMixReg;
    Op.Rd := Byte(I);
    Op.Rs := Byte((I + 1) mod LINUX_VM_REG_COUNT);
    Op.Bits := RandRotBits;
    Op.Imm := 0;
    VM.MixOps[Total + I] := Op;
  end;

  SetLength(VM.MixCode, 0);

  for I := 0 to Length(VM.MixOps) - 1 do
  begin
    Op := VM.MixOps[I];

    case Op.Kind of
      lmokXor:
      begin
        AppendByte(VM.MixCode, VM.Ops.XorImm);
        AppendByte(VM.MixCode, Op.Rd);
        AppendQWordLE(VM.MixCode, Op.Imm);
      end;

      lmokAdd:
      begin
        AppendByte(VM.MixCode, VM.Ops.AddImm);
        AppendByte(VM.MixCode, Op.Rd);
        AppendQWordLE(VM.MixCode, Op.Imm);
      end;

      lmokMul:
      begin
        AppendByte(VM.MixCode, VM.Ops.MulImm);
        AppendByte(VM.MixCode, Op.Rd);
        AppendQWordLE(VM.MixCode, Op.Imm);
      end;

      lmokRol:
      begin
        AppendByte(VM.MixCode, VM.Ops.RolImm);
        AppendByte(VM.MixCode, Op.Rd);
        AppendByte(VM.MixCode, Op.Bits);
      end;

      lmokMixReg:
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

procedure GerarProgramaGate(var VM: TLinuxVmBuild);
var
  PatchPos, FailPos: Integer;
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
  AppendByte(VM.GateCode, VM.Ops.ExecveatPayload);
  AppendByte(VM.GateCode, VM.Ops.Halt);

  FailPos := Length(VM.GateCode);

  AppendByte(VM.GateCode, VM.Ops.MovImm);
  AppendByte(VM.GateCode, 0);
  AppendQWordLE(VM.GateCode, QWord($FFFFFFFFFFFFFFFF));
  AppendByte(VM.GateCode, VM.Ops.Halt);

  if FailPos > High(Word) then
    raise Exception.Create('Gate da VM Linux excedeu alvo de 16 bits.');

  VM.GateCode[PatchPos] := Byte(FailPos and $FF);
  VM.GateCode[PatchPos + 1] := Byte((FailPos shr 8) and $FF);
end;

procedure GerarProgramaSecret(var VM: TLinuxVmBuild);
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
  AppendByte(VM.SecretCode, LINUX_VM_SECRET_SIZE);

  AppendByte(VM.SecretCode, VM.Ops.SecretJnz);
  AppendWordLE(VM.SecretCode, 0);

  AppendByte(VM.SecretCode, VM.Ops.SecretHalt);
end;

procedure GerarLinuxVmBuild(out VM: TLinuxVmBuild);
var
  Codigos: TBytes;
begin
  { TLinuxVmBuild contém arrays gerenciados; não zerar o record inteiro. }
  FillChar(VM.Ops, SizeOf(VM.Ops), 0);
  VM.ProgKey := 0;
  VM.ProgStride := 0;
  VM.ProgMul := 0;
  VM.GateK1 := 0;
  VM.GateK2 := 0;
  VM.GateK3 := 0;
  VM.GateInitDelta := 0;
  VM.GateR1 := 0;
  VM.GateR2 := 0;
  SetLength(VM.Seed, 0);
  SetLength(VM.MixOps, 0);
  SetLength(VM.MixCode, 0);
  SetLength(VM.GateCode, 0);
  SetLength(VM.SecretCode, 0);

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
  VM.Ops.ExecveatPayload := Codigos[21];

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

  VM.Seed := RandomBytes(LINUX_VM_SECRET_SIZE);
  if Length(VM.Seed) <> LINUX_VM_SECRET_SIZE then
    raise Exception.Create('Falha ao gerar seed da VM Linux.');

  GerarProgramaMix(VM);
  GerarProgramaGate(VM);
  GerarProgramaSecret(VM);

  FillChar(Codigos[0], Length(Codigos), 0);
end;

procedure PrepararLinuxVmSecret(const Secret: TBytes;
  const VM: TLinuxVmBuild; out Encoded, Mask: TBytes);
var
  Mix: TBytes;
  I: Integer;
begin
  if Length(Secret) <> LINUX_VM_SECRET_SIZE then
    raise Exception.Create('Secret da VM Linux deve ter 32 bytes.');

  if Length(VM.Seed) <> LINUX_VM_SECRET_SIZE then
    raise Exception.Create('Seed inválida na VM Linux.');

  Mix := ExecutarLinuxProgramaMix(VM, VM.Seed);
  Mask := RandomBytes(LINUX_VM_SECRET_SIZE);

  if Length(Mask) <> LINUX_VM_SECRET_SIZE then
    raise Exception.Create('Falha ao gerar máscara do Secret da VM Linux.');

  SetLength(Encoded, LINUX_VM_SECRET_SIZE);

  for I := 0 to LINUX_VM_SECRET_SIZE - 1 do
    Encoded[I] := Secret[I] xor Mask[I] xor Mix[I];

  if Length(Mix) > 0 then
    FillChar(Mix[0], Length(Mix), 0);

  SetLength(Mix, 0);
end;

function PatchExecVmTemplateLinux(const TemplatePath, OutputPath: string;
  const VM: TLinuxVmBuild): Boolean;
var
  FS: TStringList;
  Source: string;

  function ProgramaParaRust(const B: TBytes): string;
  var
    K: Integer;
  begin
    Result := '';

    for K := 0 to Length(B) - 1 do
    begin
      if K > 0 then
        Result := Result + ', ';

      if (K mod 12) = 0 then
        Result := Result + LineEnding + '    ';

      Result := Result +
        Format('0x%.2x', [B[K] xor LinuxVmKeystreamByte(VM, K)]);
    end;
  end;

  procedure Troca(const Marcador, Valor: string);
  begin
    if Pos(Marcador, Source) = 0 then
      raise Exception.Create(
        'Marcador ' + Marcador +
        ' não encontrado no exec_vm.rs.in Linux.'
      );

    Source := StringReplace(Source, Marcador, Valor, [rfReplaceAll]);
  end;

  function Hex2(V: Byte): string;
  begin
    Result := IntToHex(V, 2);
  end;

begin
  Result := False;

  if (Length(VM.MixCode) = 0) or
     (Length(VM.GateCode) = 0) or
     (Length(VM.SecretCode) = 0) then
    raise Exception.Create('Programas da VM Linux não foram gerados.');

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
    Troca('@@HOST_EXECVEAT@@', Hex2(VM.Ops.ExecveatPayload));

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

procedure LimparLinuxVmBuild(var VM: TLinuxVmBuild);
begin
  if Length(VM.Seed) > 0 then
    FillChar(VM.Seed[0], Length(VM.Seed), 0);

  if Length(VM.MixCode) > 0 then
    FillChar(VM.MixCode[0], Length(VM.MixCode), 0);

  if Length(VM.GateCode) > 0 then
    FillChar(VM.GateCode[0], Length(VM.GateCode), 0);

  if Length(VM.SecretCode) > 0 then
    FillChar(VM.SecretCode[0], Length(VM.SecretCode), 0);

  if Length(VM.MixOps) > 0 then
    FillChar(VM.MixOps[0],
      Length(VM.MixOps) * SizeOf(TLinuxMixOp), 0);

  SetLength(VM.Seed, 0);
  SetLength(VM.MixCode, 0);
  SetLength(VM.GateCode, 0);
  SetLength(VM.SecretCode, 0);
  SetLength(VM.MixOps, 0);

  FillChar(VM.Ops, SizeOf(VM.Ops), 0);
  VM.ProgKey := 0;
  VM.ProgStride := 0;
  VM.ProgMul := 0;
  VM.GateK1 := 0;
  VM.GateK2 := 0;
  VM.GateK3 := 0;
  VM.GateInitDelta := 0;
  VM.GateR1 := 0;
  VM.GateR2 := 0;
end;

end.

