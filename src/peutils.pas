unit PEUtils;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils;

type
  TPE64Info = record
    ImageBase: QWord;
    Subsystem: Word;
    Characteristics: Word;
    DllCharacteristics: Word;
    HasRelocations: Boolean;
    HasCertificateTable: Boolean;
  end;

function ReadPE64Info(const FileName: string; out Info: TPE64Info): Boolean;
function RebasePE64InPlace(const FileName: string; NewImageBase: QWord;
  out OldImageBase: QWord): Boolean;
function GenerateRandomPE64ImageBase: QWord;

implementation

uses
  Packer;

const
  IMAGE_DOS_SIGNATURE = $5A4D;       // MZ
  IMAGE_NT_SIGNATURE = $00004550;    // PE\0\0
  IMAGE_FILE_MACHINE_AMD64 = $8664;
  IMAGE_NT_OPTIONAL_HDR64_MAGIC = $020B;

  IMAGE_FILE_RELOCS_STRIPPED = $0001;
  IMAGE_FILE_DLL = $2000;

  IMAGE_SUBSYSTEM_WINDOWS_GUI = 2;
  IMAGE_SUBSYSTEM_WINDOWS_CUI = 3;

  IMAGE_DIRECTORY_ENTRY_SECURITY = 4;
  IMAGE_DIRECTORY_ENTRY_BASERELOC = 5;

  IMAGE_REL_BASED_ABSOLUTE = 0;
  IMAGE_REL_BASED_DIR64 = 10;

  PE64_IMAGE_BASE_ALIGNMENT = QWord($10000);
  PE64_RANDOM_BASE_MIN = QWord($0000000180000000);
  PE64_RANDOM_BASE_MAX = QWord($0000000700000000);

type
  TParsedPE = record
    PEOffset: Integer;
    OptionalOffset: Integer;
    SectionTableOffset: Integer;
    NumberOfSections: Word;
    SizeOfOptionalHeader: Word;
    SizeOfHeaders: LongWord;
    NumberOfRvaAndSizes: LongWord;
    RelocRVA: LongWord;
    RelocSize: LongWord;
    CertFileOffset: LongWord;
    CertSize: LongWord;
    Info: TPE64Info;
  end;

function RangeOK(const Data: TBytes; Offset, Count: Int64): Boolean; inline;
begin
  Result := (Offset >= 0) and (Count >= 0) and
    (Offset <= Length(Data)) and (Count <= Length(Data) - Offset);
end;

function GetWordLE(const Data: TBytes; Offset: Integer): Word; inline;
begin
  if not RangeOK(Data, Offset, 2) then
    raise Exception.Create('PE: leitura Word fora do arquivo.');
  Result := Word(Data[Offset]) or (Word(Data[Offset + 1]) shl 8);
end;

function GetDWordLE(const Data: TBytes; Offset: Integer): LongWord; inline;
begin
  if not RangeOK(Data, Offset, 4) then
    raise Exception.Create('PE: leitura DWORD fora do arquivo.');
  Result := LongWord(Data[Offset]) or
    (LongWord(Data[Offset + 1]) shl 8) or
    (LongWord(Data[Offset + 2]) shl 16) or
    (LongWord(Data[Offset + 3]) shl 24);
end;

function GetQWordLE(const Data: TBytes; Offset: Integer): QWord; inline;
var
  I: Integer;
begin
  if not RangeOK(Data, Offset, 8) then
    raise Exception.Create('PE: leitura QWORD fora do arquivo.');
  Result := 0;
  for I := 0 to 7 do
    Result := Result or (QWord(Data[Offset + I]) shl (I * 8));
end;

procedure PutQWordLE(var Data: TBytes; Offset: Integer; Value: QWord); inline;
var
  I: Integer;
begin
  if not RangeOK(Data, Offset, 8) then
    raise Exception.Create('PE: escrita QWORD fora do arquivo.');
  for I := 0 to 7 do
    Data[Offset + I] := Byte((Value shr (I * 8)) and $FF);
end;

function LoadBytes(const FileName: string): TBytes;
var
  FS: TFileStream;
begin
  FS := TFileStream.Create(FileName, fmOpenRead or fmShareDenyWrite);
  try
    if FS.Size <= 0 then
      raise Exception.Create('PE: arquivo vazio.');
    if FS.Size > High(Integer) then
      raise Exception.Create('PE: arquivo grande demais para o parser atual.');
    SetLength(Result, Integer(FS.Size));
    FS.ReadBuffer(Result[0], Length(Result));
  finally
    FS.Free;
  end;
end;

procedure SaveBytes(const FileName: string; const Data: TBytes);
var
  FS: TFileStream;
begin
  FS := TFileStream.Create(FileName, fmCreate);
  try
    if Length(Data) > 0 then
      FS.WriteBuffer(Data[0], Length(Data));
  finally
    FS.Free;
  end;
end;

function ParsePE64(const Data: TBytes; out P: TParsedPE): Boolean;
var
  Opt, DataDir: Integer;
  Characteristics: Word;
begin
  Result := False;
  FillChar(P, SizeOf(P), 0);

  try
    if Length(Data) < $100 then Exit;
    if GetWordLE(Data, 0) <> IMAGE_DOS_SIGNATURE then Exit;

    P.PEOffset := Integer(GetDWordLE(Data, $3C));
    if not RangeOK(Data, P.PEOffset, 24) then Exit;
    if GetDWordLE(Data, P.PEOffset) <> IMAGE_NT_SIGNATURE then Exit;
    if GetWordLE(Data, P.PEOffset + 4) <> IMAGE_FILE_MACHINE_AMD64 then Exit;

    P.NumberOfSections := GetWordLE(Data, P.PEOffset + 6);
    if (P.NumberOfSections = 0) or (P.NumberOfSections > 96) then Exit;

    P.SizeOfOptionalHeader := GetWordLE(Data, P.PEOffset + 20);
    Characteristics := GetWordLE(Data, P.PEOffset + 22);
    if (Characteristics and IMAGE_FILE_DLL) <> 0 then Exit;

    Opt := P.PEOffset + 24;
    P.OptionalOffset := Opt;
    if (P.SizeOfOptionalHeader < 112) or
      (not RangeOK(Data, Opt, P.SizeOfOptionalHeader)) then Exit;
    if GetWordLE(Data, Opt) <> IMAGE_NT_OPTIONAL_HDR64_MAGIC then Exit;

    P.Info.ImageBase := GetQWordLE(Data, Opt + 24);
    if (P.Info.ImageBase and (PE64_IMAGE_BASE_ALIGNMENT - 1)) <> 0 then Exit;

    P.SizeOfHeaders := GetDWordLE(Data, Opt + 60);
    P.Info.Subsystem := GetWordLE(Data, Opt + 68);
    P.Info.DllCharacteristics := GetWordLE(Data, Opt + 70);
    P.Info.Characteristics := Characteristics;

    if (P.Info.Subsystem <> IMAGE_SUBSYSTEM_WINDOWS_GUI) and
      (P.Info.Subsystem <> IMAGE_SUBSYSTEM_WINDOWS_CUI) then Exit;

    P.NumberOfRvaAndSizes := GetDWordLE(Data, Opt + 108);
    DataDir := Opt + 112;
    if P.NumberOfRvaAndSizes > 64 then Exit;
    if (P.NumberOfRvaAndSizes > 0) and
      (Int64(P.SizeOfOptionalHeader) < 112 +
       Int64(P.NumberOfRvaAndSizes) * 8) then Exit;

    if P.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_SECURITY then
    begin
      if not RangeOK(Data, DataDir + IMAGE_DIRECTORY_ENTRY_SECURITY * 8, 8) then Exit;
      P.CertFileOffset := GetDWordLE(Data,
        DataDir + IMAGE_DIRECTORY_ENTRY_SECURITY * 8);
      P.CertSize := GetDWordLE(Data,
        DataDir + IMAGE_DIRECTORY_ENTRY_SECURITY * 8 + 4);
    end;

    if P.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_BASERELOC then
    begin
      if not RangeOK(Data, DataDir + IMAGE_DIRECTORY_ENTRY_BASERELOC * 8, 8) then Exit;
      P.RelocRVA := GetDWordLE(Data,
        DataDir + IMAGE_DIRECTORY_ENTRY_BASERELOC * 8);
      P.RelocSize := GetDWordLE(Data,
        DataDir + IMAGE_DIRECTORY_ENTRY_BASERELOC * 8 + 4);
    end;

    P.SectionTableOffset := Opt + P.SizeOfOptionalHeader;
    if not RangeOK(Data, P.SectionTableOffset,
      Int64(P.NumberOfSections) * 40) then Exit;

    P.Info.HasCertificateTable :=
      (P.CertFileOffset <> 0) and (P.CertSize <> 0) and
      RangeOK(Data, P.CertFileOffset, P.CertSize);

    P.Info.HasRelocations :=
      ((Characteristics and IMAGE_FILE_RELOCS_STRIPPED) = 0) and
      (P.RelocRVA <> 0) and (P.RelocSize >= 8);

    Result := True;
  except
    Result := False;
  end;
end;

function RvaToFileOffset(const Data: TBytes; const P: TParsedPE;
  RVA: LongWord; RequiredSize: LongWord): Int64;
var
  I, Sec: Integer;
  VirtualSize, VirtualAddress, RawSize, RawPtr, Span: LongWord;
  Delta: QWord;
begin
  Result := -1;

  if RVA < P.SizeOfHeaders then
  begin
    if RangeOK(Data, RVA, RequiredSize) then
      Exit(RVA);
    Exit;
  end;

  for I := 0 to P.NumberOfSections - 1 do
  begin
    Sec := P.SectionTableOffset + I * 40;
    VirtualSize := GetDWordLE(Data, Sec + 8);
    VirtualAddress := GetDWordLE(Data, Sec + 12);
    RawSize := GetDWordLE(Data, Sec + 16);
    RawPtr := GetDWordLE(Data, Sec + 20);

    if VirtualSize > RawSize then Span := VirtualSize else Span := RawSize;
    if Span = 0 then Continue;

    if (RVA >= VirtualAddress) and
      (QWord(RVA) < QWord(VirtualAddress) + QWord(Span)) then
    begin
      Delta := QWord(RVA) - QWord(VirtualAddress);
      if Delta + RequiredSize > RawSize then Exit;
      if QWord(RawPtr) + Delta > QWord(High(Int64)) then Exit;
      if not RangeOK(Data, Int64(QWord(RawPtr) + Delta), RequiredSize) then Exit;
      Exit(Int64(QWord(RawPtr) + Delta));
    end;
  end;
end;

function ReadPE64Info(const FileName: string; out Info: TPE64Info): Boolean;
var
  Data: TBytes;
  P: TParsedPE;
begin
  FillChar(Info, SizeOf(Info), 0);
  try
    Data := LoadBytes(FileName);
    Result := ParsePE64(Data, P);
    if Result then
      Info := P.Info;
  except
    Result := False;
  end;
end;

function ApplyDelta64(Value, OldBase, NewBase: QWord; out NewValue: QWord): Boolean;
begin
  Result := False;
  if NewBase >= OldBase then
  begin
    if Value > High(QWord) - (NewBase - OldBase) then Exit;
    NewValue := Value + (NewBase - OldBase);
  end
  else
  begin
    if Value < (OldBase - NewBase) then Exit;
    NewValue := Value - (OldBase - NewBase);
  end;
  Result := True;
end;

function RebasePE64InPlace(const FileName: string; NewImageBase: QWord;
  out OldImageBase: QWord): Boolean;
var
  Data: TBytes;
  P: TParsedPE;
  RelocOff, PosInDir, BlockOff, TargetOff: Int64;
  PageRVA, BlockSize, EntryCount, J: LongWord;
  Entry, RelocType, RelocOffset: Word;
  TargetRVA: QWord;
  OldValue, NewValue: QWord;
begin
  Result := False;
  OldImageBase := 0;

  if (NewImageBase = 0) or
    ((NewImageBase and (PE64_IMAGE_BASE_ALIGNMENT - 1)) <> 0) then Exit;

  try
    Data := LoadBytes(FileName);
    if not ParsePE64(Data, P) then Exit;

    OldImageBase := P.Info.ImageBase;
    if NewImageBase = OldImageBase then Exit;
    if not P.Info.HasRelocations then Exit;
    if P.Info.HasCertificateTable then Exit;

    RelocOff := RvaToFileOffset(Data, P, P.RelocRVA, P.RelocSize);
    if RelocOff < 0 then Exit;

    PosInDir := 0;
    while PosInDir < P.RelocSize do
    begin
      if PosInDir + 8 > P.RelocSize then Exit;
      BlockOff := RelocOff + PosInDir;
      if not RangeOK(Data, BlockOff, 8) then Exit;

      PageRVA := GetDWordLE(Data, Integer(BlockOff));
      BlockSize := GetDWordLE(Data, Integer(BlockOff) + 4);
      if (BlockSize < 8) or ((BlockSize and 1) <> 0) then Exit;
      if PosInDir + BlockSize > P.RelocSize then Exit;
      if not RangeOK(Data, BlockOff, BlockSize) then Exit;

      EntryCount := (BlockSize - 8) div 2;
      if EntryCount > 0 then
        for J := 0 to EntryCount - 1 do
        begin
          Entry := GetWordLE(Data, Integer(BlockOff + 8 + Int64(J) * 2));
          RelocType := Entry shr 12;
          RelocOffset := Entry and $0FFF;

          case RelocType of
            IMAGE_REL_BASED_ABSOLUTE:
              Continue;
            IMAGE_REL_BASED_DIR64:
              begin
                TargetRVA := QWord(PageRVA) + QWord(RelocOffset);
                if TargetRVA > High(LongWord) then Exit;
                TargetOff := RvaToFileOffset(Data, P, LongWord(TargetRVA), 8);
                if TargetOff < 0 then Exit;
                OldValue := GetQWordLE(Data, Integer(TargetOff));
                if not ApplyDelta64(OldValue, OldImageBase, NewImageBase,
                  NewValue) then Exit;
                PutQWordLE(Data, Integer(TargetOff), NewValue);
              end;
          else
            // Só processamos relocations conhecidas nesta versão.
            Exit;
          end;
        end;

      Inc(PosInDir, BlockSize);
    end;

    if PosInDir <> P.RelocSize then Exit;

    PutQWordLE(Data, P.OptionalOffset + 24, NewImageBase);
    SaveBytes(FileName, Data);
    Result := True;
  except
    Result := False;
  end;

  if Length(Data) > 0 then
    FillChar(Data[0], Length(Data), 0);
end;

function GenerateRandomPE64ImageBase: QWord;
var
  R: TBytes;
  V, Slots: QWord;
  I: Integer;
begin
  R := RandomBytes(8);
  if Length(R) <> 8 then
    raise Exception.Create('Falha ao gerar ImageBase aleatória.');

  V := 0;
  for I := 0 to 7 do
    V := V or (QWord(R[I]) shl (I * 8));

  Slots := (PE64_RANDOM_BASE_MAX - PE64_RANDOM_BASE_MIN) div
    PE64_IMAGE_BASE_ALIGNMENT;
  if Slots = 0 then
    raise Exception.Create('Faixa de ImageBase inválida.');

  Result := PE64_RANDOM_BASE_MIN +
    (V mod Slots) * PE64_IMAGE_BASE_ALIGNMENT;

  FillChar(R[0], Length(R), 0);
end;

end.

